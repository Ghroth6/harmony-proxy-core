package policy

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	mihomoHTTP "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

type preparedVehicle struct {
	resource    contract.Resource
	uri, proxy  string
	kind        P.VehicleType
	session     *resourceSession
	requirement contract.Requirement
	decode      func([]byte) ([]string, error)
	task        string
	pending     ResourceVersion
}

func (v *preparedVehicle) Path() string        { return v.resource.RelativePath }
func (v *preparedVehicle) Url() string         { return v.uri }
func (v *preparedVehicle) Proxy() string       { return v.proxy }
func (v *preparedVehicle) Type() P.VehicleType { return v.kind }

func (v *preparedVehicle) Read(root context.Context, oldHash utils.HashType) ([]byte, utils.HashType, error) {
	v.task = ""
	v.pending = ResourceVersion{}
	if root.Err() != nil {
		return nil, utils.HashType{}, root.Err()
	}
	if v.kind != P.HTTP {
		return nil, utils.HashType{}, errors.New("POLICY_FIXED_RESOURCE_REACQUIRE_FORBIDDEN")
	}
	observed, available := platformnetwork.Current()
	if !available || !observed.Online || observed.Generation != v.session.networkGeneration {
		return nil, utils.HashType{}, errors.New("POLICY_RESOURCE_NETWORK_CHANGED")
	}
	ctx, cancel := context.WithTimeout(root, resource.DefaultHttpTimeout)
	defer cancel()
	var headers map[string][]string
	if v.requirement.SourceHeadersJSON != "" && json.Unmarshal([]byte(v.requirement.SourceHeadersJSON), &headers) != nil {
		return nil, utils.HashType{}, errors.New("POLICY_RESOURCE_HEADERS_INVALID")
	}
	proxy := v.proxy
	if proxy == "" {
		proxy = "DIRECT"
	}
	response, err := mihomoHTTP.HttpRequest(ctx, v.uri, "GET", headers, nil,
		mihomoHTTP.WithSpecialProxy(proxy),
		mihomoHTTP.WithResourceRequest(func() {
			v.task = "resource:" + strconv.FormatUint(actualResourceAttempts.Add(1), 10)
			v.session.record(v.task, v.resource.RefID, "acquiring", "", ResourceVersion{})
		}, v.session.RetainWorkerCloseFailure))
	if err != nil {
		if ctx.Err() != nil {
			return nil, utils.HashType{}, ctx.Err()
		}
		return nil, utils.HashType{}, errors.New("POLICY_RESOURCE_HTTP_FAILED")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		closeErr := response.Body.Close()
		v.session.RetainWorkerCloseFailure(response.Body, closeErr)
		return nil, utils.HashType{}, errors.New("POLICY_RESOURCE_HTTP_STATUS")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, v.requirement.MaxBytes+1))
	closeErr := response.Body.Close()
	v.session.RetainWorkerCloseFailure(response.Body, closeErr)
	if ctx.Err() != nil {
		return nil, utils.HashType{}, ctx.Err()
	}
	if readErr != nil || closeErr != nil {
		return nil, utils.HashType{}, errors.New("POLICY_RESOURCE_HTTP_INCOMPLETE")
	}
	if int64(len(data)) > v.requirement.MaxBytes || len(data) == 0 {
		return nil, utils.HashType{}, errors.New("POLICY_RESOURCE_BOUNDS")
	}
	if _, err = v.decode(data); err != nil {
		return nil, utils.HashType{}, errors.New("POLICY_RESOURCE_PAYLOAD_INVALID")
	}
	content := contract.Digest(data)
	v.pending = ResourceVersion{RefID: v.resource.RefID, SourceDigest: v.resource.SourceDigest, ContentDigest: content, ByteLength: int64(len(data)), RelativePath: "immutable/" + content[7:] + "/" + v.resource.Kind + "." + v.resource.Format}
	v.session.record(v.task, v.resource.RefID, "acquired", "", v.pending)
	if err = v.session.reserveAdoption(v.pending); err != nil {
		return nil, utils.HashType{}, err
	}
	if err = v.session.engine.saveImmutable(ctx, v.pending, data, v.session); err != nil {
		return nil, utils.HashType{}, err
	}
	v.session.record(v.task, v.resource.RefID, "saved", "", v.pending)
	return data, utils.MakeHash(data), nil
}

// The bounded complete response was saved before the short strategy commit.
// Disk I/O must not hold Fetcher.Cancel's admission/publication mutex.
func (v *preparedVehicle) Write(data []byte) error {
	if v.pending.ContentDigest != contract.Digest(data) || v.pending.ByteLength != int64(len(data)) {
		return errors.New("POLICY_RESOURCE_DIGEST_INVALID")
	}
	return nil
}
func (v *preparedVehicle) PreparedUpdateResult(same bool, err error) {
	defer v.session.finishAdoption(v.resource.RefID)
	if v.task == "" {
		return
	}
	if err != nil {
		stage, code := "failed", "POLICY_RESOURCE_UPDATE_FAILED"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			stage = "cancelled"
			code = "POLICY_RESOURCE_CANCELLED"
		}
		v.session.record(v.task, v.resource.RefID, stage, code, ResourceVersion{})
		return
	}
	v.session.record(v.task, v.resource.RefID, "adopted", "", v.pending)
}

func (e *Engine) saveImmutable(ctx context.Context, value ResourceVersion, data []byte, owner *resourceSession) (result error) {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	segments := strings.Split(value.RelativePath, "/")
	if len(segments) != 3 {
		return errors.New("POLICY_RESOURCE_PATH_INVALID")
	}
	for index := 0; index < 2; index++ {
		directory := strings.Join(segments[:index+1], "/")
		if err := e.root.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.New("POLICY_RESOURCE_SAVE_FAILED")
		}
		info, err := e.root.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("POLICY_RESOURCE_PATH_INVALID")
		}
	}
	if _, err := e.root.Lstat(value.RelativePath); err == nil {
		return e.verifyImmutable(ctx, value, owner)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("POLICY_RESOURCE_SAVE_FAILED")
	}
	temporary := strings.Join(segments[:2], "/") + "/.pending-" + rand.Text()
	file, err := e.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("POLICY_RESOURCE_SAVE_FAILED")
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			if err := e.root.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, errors.New("POLICY_RESOURCE_SAVE_FAILED"))
			}
		}
	}()
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	owner.RetainWorkerCloseFailure(file, closeErr)
	if writeErr != nil || closeErr != nil {
		if closeErr != nil {
			removeTemporary = false
		}
		return errors.New("POLICY_RESOURCE_SAVE_FAILED")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Re-read only the completed temporary file before atomic publication.
	verified, err := e.root.Open(temporary)
	if err != nil {
		return errors.New("POLICY_RESOURCE_SAVE_FAILED")
	}
	actual, readErr := io.ReadAll(io.LimitReader(verified, value.ByteLength+1))
	closeErr = verified.Close()
	owner.RetainWorkerCloseFailure(verified, closeErr)
	if readErr != nil || closeErr != nil || len(actual) != len(data) || contract.Digest(actual) != value.ContentDigest {
		if closeErr != nil {
			removeTemporary = false
		}
		return errors.New("POLICY_RESOURCE_DIGEST_INVALID")
	}
	directory, err := e.root.Open(strings.Join(segments[:2], "/"))
	if err != nil {
		return errors.New("POLICY_RESOURCE_SAVE_FAILED")
	}
	err = publishImmutable(directory, strings.Split(temporary, "/")[2], segments[2], owner)
	closeErr = directory.Close()
	owner.RetainWorkerCloseFailure(directory, closeErr)
	if errors.Is(err, os.ErrExist) && closeErr == nil {
		// Another resource reference may publish these identical bytes first.
		// Accept only its complete regular file after independently re-hashing it.
		return e.verifyImmutable(ctx, value, owner)
	}
	if err != nil || closeErr != nil {
		return errors.New("POLICY_RESOURCE_SAVE_FAILED")
	}
	return ctx.Err()
}

func (e *Engine) verifyImmutable(ctx context.Context, value ResourceVersion, owner *resourceSession) error {
	info, err := e.root.Lstat(value.RelativePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != value.ByteLength {
		return errors.New("POLICY_RESOURCE_DIGEST_INVALID")
	}
	file, err := e.root.Open(value.RelativePath)
	if err != nil {
		return errors.New("POLICY_RESOURCE_SAVE_FAILED")
	}
	actual, readErr := io.ReadAll(io.LimitReader(file, value.ByteLength+1))
	closeErr := file.Close()
	owner.RetainWorkerCloseFailure(file, closeErr)
	if readErr != nil || closeErr != nil || int64(len(actual)) != value.ByteLength || contract.Digest(actual) != value.ContentDigest {
		return errors.New("POLICY_RESOURCE_DIGEST_INVALID")
	}
	return ctx.Err()
}
