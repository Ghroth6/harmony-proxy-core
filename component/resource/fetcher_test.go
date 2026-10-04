package resource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	MHTTP "github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/listener/inner"
)

type testVehicle struct {
	path   string
	read   func(context.Context, utils.HashType) ([]byte, utils.HashType, error)
	writes atomic.Int32
}

func (v *testVehicle) Read(ctx context.Context, old utils.HashType) ([]byte, utils.HashType, error) {
	return v.read(ctx, old)
}
func (v *testVehicle) Write(b []byte) error { v.writes.Add(1); return safeWrite(v.path, b) }
func (v *testVehicle) Path() string         { return v.path }
func (v *testVehicle) Url() string          { return "test://provider" }
func (v *testVehicle) Proxy() string        { return "" }
func (v *testVehicle) Type() P.VehicleType  { return P.HTTP }
func parseString(b []byte) (string, error)  { return string(b), nil }
func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("work did not reach the expected boundary")
	}
}
func waitRetired[V any](t *testing.T, f *Fetcher[V]) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}
func expectStillOwned[V any](t *testing.T, f *Fetcher[V]) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := f.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected unfinished retirement, got %v", err)
	}
}

func TestFetcherRetiresLateVehicleAndRejectsAllNewEntries(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var metadata atomic.Int32
	v := &testVehicle{path: filepath.Join(t.TempDir(), "provider")}
	v.read = func(ctx context.Context, old utils.HashType) ([]byte, utils.HashType, error) {
		close(entered)
		<-release // Deliberately emulate a vehicle that ignores cancellation.
		err := Commit(ctx, func() error { metadata.Add(1); return nil })
		return []byte("late"), utils.MakeHash([]byte("late")), err
	}
	var updates atomic.Int32
	f := NewFetcher("late", 0, v, nil, parseString, func(string) { updates.Add(1) })
	result := make(chan error, 1)
	go func() { _, _, err := f.Update(); result <- err }()
	await(t, entered)
	f.Cancel()
	expectStillOwned(t, f)
	if _, err := f.Initial(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Initial admitted after Cancel: %v", err)
	}
	if _, _, err := f.Update(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Update admitted after Cancel: %v", err)
	}
	if _, _, err := f.SideUpdate([]byte("new")); !errors.Is(err, context.Canceled) {
		t.Fatalf("SideUpdate admitted after Cancel: %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("late result: %v", err)
	}
	waitRetired(t, f)
	if metadata.Load() != 0 || updates.Load() != 0 || v.writes.Load() != 0 || !f.UpdatedAt().IsZero() {
		t.Fatal("retired vehicle published state")
	}
}

func TestFetcherParserRetirementLeavesFileHashAndCallbackUnchanged(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	v := &testVehicle{path: filepath.Join(t.TempDir(), "provider")}
	var updates atomic.Int32
	f := NewFetcher("parser", 0, v, nil, func(b []byte) (string, error) {
		if string(b) == "late" {
			close(entered)
			<-release
		}
		return string(b), nil
	}, func(string) { updates.Add(1) })
	if _, _, err := f.SideUpdate([]byte("old")); err != nil {
		t.Fatal(err)
	}
	before := f.UpdatedAt()
	result := make(chan error, 1)
	go func() { _, _, err := f.SideUpdate([]byte("late")); result <- err }()
	await(t, entered)
	closed := make(chan error, 1)
	go func() { closed <- f.Close() }()
	await(t, f.Context().Done())
	expectStillOwned(t, f)
	select {
	case err := <-closed:
		t.Fatalf("Close completed before parser: %v", err)
	default:
	}
	if _, err := f.Initial(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Initial reopened retired fetcher: %v", err)
	}
	once.Do(func() { close(release) })
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("parser late result: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(v.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old" || !f.UpdatedAt().Equal(before) || !f.hash.Equal(utils.MakeHash([]byte("old"))) || updates.Load() != 1 || v.writes.Load() != 1 {
		t.Fatal("retired parser committed a result")
	}
	// The replacement can safely use the same path once retirement completes.
	replacement := NewFetcher("parser", 0, v, nil, parseString, nil)
	defer replacement.Close()
	if _, _, err := replacement.SideUpdate([]byte("replacement")); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(v.path)
	if string(b) != "replacement" {
		t.Fatal("replacement did not own the path")
	}
}

func TestFetcherRetiredUnchangedResponseDoesNotTouchFile(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	v := &testVehicle{path: filepath.Join(t.TempDir(), "provider")}
	v.read = func(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
		close(entered)
		<-release
		return nil, utils.MakeHash([]byte("same")), nil
	}
	f := NewFetcher("same", 0, v, nil, parseString, nil)
	if _, _, err := f.SideUpdate([]byte("same")); err != nil {
		t.Fatal(err)
	}
	sentinel := time.Unix(100000, 0)
	if err := os.Chtimes(v.path, sentinel, sentinel); err != nil {
		t.Fatal(err)
	}
	before := f.UpdatedAt()
	result := make(chan error, 1)
	go func() { _, _, err := f.Update(); result <- err }()
	await(t, entered)
	f.Cancel()
	close(release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("unchanged response: %v", err)
	}
	waitRetired(t, f)
	stat, err := os.Stat(v.path)
	if err != nil {
		t.Fatal(err)
	}
	if !stat.ModTime().Equal(sentinel) || !before.Equal(f.UpdatedAt()) {
		t.Fatal("canceled same-hash response refreshed timestamps")
	}
}

type countingFileVehicle struct {
	*FileVehicle
	reads    atomic.Int32
	readDone chan struct{}
}

func (v *countingFileVehicle) Read(ctx context.Context, h utils.HashType) ([]byte, utils.HashType, error) {
	v.reads.Add(1)
	select {
	case v.readDone <- struct{}{}:
	default:
	}
	return v.FileVehicle.Read(ctx, h)
}
func TestFetcherRepeatedInitialOwnsOneWatcherAndStopsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	if err := os.WriteFile(path, []byte("initial"), 0600); err != nil {
		t.Fatal(err)
	}
	v := &countingFileVehicle{FileVehicle: NewFileVehicle(path), readDone: make(chan struct{}, 32)}
	f := NewFetcher("file", 0, v, nil, parseString, nil)
	defer f.Close()
	for i := 0; i < 5; i++ {
		if _, err := f.Initial(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("updated"), 0600); err != nil {
		t.Fatal(err)
	}
	await(t, v.readDone)
	time.Sleep(250 * time.Millisecond) // Covers any extra debounced callbacks from duplicate watchers.
	if got := v.reads.Load(); got != 1 {
		t.Fatalf("one file change caused %d reads", got)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after stop"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := v.reads.Load(); got != 1 {
		t.Fatalf("retired watcher read again: %d", got)
	}
}

func TestFetcherRepeatedInitialOwnsOnePullLoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	if err := os.WriteFile(path, []byte("initial"), 0600); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 20)
	var calls atomic.Int32
	v := &testVehicle{path: path}
	v.read = func(ctx context.Context, _ utils.HashType) ([]byte, utils.HashType, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, utils.HashType{}, ctx.Err()
	}
	f := NewFetcher("loop", 100*time.Millisecond, v, nil, parseString, nil)
	defer f.Close()
	for i := 0; i < 5; i++ {
		if _, err := f.Initial(); err != nil {
			t.Fatal(err)
		}
	}
	await(t, entered)
	time.Sleep(150 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("duplicate periodic reads: %d", got)
	}
	f.Cancel()
	waitRetired(t, f)
}

func TestFetcherWatcherRetirementJoinsItsParser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	if err := os.WriteFile(path, []byte("initial"), 0600); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var updates atomic.Int32
	f := NewFetcher("watcher-parser", 0, NewFileVehicle(path), nil, func(b []byte) (string, error) {
		if string(b) == "late" {
			close(entered)
			<-release
		}
		return string(b), nil
	}, func(string) { updates.Add(1) })
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("late"), 0600); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	f.Cancel()
	expectStillOwned(t, f)
	once.Do(func() { close(release) })
	waitRetired(t, f)
	if updates.Load() != 1 {
		t.Fatal("retired watcher published its parser result")
	}
}

func TestHTTPVehicleRetirementRejectsLateMetadataETagAndPayload(t *testing.T) {
	previous := inner.GetTunnel()
	inner.New(nil)
	defer inner.New(previous)
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	defer C.SetHomeDir(previousHome)
	cache := cachefile.Cache()
	if cache.DB == nil {
		t.Fatal("temporary cache did not open")
	}
	defer cache.Close()
	previousETag := ETag()
	SetETag(true)
	defer SetETag(previousETag)
	headers, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("ETag", "old")
			w.Header().Set("subscription-userinfo", "old-info")
			io.WriteString(w, "old")
			return
		}
		w.Header().Set("ETag", "late")
		w.Header().Set("subscription-userinfo", "late-info")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(headers)
		<-release
		io.WriteString(w, "late")
	}))
	defer func() {
		once.Do(func() { close(release) })
		server.Close()
	}()
	vehicle := NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "provider"), "", nil, 3*time.Second, 0)
	var metadata atomic.Int32
	vehicle.SetInRead(func(resp *MHTTP.Response) {
		metadata.Add(1)
		cache.SetSubscriptionInfo("resource-retirement", resp.Header.Get("subscription-userinfo"))
	})
	f := NewFetcher("http", 0, vehicle, nil, parseString, nil)
	defer f.Close()
	if _, _, err := f.Update(); err != nil {
		t.Fatal(err)
	}
	if metadata.Load() != 1 || cache.GetETagWithHash(server.URL).ETag != "old" {
		t.Fatal("initial real HTTP commit failed")
	}
	result := make(chan error, 1)
	go func() { _, _, err := f.Update(); result <- err }()
	await(t, headers)
	f.Cancel()
	waitRetired(t, f)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("slow HTTP cancellation: %v", err)
	}
	once.Do(func() { close(release) })
	b, err := os.ReadFile(vehicle.Path())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old" || metadata.Load() != 1 || cache.GetETagWithHash(server.URL).ETag != "old" || cache.GetSubscriptionInfo("resource-retirement") != "old-info" {
		t.Fatal("late HTTP response committed metadata, ETag or payload")
	}
}

func TestCommitGuardSeparatesOwnerRetirementFromRequestTimeout(t *testing.T) {
	v := &testVehicle{path: filepath.Join(t.TempDir(), "provider")}
	owner := NewFetcher("owner", 0, v, nil, parseString, nil)
	defer owner.Close()
	ctx, cancel := context.WithCancel(owner.Context())
	cancel()
	calls := 0
	if err := Commit(ctx, func() error { calls++; return nil }); err != nil {
		t.Fatalf("owner rejected timeout result: %v", err)
	}
	owner.Cancel()
	if err := Commit(ctx, func() error { calls++; return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("retired owner commit: %v", err)
	}
	if err := Commit(contextWithoutGuardCanceled(), func() error { calls++; return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("unguarded cancellation: %v", err)
	}
	if calls != 1 {
		t.Fatalf("commit count=%d", calls)
	}
}
func contextWithoutGuardCanceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
