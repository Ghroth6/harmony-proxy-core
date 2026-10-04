package resource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/configresources"
	C "github.com/metacubex/mihomo/constant"
)

type candidateCleanupAdapter struct {
	C.ProxyAdapter
	closes atomic.Int32
	close  func() error
}

func (a *candidateCleanupAdapter) Name() string { return "candidate" }
func (a *candidateCleanupAdapter) Close() error {
	a.closes.Add(1)
	return a.close()
}

func TestFetcherRetainsUnpublishedCandidateCleanupAcrossWait(t *testing.T) {
	parsed, releaseParser := make(chan struct{}), make(chan struct{})
	closing, releaseClose := make(chan struct{}), make(chan struct{})
	a := &candidateCleanupAdapter{close: func() error { close(closing); <-releaseClose; return nil }}
	var owned configresources.Set
	owned.AddAdapter(a)
	f := NewFetcher("candidate", 0, NewFileVehicle(filepath.Join(t.TempDir(), "provider")), nil,
		func([]byte) (string, error) { close(parsed); <-releaseParser; return "owned", nil }, nil,
		WithDiscard(func(string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			return owned.Close(ctx)
		}))
	updateDone := make(chan error, 1)
	go func() { _, _, err := f.SideUpdate([]byte("candidate")); updateDone <- err }()
	await(t, parsed)
	f.Cancel()
	close(releaseParser)
	await(t, closing)
	err := <-updateDone
	var cleanup *configresources.CleanupError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &cleanup) {
		t.Fatalf("lost cancellation or pending cleanup: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := f.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait forgot candidate close: %v", err)
	}
	close(releaseClose)
	if err := f.Wait(context.Background()); err != nil {
		t.Fatalf("completed cleanup retained an old wait timeout: %v", err)
	}
	if a.closes.Load() != 1 {
		t.Fatalf("candidate closed %d times", a.closes.Load())
	}
}

func TestFetcherInitialPreservesParserCleanupErrorAndSkipsFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	if err := os.WriteFile(path, []byte("local candidate"), 0600); err != nil {
		t.Fatal(err)
	}
	parseFailure, closeFailure := errors.New("parse failed"), errors.New("close failed")
	a := &candidateCleanupAdapter{close: func() error { return closeFailure }}
	var reads atomic.Int32
	v := &testVehicle{path: path, read: func(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
		reads.Add(1)
		return []byte("remote candidate"), utils.HashType{}, nil
	}}
	f := NewFetcher("failure", 0, v, nil, func([]byte) (string, error) {
		var owned configresources.Set
		owned.AddAdapter(a)
		return "", errors.Join(parseFailure, owned.Close(context.Background()))
	}, nil)
	_, err := f.Initial()
	if !errors.Is(err, parseFailure) || !errors.Is(err, closeFailure) {
		t.Fatalf("Initial lost failure causes: %v", err)
	}
	if reads.Load() != 0 {
		t.Fatal("Initial constructed another candidate after cleanup failure")
	}
	if _, _, err := f.SideUpdate([]byte("new candidate")); !errors.Is(err, context.Canceled) {
		t.Fatalf("failed cleanup did not block new updates: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := f.Wait(context.Background()); !errors.Is(err, closeFailure) || errors.Is(err, parseFailure) {
			t.Fatalf("retirement must report actual cleanup only: %v", err)
		}
	}
	if a.closes.Load() != 1 {
		t.Fatalf("candidate close retried %d times", a.closes.Load())
	}
}

func TestFetcherDiscardFailureKeepsOriginalCommitError(t *testing.T) {
	parseStarted, release := make(chan struct{}), make(chan struct{})
	closeFailure := errors.New("candidate close failed")
	var discards atomic.Int32
	f := NewFetcher("failed-discard", 0, NewFileVehicle(filepath.Join(t.TempDir(), "provider")), nil,
		func([]byte) (string, error) { close(parseStarted); <-release; return "parsed", nil }, nil,
		WithDiscard(func(string) error { discards.Add(1); return closeFailure }))
	done := make(chan error, 1)
	go func() { _, _, err := f.SideUpdate([]byte("candidate")); done <- err }()
	await(t, parseStarted)
	f.Cancel()
	close(release)
	err := <-done
	if !errors.Is(err, context.Canceled) || !errors.Is(err, closeFailure) {
		t.Fatalf("discard hid original error: %v", err)
	}
	if err := f.Wait(context.Background()); !errors.Is(err, closeFailure) {
		t.Fatalf("retirement forgot failed discard: %v", err)
	}
	if discards.Load() != 1 {
		t.Fatalf("discard count %d", discards.Load())
	}
}
