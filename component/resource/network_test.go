package resource

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/forwarding"
)

func TestFetcherNetworkTransitionDiscardsLateParseAndCanUpdateAgain(t *testing.T) {
	forwarding.EnableManagementNetwork()
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	parsed, release := make(chan struct{}), make(chan struct{})
	var parses, commits, discards atomic.Int32
	v := &testVehicle{path: filepath.Join(t.TempDir(), "provider"), read: func(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
		return []byte("candidate"), utils.MakeHash([]byte("candidate")), nil
	}}
	f := NewFetcher("network", 0, v, nil, func([]byte) (string, error) {
		if parses.Add(1) == 1 {
			close(parsed)
			<-release
		}
		return "node", nil
	}, func(string) { commits.Add(1) }, WithDiscard(func(string) error { discards.Add(1); return nil }))
	defer f.Close()
	result := make(chan error, 1)
	go func() { _, _, err := f.Update(); result <- err }()
	await(t, parsed)
	forwarding.CancelManagementNetwork()
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := forwarding.WaitManagementNetwork(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forgot parser: %v", err)
	}
	close(release)
	if err := <-result; !errors.Is(err, forwarding.ErrManagementNetworkPaused) {
		t.Fatalf("late update: %v", err)
	}
	if commits.Load() != 0 || discards.Load() != 1 {
		t.Fatalf("commits=%d discards=%d", commits.Load(), discards.Load())
	}
	if err := forwarding.WaitManagementNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.Update(); err != nil {
		t.Fatal("configuration was permanently canceled", err)
	}
	if commits.Load() != 1 {
		t.Fatal("fresh update not committed")
	}
}
