package session

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
)

func TestAnyTLSPoolFirstRequestAfterNetworkResumeSkipsOldSession(t *testing.T) {
	forwarding.EnableManagementNetwork()
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate) }) }
	defer release()
	oldReadExited := make(chan struct{})
	pad := lifecyclePadding()
	var dials atomic.Int32
	var firstPhysicalContext context.Context
	var serversLock sync.Mutex
	var servers []*Session
	client := NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) {
		left, right := net.Pipe()
		owned, err := forwarding.OwnNetworkConn(ctx, left)
		if err != nil {
			_ = right.Close()
			return nil, err
		}
		server := NewServerSession(right, func(stream *Stream) { defer stream.Close(); _, _ = io.Copy(stream, stream) }, pad)
		serversLock.Lock()
		servers = append(servers, server)
		serversLock.Unlock()
		go server.Run()
		if dials.Add(1) == 1 {
			firstPhysicalContext = ctx
			// Epoch close finishes the actual physical socket, but a protocol
			// reader can observe that result later than WaitManagementNetwork.
			return &lifecycleConn{Conn: owned, readExited: oldReadExited, readRelease: gate}, nil
		}
		return owned, nil
	}, pad, "test", time.Hour, time.Hour, 1, false)
	defer func() {
		release()
		_ = client.Close()
		serversLock.Lock()
		defer serversLock.Unlock()
		for _, server := range servers {
			_ = server.Close()
		}
		forwarding.CancelManagementNetwork()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := forwarding.WaitManagementNetwork(ctx); err != nil {
			t.Error(err)
		}
		if err := forwarding.ResumeManagementNetwork(); err != nil {
			t.Error(err)
		}
	}()
	exchange := func(conn net.Conn) error {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte("echo")); err != nil {
			return err
		}
		var b [4]byte
		_, err := io.ReadFull(conn, b[:])
		return err
	}
	ctx, finish, err := forwarding.AcquireManagementNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.CreateStream(ctx)
	if err != nil {
		finish()
		t.Fatal(err)
	}
	if err := exchange(first); err != nil {
		finish()
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		finish()
		t.Fatal(err)
	}
	finish()
	if firstPhysicalContext.Err() != nil {
		t.Fatalf("pooled physical transport retained one request's cancellation: %v", firstPhysicalContext.Err())
	}
	forwarding.CancelManagementNetwork()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := forwarding.WaitManagementNetwork(wait); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, oldReadExited)
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	fresh, done, err := forwarding.AcquireManagementNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	result := make(chan error, 1)
	go func() {
		conn, err := client.CreateStream(fresh)
		if err == nil {
			err = exchange(conn)
			_ = conn.Close()
		}
		result <- err
	}()
	// Release the delayed old reader after enough time for the first restored
	// request to expose whether it selected that known-obsolete pool entry.
	timer := time.AfterFunc(100*time.Millisecond, release)
	defer timer.Stop()
	if err := lifecycleResult(t, result); err != nil {
		t.Fatalf("first restored request reused retired network session: %v", err)
	}
	if dials.Load() != 2 {
		t.Fatalf("physical dials = %d, want exactly one new session", dials.Load())
	}
}
