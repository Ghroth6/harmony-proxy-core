package statistic

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/sing/common/bufio"
)

// Embedded interfaces deliberately fail on unexpected I/O paths.
type activityConn struct {
	C.Conn
	n           int
	err         error
	bufferRead  func(*buf.Buffer) error
	bufferWrite func(*buf.Buffer) error
	read        func([]byte) (int, error)
	write       func([]byte) (int, error)
}

func (*activityConn) Chains() C.Chain           { return C.Chain{"test"} }
func (*activityConn) ProviderChains() C.Chain   { return nil }
func (*activityConn) RemoteDestination() string { return "test:443" }
func (*activityConn) Close() error              { return nil }
func (c *activityConn) Read(b []byte) (int, error) {
	if c.read != nil {
		return c.read(b)
	}
	return c.n, c.err
}
func (c *activityConn) Write(b []byte) (int, error) {
	if c.write != nil {
		return c.write(b)
	}
	return c.n, c.err
}
func (c *activityConn) ReadBuffer(b *buf.Buffer) error  { return c.bufferRead(b) }
func (c *activityConn) WriteBuffer(b *buf.Buffer) error { return c.bufferWrite(b) }

type activityPacketConn struct {
	C.PacketConn
	n   int
	err error
}

func (*activityPacketConn) Chains() C.Chain           { return C.Chain{"test"} }
func (*activityPacketConn) ProviderChains() C.Chain   { return nil }
func (*activityPacketConn) RemoteDestination() string { return "test:53" }
func (*activityPacketConn) Close() error              { return nil }
func (c *activityPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return c.n, &net.UDPAddr{}, c.err
}
func (c *activityPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return make([]byte, c.n), nil, &net.UDPAddr{}, c.err
}
func (c *activityPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return c.n, c.err
}

func TestActivityStartsAtCreationAndSurvivesClose(t *testing.T) {
	m := &Manager{}
	trackers := []Tracker{
		NewTCPTracker(&activityConn{}, m, &C.Metadata{}, nil, 3, 4, true),
		NewUDPTracker(&activityPacketConn{}, m, &C.Metadata{}, nil, 5, 6, true),
	}
	for _, tracker := range trackers {
		if tracker.LastActivity() != tracker.Info().Start {
			t.Fatal("initial activity must be exactly the creation time, including its monotonic clock")
		}
		before := tracker.LastActivity()
		if err := tracker.Close(); err != nil {
			t.Fatal(err)
		}
		if m.Get(tracker.ID()) != nil || tracker.LastActivity() != before {
			t.Fatal("close must remove the tracker without manufacturing activity")
		}
		encoded, err := json.Marshal(tracker.Info())
		if err != nil {
			t.Fatal(err)
		}
		var snapshot map[string]any
		if err = json.Unmarshal(encoded, &snapshot); err != nil {
			t.Fatal(err)
		}
		if len(snapshot) != 9 {
			t.Fatalf("activity must not change the connection JSON schema: %s", encoded)
		}
	}
	if up, down := m.Total(); up != 8 || down != 10 {
		t.Fatalf("creation/close changed existing byte accounting: %d/%d", up, down)
	}
}

func assertActivity(t *testing.T, tracker Tracker, before time.Time, want bool) {
	t.Helper()
	after := tracker.LastActivity()
	if want {
		if !after.After(before) || time.Since(after) > time.Second || after.After(time.Now()) {
			t.Fatalf("expected recent activity, before=%v after=%v", before, after)
		}
	} else if after != before {
		t.Fatalf("unsuccessful/empty operation changed activity: %v -> %v", before, after)
	}
}

func TestTCPActivityUsesTransferredBytes(t *testing.T) {
	for _, direction := range []string{"read", "write"} {
		for _, tc := range []struct {
			name string
			n    int
			err  error
		}{
			{"success", 3, nil},
			{"partial-error", 3, io.ErrUnexpectedEOF},
			{"empty-success", 0, nil},
			{"failure", 0, io.EOF},
		} {
			t.Run(direction+"/"+tc.name, func(t *testing.T) {
				m := &Manager{}
				tracker := NewTCPTracker(&activityConn{n: tc.n, err: tc.err}, m, &C.Metadata{}, nil, 0, 0, true)
				tracker.Start = time.Now().Add(-3 * time.Minute)
				before := tracker.LastActivity()
				var n int
				var err error
				if direction == "read" {
					n, err = tracker.Read(make([]byte, 8))
				} else {
					n, err = tracker.Write(make([]byte, 8))
				}
				if n != tc.n || err != tc.err {
					t.Fatal("I/O result was not preserved")
				}
				assertActivity(t, tracker, before, tc.n > 0)
				up, down := m.Total()
				if up+down != int64(tc.n) {
					t.Fatal("activity changed byte accounting")
				}
			})
		}
	}
}

func TestTCPBufferReadActivity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before int
		after  int
		err    error
		active bool
	}{
		{"empty-read", 0, 3, nil, true},
		{"empty-partial-error", 0, 3, io.ErrUnexpectedEOF, true},
		{"empty-eof", 0, 0, io.EOF, false},
		{"append-read", 2, 5, nil, true},
		{"prefilled-error", 2, 2, io.EOF, false},
		// A replacing reader on a nonempty buffer exposes no reliable byte delta.
		{"replace-no-growth", 4, 2, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &activityConn{bufferRead: func(b *buf.Buffer) error {
				b.Truncate(tc.after)
				return tc.err
			}}
			tracker := NewTCPTracker(conn, &Manager{}, &C.Metadata{}, nil, 0, 0, false)
			tracker.Start = time.Now().Add(-3 * time.Minute)
			before := tracker.LastActivity()
			b := buf.NewSize(16)
			defer b.Release()
			b.Truncate(tc.before)
			if err := tracker.ReadBuffer(b); err != tc.err || b.Len() != tc.after {
				t.Fatal("buffer result was not preserved")
			}
			assertActivity(t, tracker, before, tc.active)
		})
	}
}

func TestTCPBufferWriteActivity(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		err  error
	}{
		{"success", 3, nil},
		{"empty", 0, nil},
		{"failure-or-unobservable-partial", 3, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &activityConn{bufferWrite: func(b *buf.Buffer) error {
				b.Release()
				return tc.err
			}}
			tracker := NewTCPTracker(conn, &Manager{}, &C.Metadata{}, nil, 0, 0, false)
			tracker.Start = time.Now().Add(-3 * time.Minute)
			before := tracker.LastActivity()
			b := buf.NewSize(tc.n)
			b.Truncate(tc.n)
			if err := tracker.WriteBuffer(b); err != tc.err {
				t.Fatal("buffer write result was not preserved")
			}
			assertActivity(t, tracker, before, tc.err == nil && tc.n > 0)
		})
	}
}

func TestTCPUnwrappedCopyActivity(t *testing.T) {
	for _, push := range []bool{false, true} {
		conn := &activityConn{n: 3}
		m := &Manager{}
		tracker := NewTCPTracker(conn, m, &C.Metadata{}, nil, 0, 0, push)
		tracker.Start = time.Now().Add(-3 * time.Minute)
		before := tracker.LastActivity()
		reader, reads := tracker.UnwrapReader()
		writer, writes := tracker.UnwrapWriter()
		if reader != conn || writer != conn {
			t.Fatal("fast copy must still unwrap to the underlying connection")
		}
		reads[0](0)
		writes[0](0)
		assertActivity(t, tracker, before, false)
		n, _ := reader.Read(make([]byte, 8))
		reads[0](int64(n))
		assertActivity(t, tracker, before, true)
		n, _ = writer.Write(make([]byte, 8))
		writes[0](int64(n))
		if tracker.UploadTotal.Load() != 3 || tracker.DownloadTotal.Load() != 3 {
			t.Fatal("unwrapped I/O must be counted exactly once")
		}
		up, down := m.Total()
		if (push && (up != 3 || down != 3)) || (!push && (up != 0 || down != 0)) {
			t.Fatal("internal traffic exclusion changed")
		}
	}
}

func TestUDPActivityIncludesEmptyDatagrams(t *testing.T) {
	for _, operation := range []string{"read", "wait-read", "write"} {
		for _, tc := range []struct {
			name string
			n    int
			err  error
		}{
			{"datagram", 3, nil},
			{"zero-length-datagram", 0, nil},
			{"data-with-error", 3, io.ErrUnexpectedEOF},
			{"failure", 0, io.EOF},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				m := &Manager{}
				tracker := NewUDPTracker(&activityPacketConn{n: tc.n, err: tc.err}, m, &C.Metadata{}, nil, 0, 0, true)
				tracker.Start = time.Now().Add(-3 * time.Minute)
				before := tracker.LastActivity()
				var n int
				var err error
				switch operation {
				case "read":
					n, _, err = tracker.ReadFrom(make([]byte, 8))
				case "wait-read":
					var data []byte
					data, _, _, err = tracker.WaitReadFrom()
					n = len(data)
				case "write":
					n, err = tracker.WriteTo(make([]byte, tc.n), &net.UDPAddr{})
				}
				if n != tc.n || err != tc.err {
					t.Fatal("datagram result was not preserved")
				}
				assertActivity(t, tracker, before, tc.n > 0 || tc.err == nil)
				up, down := m.Total()
				if up+down != int64(tc.n) {
					t.Fatal("datagram byte accounting changed")
				}
			})
		}
	}
}

func TestActivityThroughRealCopyFastPath(t *testing.T) {
	payload := []byte("copy through both tracked endpoints")
	input := bytes.NewReader(payload)
	var output bytes.Buffer
	source := &activityConn{read: input.Read, bufferRead: bufio.NewExtendedReader(input).ReadBuffer}
	destination := &activityConn{write: output.Write, bufferWrite: bufio.NewExtendedWriter(&output).WriteBuffer}
	m := &Manager{}
	reader := NewTCPTracker(source, m, &C.Metadata{}, nil, 0, 0, true)
	writer := NewTCPTracker(destination, m, &C.Metadata{}, nil, 0, 0, true)
	reader.Start = time.Now().Add(-3 * time.Minute)
	writer.Start = reader.Start
	n, err := bufio.Copy(writer, reader)
	if err != nil || n != int64(len(payload)) || !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("copy failed: %d, %v, %q", n, err, output.Bytes())
	}
	assertActivity(t, reader, reader.Start, true)
	assertActivity(t, writer, writer.Start, true)
	up, down := m.Total()
	if up != n || down != n || reader.DownloadTotal.Load() != n || writer.UploadTotal.Load() != n {
		t.Fatalf("copy counters must fire exactly once: up=%d down=%d copied=%d", up, down, n)
	}
}

func TestConcurrentActivityDoesNotMoveBackward(t *testing.T) {
	tracker := NewTCPTracker(&activityConn{n: 1}, &Manager{}, &C.Metadata{}, nil, 0, 0, false)
	tracker.Start = time.Now().Add(-3 * time.Minute)
	var workers sync.WaitGroup
	failed := make(chan error, 1)
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			previous := tracker.LastActivity()
			for i := 0; i < 1000; i++ {
				_, _ = tracker.Read(nil)
				_, _ = tracker.Write(nil)
				next := tracker.LastActivity()
				if next.Before(previous) {
					select {
					case failed <- errors.New("concurrent activity moved backward"):
					default:
					}
				}
				previous = next
			}
		}()
	}
	workers.Wait()
	select {
	case err := <-failed:
		t.Fatal(err)
	default:
	}
	assertActivity(t, tracker, tracker.Start, true)
	if tracker.UploadTotal.Load() != 8000 || tracker.DownloadTotal.Load() != 8000 {
		t.Fatal("concurrent activity changed byte accounting")
	}
}
