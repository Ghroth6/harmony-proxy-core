package tuic_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/tuic/types"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type packetProxy struct{ *outbound.Base }

func (p *packetProxy) ListenPacketContext(ctx context.Context, _ *C.Metadata) (C.PacketConn, error) {
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return outbound.NewPacketConn(pc, p), nil
}

var forwardingGeneration atomic.Uint64

// Both versions use the real pool, QUIC, authentication and TUIC stream framing.
// The UDP socket is obtained through the real nested proxy dialer, whose request
// ownership must not accidentally include the pool's shared QUIC transport.
func TestSharedTUICPoolSurvivesForwardingStopAfterManagementReuse(t *testing.T) {
	for _, version := range []int{4, 5} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			var token [32]byte
			token[0] = 7
			var user [16]byte
			user[0] = 9
			server, err := tuic.NewServer(&tuic.ServerOption{
				TlsConfig:  &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"tuic-test"}},
				QuicConfig: &quic.Config{EnableDatagrams: true},
				Tokens:     [][32]byte{token}, Users: map[[16]byte]string{user: "password"}, AuthenticationTimeout: 5 * time.Second,
				HandleTcpFn: func(c net.Conn, _ socks5.Addr, _ ...inbound.Addition) error {
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
					return nil
				},
			}, pc)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			serveDone := make(chan struct{})
			go func() { defer close(serveDone); _ = server.Serve() }()
			defer func() { _ = server.Close(); <-serveDone }()
			proxy := &packetProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "nested-udp", Type: C.Direct})}
			var dials int
			var retained context.Context
			var transports []*quic.Conn
			defer func() {
				for _, c := range transports {
					_ = c.CloseWithError(0, "test completed")
				}
			}()
			dial := func(ctx context.Context) (*quic.Conn, error) {
				dials++
				retained = ctx
				_, conn, err := common.DialQuic(ctx, pc.LocalAddr().String(), nil, proxydialer.New(proxy, true), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"tuic-test"}}, &quic.Config{EnableDatagrams: true}, common.DialQuicOption{})
				if err == nil {
					transports = append(transports, conn)
				}
				return conn, err
			}
			var client *tuic.PoolClient
			if version == 4 {
				client = tuic.NewPoolClientV4(&tuic.ClientOptionV4{Token: token, MaxOpenStreams: 100, RequestTimeout: time.Second}, dial)
			} else {
				client = tuic.NewPoolClientV5(&tuic.ClientOptionV5{Uuid: user, Password: "password", MaxOpenStreams: 100}, dial)
			}
			forwarding.Enable()
			if err := forwarding.Start(context.Background(), forwardingGeneration.Add(1)); err != nil {
				t.Fatal(err)
			}
			stop := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := forwarding.Stop(ctx); err != nil {
					t.Error(err)
				}
			}
			defer stop()
			scope, finish, err := forwarding.Acquire(nil)
			if err != nil {
				t.Fatal(err)
			}
			metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 80}
			first, err := client.DialContext(scope, metadata)
			if err != nil {
				finish()
				t.Fatal(err)
			}
			first, err = forwarding.OwnConn(scope, first)
			finish()
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			exchange := func(c net.Conn) {
				t.Helper()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := c.Write([]byte("hello")); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 5)
				if _, err := io.ReadFull(c, b); err != nil || string(b) != "hello" {
					t.Fatalf("echo: %q %v", b, err)
				}
				_ = c.SetDeadline(time.Time{})
			}
			exchange(first)
			management, err := client.DialContext(context.Background(), metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer management.Close()
			exchange(management)
			if dials != 1 {
				t.Fatalf("did not reuse pool: %d dials", dials)
			}
			stop()
			if retained.Err() != nil {
				t.Fatalf("retained physical context canceled: %v", retained.Err())
			}
			exchange(management)
			if dials != 1 {
				t.Fatal("management replaced the physical connection")
			}
			_ = first.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := first.Read(make([]byte, 1)); err == nil {
				t.Fatal("forwarding stream remained open")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("forwarding stream only returned after read timeout")
			}
			// Retiring the whole pool is stronger than stopping one forwarding
			// generation: both TCP and UDP transports and active streams end.
			udp, err := client.ListenPacket(context.Background(), metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			udpRead := make(chan error, 1)
			go func() { _, _, err := udp.ReadFrom(make([]byte, 32)); udpRead <- err }()
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			for _, transport := range transports {
				if transport.Context().Err() == nil {
					t.Fatal("pool returned before its QUIC connection ended")
				}
			}
			select {
			case err := <-udpRead:
				if err == nil {
					t.Fatal("UDP reader survived retirement")
				}
			case <-time.After(time.Second):
				t.Fatal("pool did not close its UDP reader")
			}
			_ = management.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := management.Read(make([]byte, 1)); err == nil {
				t.Fatal("TCP stream survived pool retirement")
			}
			if _, err := client.DialContext(context.Background(), metadata); !errors.Is(err, types.ClientClosed) {
				t.Fatalf("retired pool admitted TCP: %v", err)
			}
			if _, err := client.ListenPacket(context.Background(), metadata); !errors.Is(err, types.ClientClosed) {
				t.Fatalf("retired pool admitted UDP: %v", err)
			}
			if dials != 2 {
				t.Fatalf("retired pool reconnected: %d", dials)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTUICPoolCloseCancelsAndJoinsPendingDial(t *testing.T) {
	for _, version := range []int{4, 5} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			dial := func(ctx context.Context) (*quic.Conn, error) {
				close(started)
				<-ctx.Done()
				close(canceled)
				<-release
				return nil, ctx.Err()
			}
			var client *tuic.PoolClient
			if version == 4 {
				client = tuic.NewPoolClientV4(&tuic.ClientOptionV4{MaxOpenStreams: 100}, dial)
			} else {
				client = tuic.NewPoolClientV5(&tuic.ClientOptionV5{MaxOpenStreams: 100}, dial)
			}
			dialResult := make(chan error, 1)
			go func() { _, err := client.DialContext(context.Background(), &C.Metadata{}); dialResult <- err }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("dial did not start")
			}
			closeResult := make(chan error, 1)
			go func() { closeResult <- client.Close() }()
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("pool did not cancel pending dial")
			}
			select {
			case err := <-closeResult:
				t.Fatalf("pool forgot unfinished dial: %v", err)
			default:
			}
			close(release)
			if err := <-dialResult; !errors.Is(err, context.Canceled) {
				t.Fatalf("wrong canceled dial result: %v", err)
			}
			if err := <-closeResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}
