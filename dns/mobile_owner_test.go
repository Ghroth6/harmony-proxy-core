package dns_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/fakeip"
	C "github.com/metacubex/mihomo/constant"
	DNS "github.com/metacubex/mihomo/dns"
	"github.com/metacubex/quic-go"
	MTLS "github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

func TestOwnedDNSUsesActualQUICAnswerAndJoinsTransportRetirement(t *testing.T) {
	certificate := ownedDNSPeerCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &MTLS.Config{Certificates: []MTLS.Certificate{{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey}}, NextProtos: []string{"doq"}}, &quic.Config{MaxIdleTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerRelease := make(chan struct{})
	peerDone := make(chan struct{})
	defer func() { close(peerRelease); <-peerDone }()
	request := make(chan error, 1)
	go func() {
		defer close(peerDone)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := listener.Accept(ctx)
		if err != nil {
			request <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			request <- err
			return
		}
		_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
		var length uint16
		err = binary.Read(stream, binary.BigEndian, &length)
		payload := make([]byte, int(length))
		if err == nil {
			_, err = io.ReadFull(stream, payload)
		}
		question := new(D.Msg)
		if err == nil {
			err = question.Unpack(payload)
		}
		if err == nil && (question.Id != 0 || len(question.Question) != 1 || question.Question[0].Name != "owned-quic.test.") {
			err = errors.New("actual DoQ peer received an unexpected framed question")
		}
		if err == nil {
			answer := new(D.Msg).SetReply(question)
			answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 10)}}
			payload, err = answer.Pack()
			if err == nil {
				err = binary.Write(stream, binary.BigEndian, uint16(len(payload)))
			}
			if err == nil {
				_, err = stream.Write(payload)
			}
			if err == nil {
				err = stream.Close()
			}
		}
		request <- err
		<-peerRelease // retain the genuine reusable peer until the assertion ends.
	}()
	owner := DNS.NewResolverOwner()
	defer owner.Close(context.Background())
	service := DNS.NewService(DNS.NewResolver(DNS.Config{Owner: owner, Main: []DNS.NameServer{{Net: "quic", Addr: listener.Addr().String(), Params: map[string]string{"skip-cert-verify": "true"}}}}), DNS.NewEnhancer(DNS.EnhancerConfig{}))
	if err = owner.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	question := new(D.Msg).SetQuestion("owned-quic.test.", D.TypeA)
	question.Id = 1234
	answer, err := service.ServeMsg(context.Background(), question)
	if err != nil || len(answer.Answer) != 1 || answer.Id != 1234 || answer.Answer[0].(*D.A).A.String() != "203.0.113.10" {
		t.Fatalf("owned resolver did not return the real framed QUIC answer: %v", err)
	}
	if err = <-request; err != nil {
		t.Fatal(err)
	}
	owner.Cancel()
	deadline, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	if err = owner.Wait(deadline); err != nil {
		t.Fatalf("actual QUIC transport retirement did not return: %v", err)
	}
	if _, err = service.ServeMsg(context.Background(), question); !errors.Is(err, DNS.ErrResolverRetired) {
		t.Fatalf("retired QUIC candidate admitted a cached DNS query: %v", err)
	}
}

func TestOwnedDNSCancelClosesActualIdleHTTPSAndHTTP2Pool(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http11", true: "http2"}[h2], func(t *testing.T) {
			closed := make(chan struct{})
			var closeOnce sync.Once
			protocol := make(chan int, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				protocol <- r.ProtoMajor
				payload, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
				question := new(D.Msg)
				if err == nil {
					err = question.Unpack(payload)
				}
				if err != nil || len(question.Question) != 1 || question.Question[0].Name != "owned-https-idle.test." {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				answer := new(D.Msg).SetReply(question)
				answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 9)}}
				payload, _ = answer.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(payload)
			}))
			server.EnableHTTP2 = h2
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					closeOnce.Do(func() { close(closed) })
				}
			}
			server.StartTLS()
			defer server.Close()
			owner := DNS.NewResolverOwner()
			defer owner.Close(context.Background())
			service := DNS.NewService(DNS.NewResolver(DNS.Config{Owner: owner, Main: []DNS.NameServer{{Net: "https", Addr: server.URL + "/dns-query", Params: map[string]string{"skip-cert-verify": "true"}}}}), DNS.NewEnhancer(DNS.EnhancerConfig{}))
			if err := owner.Activate(context.Background()); err != nil {
				t.Fatal(err)
			}
			answer, err := service.ServeMsg(context.Background(), new(D.Msg).SetQuestion("owned-https-idle.test.", D.TypeA))
			if err != nil || len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "203.0.113.9" {
				t.Fatalf("owned DNS did not return the actual HTTPS answer: %v", err)
			}
			wantProtocol := 1
			if h2 {
				wantProtocol = 2
			}
			if <-protocol != wantProtocol {
				t.Fatal("actual HTTPS peer negotiated the wrong transport")
			}
			select {
			case <-closed:
				t.Fatal("active candidate discarded its real reusable HTTPS pool")
			case <-time.After(30 * time.Millisecond):
			}
			owner.Cancel()
			deadline, stop := context.WithTimeout(context.Background(), 750*time.Millisecond)
			defer stop()
			if err = owner.Wait(deadline); err != nil {
				t.Fatalf("DNS owner failed to join actual HTTPS retirement: %v", err)
			}
			select {
			case <-closed:
			case <-time.After(750 * time.Millisecond):
				t.Fatal("DNS owner returned cleanup with an actual HTTPS pooled connection still open")
			}
		})
	}
}

func ownedDNSPeerCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned-dns.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestOwnedDNSCancelRetiresActualTLSReadAfterSharedWaiterLeaves(t *testing.T) {
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ownedDNSPeerCertificate(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request := make(chan error, 1)
	peerClosed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			request <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		payload := make([]byte, int(length))
		if err == nil {
			_, err = io.ReadFull(conn, payload)
		}
		message := new(D.Msg)
		if err == nil {
			err = message.Unpack(payload)
		}
		if err == nil && (len(message.Question) != 1 || message.Question[0].Name != "owned-tls-lifecycle.test.") {
			err = errors.New("physical TLS DNS peer received an unexpected question")
		}
		request <- err
		_, err = conn.Read(make([]byte, 1)) // withhold the DNS answer.
		peerClosed <- err
	}()
	owner := DNS.NewResolverOwner()
	defer owner.Close(context.Background())
	resolvers := DNS.NewResolver(DNS.Config{Owner: owner, Main: []DNS.NameServer{{Net: "tls", Addr: listener.Addr().String(), Params: map[string]string{"skip-cert-verify": "true"}}}})
	service := DNS.NewService(resolvers, DNS.NewEnhancer(DNS.EnhancerConfig{}))
	if err = owner.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	waiter, cancel := context.WithCancel(context.Background())
	defer cancel()
	queryDone := make(chan error, 1)
	go func() {
		_, err := service.ServeMsg(waiter, new(D.Msg).SetQuestion("owned-tls-lifecycle.test.", D.TypeA))
		queryDone <- err
	}()
	select {
	case err = <-request:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned DNS did not reach the real TLS peer")
	}
	cancel()
	if err = <-queryDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("individual TLS DNS waiter lost cancellation: %v", err)
	}
	select {
	case err = <-peerClosed:
		t.Fatalf("individual waiter closed the independently owned TLS read: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	owner.Cancel()
	deadline, stop := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer stop()
	if err = owner.Wait(deadline); err != nil {
		t.Fatalf("DNS owner did not join the actual TLS read: %v", err)
	}
	select {
	case err = <-peerClosed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("TLS socket was not actually closed by instance retirement: %v", err)
		}
	case <-time.After(750 * time.Millisecond):
		t.Fatal("owner reported TLS cleanup while its physical read remained alive")
	}
}

func TestOwnedDNSServiceRejectsPreparedAndRetiredFakeIPQueries(t *testing.T) {
	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.0/24"), Size: 32})
	if err != nil {
		t.Fatal(err)
	}
	owner := DNS.NewResolverOwner()
	defer owner.Close(context.Background())
	resolvers := DNS.NewResolver(DNS.Config{Owner: owner})
	service := DNS.NewService(resolvers, DNS.NewEnhancer(DNS.EnhancerConfig{EnhancedMode: C.DNSFakeIP, FakeIPPool: pool, FakeIPSkipper: &fakeip.Skipper{}}))
	question := new(D.Msg).SetQuestion("owned-fake-ip.test.", D.TypeA)
	if _, err = service.ServeMsg(context.Background(), question); !errors.Is(err, DNS.ErrResolverNotActive) {
		t.Fatalf("prepared DNS service admitted a fake-IP query: %v", err)
	}
	if err = owner.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	answer, err := service.ServeMsg(context.Background(), question)
	if err != nil || len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "198.18.0.4" {
		t.Fatalf("active instance lost the actual fake-IP policy: answer=%v err=%v", answer, err)
	}
	if err = owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ServeMsg(context.Background(), question); !errors.Is(err, DNS.ErrResolverRetired) {
		t.Fatalf("retired DNS service answered from its fake-IP cache: %v", err)
	}
}

func TestOwnedDNSCancelRetiresActualSharedTCPReadAfterWaiterCancellation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	request := make(chan error, 1)
	peerClosed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			request <- err
			return
		}
		accepted <- conn
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		payload := make([]byte, int(length))
		if err == nil {
			_, err = io.ReadFull(conn, payload)
		}
		message := new(D.Msg)
		if err == nil {
			err = message.Unpack(payload)
		}
		if err == nil && (len(message.Question) != 1 || message.Question[0].Name != "owned-dns-lifecycle.test.") {
			err = errors.New("physical DNS peer received an unexpected question")
		}
		request <- err
		// No answer: owner cancellation must close the actual client socket and
		// interrupt its physical read, rather than wait for the DNS timeout.
		_, err = conn.Read(make([]byte, 1))
		peerClosed <- err
	}()
	owner := DNS.NewResolverOwner()
	defer owner.Close(context.Background())
	resolvers := DNS.NewResolver(DNS.Config{Owner: owner, Main: []DNS.NameServer{{Net: "tcp", Addr: listener.Addr().String()}}})
	service := DNS.NewService(resolvers, DNS.NewEnhancer(DNS.EnhancerConfig{}))
	if err = owner.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	waiter, cancelWaiter := context.WithCancel(context.Background())
	defer cancelWaiter()
	queryDone := make(chan error, 1)
	go func() {
		_, err := service.ServeMsg(waiter, new(D.Msg).SetQuestion("owned-dns-lifecycle.test.", D.TypeA))
		queryDone <- err
	}()
	select {
	case err = <-request:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned service did not reach the actual DNS TCP peer")
	}
	conn := <-accepted
	defer conn.Close()
	cancelWaiter()
	select {
	case err = <-queryDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("individual DNS waiter cancellation lost its error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("individual DNS waiter did not cancel")
	}
	select {
	case err = <-peerClosed:
		t.Fatalf("individual waiter retired the instance's shared upstream: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	owner.Cancel()
	deadline, cancelDeadline := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancelDeadline()
	if err = owner.Wait(deadline); err != nil {
		t.Fatalf("DNS owner did not join the real shared worker and physical read: %v", err)
	}
	select {
	case err = <-peerClosed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("DNS owner did not close its actual physical TCP socket: %v", err)
		}
	case <-time.After(750 * time.Millisecond):
		t.Fatal("DNS owner reported cleanup while its physical socket stayed open")
	}
	if _, err = service.ServeMsg(context.Background(), new(D.Msg).SetQuestion("owned-dns-lifecycle.test.", D.TypeA)); err == nil {
		t.Fatal("retired DNS service admitted another query")
	}
	if err = owner.Activate(context.Background()); err == nil {
		t.Fatal("a retired DNS owner was reused for another runtime generation")
	}
}
