package dns_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/fakeip"
	C "github.com/metacubex/mihomo/constant"
	DNS "github.com/metacubex/mihomo/dns"
	D "github.com/miekg/dns"
)

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
