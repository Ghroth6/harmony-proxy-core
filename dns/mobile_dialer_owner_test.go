package dns_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	DNS "github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/mobile/protection"
	D "github.com/miekg/dns"
)

func TestOwnedDNSRetainsActualConcurrentDialUntilBlockedProtectionReturns(t *testing.T) {
	certificate := ownedDNSPeerCertificate(t)
	first, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	port := first.Addr().(*net.TCPAddr).Port
	second, err := tls.Listen("tcp4", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)), &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	var peerTasks sync.WaitGroup
	defer func() { first.Close(); second.Close(); peerTasks.Wait() }()
	for _, listener := range []net.Listener{first, second} {
		peerTasks.Add(1)
		go func(listener net.Listener) {
			defer peerTasks.Done()
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			var length uint16
			if binary.Read(conn, binary.BigEndian, &length) != nil {
				return
			}
			payload := make([]byte, int(length))
			if _, err = io.ReadFull(conn, payload); err != nil {
				return
			}
			question := new(D.Msg)
			if question.Unpack(payload) != nil {
				return
			}
			answer := new(D.Msg).SetReply(question)
			answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 11)}}
			payload, _ = answer.Pack()
			_ = binary.Write(conn, binary.BigEndian, uint16(len(payload)))
			_, _ = conn.Write(payload)
			_, _ = conn.Read(make([]byte, 1))
		}(listener)
	}
	bootstrap, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Close()
	go func() {
		buffer := make([]byte, 2048)
		n, from, err := bootstrap.ReadFrom(buffer)
		if err != nil {
			return
		}
		question := new(D.Msg)
		if question.Unpack(buffer[:n]) != nil {
			return
		}
		answer := new(D.Msg).SetReply(question)
		for _, ip := range []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2)} {
			answer.Answer = append(answer.Answer, &D.A{Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: ip})
		}
		payload, _ := answer.Pack()
		_, _ = bootstrap.WriteTo(payload, from)
	}()
	var gate protection.Gate
	if gate.InstallDialerHook() != protection.Success {
		t.Fatal("actual socket protection hook could not be installed")
	}
	blocked, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	var controls atomic.Int32
	if gate.Register(1, func(_, _ uint64, _ uintptr) int32 {
		if controls.Add(1) == 3 { // bootstrap UDP, then the two real TCP racers.
			close(blocked)
			<-release
			close(returned)
		}
		return protection.Success
	}) != protection.Success {
		t.Fatal("actual external protection callback not registered")
	}
	owner := DNS.NewResolverOwner()
	defer func() {
		once.Do(func() { close(release) })
		_ = owner.Close(context.Background())
		_ = gate.Unregister(1)
	}()
	previousConcurrent := dialer.GetTcpConcurrent()
	dialer.SetTcpConcurrent(true)
	defer dialer.SetTcpConcurrent(previousConcurrent)
	service := DNS.NewService(DNS.NewResolver(DNS.Config{Owner: owner, Default: []DNS.NameServer{{Net: "udp", Addr: bootstrap.LocalAddr().String()}}, Main: []DNS.NameServer{{Net: "tls", Addr: net.JoinHostPort("owned-race.test", strconv.Itoa(port)), Params: map[string]string{"skip-cert-verify": "true"}}}}), DNS.NewEnhancer(DNS.EnhancerConfig{}))
	if err = owner.Activate(protection.WithGeneration(context.Background(), 1)); err != nil {
		t.Fatal(err)
	}
	answer, err := service.ServeMsg(context.Background(), new(D.Msg).SetQuestion("owned-race-answer.test.", D.TypeA))
	if err != nil || len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "203.0.113.11" {
		t.Fatalf("actual DNS winner did not return the TLS answer: %v", err)
	}
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("second real physical dial did not enter protection")
	}
	owner.Cancel()
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = owner.Wait(short)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DNS owner discarded an actual loser dial still borrowing a physical socket: %v", err)
	}
	if gate.Unregister(1) != protection.Busy {
		t.Fatal("real blocked socket protection did not retain its callback owner")
	}
	once.Do(func() { close(release) })
	<-returned
	joined, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = owner.Wait(joined); err != nil {
		t.Fatalf("DNS owner could not join the actual late dial after its callback returned: %v", err)
	}
	if gate.Unregister(1) != protection.Success {
		t.Fatal("DNS cleanup completed before the actual protection request returned")
	}
}
