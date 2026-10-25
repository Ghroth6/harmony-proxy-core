package policy_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	D "github.com/miekg/dns"
)

func TestOriginalDNSAdapterCapturesCandidateServiceAndJoinsBeforeRetirement(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			first, firstQueries := publicDNSPeer(t, "192.0.2.10")
			later, laterQueries := publicDNSPeer(t, "192.0.2.20")
			engine, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := engine.Close(); err != nil {
					t.Error(err)
				}
			})
			build := func(server string) *config.Config {
				input := []byte(fmt.Sprintf("ipv6: false\nprofile: {store-fake-ip: false}\nproxies: [{name: PublicDNS, type: dns}]\ndns: {enable: true, ipv6: false, enhanced-mode: redir-host, nameserver: ['%s'], default-nameserver: [127.0.0.1]}\nrules: ['MATCH,PublicDNS']\n", server))
				platform := publicPlatform()
				platform.RuntimeOptions.DNS = true
				platform.TunPolicy.DNSServers = []string{"10.111.0.2"}
				prepared, err := contract.Seal(contract.Digest(input), nil, platform, nil)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := engine.BuildCandidate(input, prepared)
				if err != nil {
					t.Fatal(err)
				}
				return cfg
			}
			candidate := build(first)
			var protected atomic.Int32
			root, generation := activatePublicPolicy(t, candidate, []string{}, &protected)
			metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53}
			var conn net.Conn
			var packet net.PacketConn
			if transport == "tcp" {
				conn, err = candidate.Proxies["PublicDNS"].DialContext(root, metadata)
			} else {
				packet, err = candidate.Proxies["PublicDNS"].ListenPacketContext(root, metadata)
			}
			if err != nil {
				t.Fatal(err)
			}
			if conn != nil {
				defer conn.Close()
			}
			if packet != nil {
				defer packet.Close()
			}
			exchange := func(name string) string {
				q := new(D.Msg)
				q.SetQuestion(name, D.TypeA)
				payload, _ := q.Pack()
				var answer []byte
				if conn != nil {
					_ = conn.SetDeadline(time.Now().Add(time.Second))
					frame := make([]byte, 2+len(payload))
					binary.BigEndian.PutUint16(frame, uint16(len(payload)))
					copy(frame[2:], payload)
					if _, err := conn.Write(frame); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(conn, frame[:2]); err != nil {
						t.Fatal(err)
					}
					answer = make([]byte, binary.BigEndian.Uint16(frame[:2]))
					if _, err := io.ReadFull(conn, answer); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := packet.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}); err != nil {
						t.Fatal(err)
					}
					answer = make([]byte, 2048)
					n, _, err := packet.ReadFrom(answer)
					if err != nil {
						t.Fatal(err)
					}
					answer = answer[:n]
				}
				response := new(D.Msg)
				if response.Unpack(answer) != nil || len(response.Answer) != 1 {
					t.Fatal("actual DNS adapter response missing")
				}
				return response.Answer[0].(*D.A).A.String()
			}
			if got := exchange("first.captured.invalid."); got != "192.0.2.10" {
				t.Fatal("original candidate service was not used")
			}
			second := build(later)
			defer second.Discard(context.Background())
			if err := second.ActivateMobileNetwork(generation); err != nil {
				t.Fatal(err)
			}
			if err := second.ActivateMobilePolicyDNS(root); err != nil {
				t.Fatal(err)
			}
			old := resolver.DefaultService
			resolver.DefaultService = second.MobileDNSService()
			defer func() { resolver.DefaultService = old }()
			if got := exchange("second.captured.invalid."); got != "192.0.2.10" {
				t.Errorf("an established DNS adapter switched to a later global service: %s", got)
			}
			candidate.CancelMobilePolicyServices()
			wait, finish := context.WithTimeout(context.Background(), time.Second)
			defer finish()
			if err := candidate.WaitMobilePolicyServices(wait); err != nil {
				t.Fatal(err)
			}
			q := new(D.Msg)
			q.SetQuestion("after-retirement.invalid.", D.TypeA)
			payload, _ := q.Pack()
			if conn != nil {
				_ = conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
				frame := make([]byte, 2+len(payload))
				binary.BigEndian.PutUint16(frame, uint16(len(payload)))
				copy(frame[2:], payload)
				if _, err := conn.Write(frame); err == nil {
					t.Error("joined old DNS owner still admitted a TCP message")
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := packet.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}); err == nil {
					t.Error("joined old DNS owner still admitted a UDP message")
				}
				if err := packet.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if firstQueries.Load() != 2 || laterQueries.Load() != 0 || protected.Load() < 2 {
				t.Errorf("candidate DNS/protection mismatch: first=%d later=%d protected=%d", firstQueries.Load(), laterQueries.Load(), protected.Load())
			}
		})
	}
}

func TestOriginalDNSAdapterCancellationJoinsPendingTCPAndUDPQueries(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			serverPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			seen := make(chan struct{}, 1)
			server := &D.Server{PacketConn: serverPacket, Handler: D.HandlerFunc(func(D.ResponseWriter, *D.Msg) {
				select {
				case seen <- struct{}{}:
				default:
				}
			})}
			serverDone := make(chan struct{})
			go func() { defer close(serverDone); _ = server.ActivateAndServe() }()
			t.Cleanup(func() { _ = server.Shutdown(); <-serverDone })
			engine, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := engine.Close(); err != nil {
					t.Error(err)
				}
			})
			input := []byte(fmt.Sprintf("ipv6: false\nprofile: {store-fake-ip: false}\nproxies: [{name: PublicDNS, type: dns}]\ndns: {enable: true, ipv6: false, enhanced-mode: redir-host, nameserver: ['%s'], default-nameserver: [127.0.0.1]}\nrules: ['MATCH,PublicDNS']\n", serverPacket.LocalAddr().String()))
			platform := publicPlatform()
			platform.RuntimeOptions.DNS = true
			platform.TunPolicy.DNSServers = []string{"10.111.0.2"}
			prepared, err := contract.Seal(contract.Digest(input), nil, platform, nil)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := engine.BuildCandidate(input, prepared)
			if err != nil {
				t.Fatal(err)
			}
			var protected atomic.Int32
			root, _ := activatePublicPolicy(t, cfg, []string{}, &protected)
			question := new(D.Msg)
			question.SetQuestion("pending.adapter.invalid.", D.TypeA)
			payload, _ := question.Pack()
			metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53}
			read := make(chan error, 1)
			if transport == "tcp" {
				conn, err := cfg.Proxies["PublicDNS"].DialContext(root, metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				frame := make([]byte, 2+len(payload))
				binary.BigEndian.PutUint16(frame, uint16(len(payload)))
				copy(frame[2:], payload)
				if _, err := conn.Write(frame); err != nil {
					t.Fatal(err)
				}
				go func() { header := make([]byte, 2); _, err := io.ReadFull(conn, header); read <- err }()
			} else {
				conn, err := cfg.Proxies["PublicDNS"].ListenPacketContext(root, metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := conn.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}); err != nil {
					t.Fatal(err)
				}
				go func() { _, _, err := conn.ReadFrom(make([]byte, 2048)); read <- err }()
			}
			select {
			case <-seen:
			case <-time.After(time.Second):
				t.Fatal("actual upstream DNS request did not become pending")
			}
			cfg.CancelMobilePolicyServices()
			wait, finish := context.WithTimeout(context.Background(), time.Second)
			defer finish()
			if err := cfg.WaitMobilePolicyServices(wait); err != nil {
				t.Fatal("pending relay or resolver worker did not join", err)
			}
			select {
			case err := <-read:
				if err == nil {
					t.Fatal("cancelled DNS relay published an answer after its owner retired")
				}
			case <-time.After(time.Second):
				t.Fatal("retired DNS association retained its blocked read")
			}
			if protected.Load() == 0 {
				t.Fatal("actual pending DNS transport bypassed generation protection")
			}
		})
	}
}

func TestOriginalDNSAdapterReturnsSERVFAILAndKeepsActiveAssociation(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &D.Server{PacketConn: upstream, Handler: D.HandlerFunc(func(w D.ResponseWriter, request *D.Msg) {
				response := new(D.Msg)
				response.SetReply(request)
				if request.Question[0].Name == "failure.adapter.invalid." {
					response.Rcode = D.RcodeServerFailure
				} else {
					answer, err := D.NewRR(request.Question[0].Name + " 60 IN A 192.0.2.10")
					if err != nil {
						t.Error(err)
						return
					}
					response.Answer = []D.RR{answer}
				}
				_ = w.WriteMsg(response)
			})}
			serverDone := make(chan struct{})
			go func() { defer close(serverDone); _ = server.ActivateAndServe() }()
			t.Cleanup(func() { _ = server.Shutdown(); <-serverDone })
			engine, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := engine.Close(); err != nil {
					t.Error(err)
				}
			})
			input := []byte(fmt.Sprintf("ipv6: false\nprofile: {store-fake-ip: false}\nproxies: [{name: PublicDNS, type: dns}]\ndns: {enable: true, ipv6: false, enhanced-mode: redir-host, nameserver: ['%s'], default-nameserver: [127.0.0.1]}\nrules: ['MATCH,PublicDNS']\n", upstream.LocalAddr().String()))
			platform := publicPlatform()
			platform.RuntimeOptions.DNS = true
			platform.TunPolicy.DNSServers = []string{"10.111.0.2"}
			prepared, err := contract.Seal(contract.Digest(input), nil, platform, nil)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := engine.BuildCandidate(input, prepared)
			if err != nil {
				t.Fatal(err)
			}
			var protected atomic.Int32
			root, _ := activatePublicPolicy(t, cfg, []string{}, &protected)
			metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53}
			var conn net.Conn
			var packet net.PacketConn
			if transport == "tcp" {
				conn, err = cfg.Proxies["PublicDNS"].DialContext(root, metadata)
			} else {
				packet, err = cfg.Proxies["PublicDNS"].ListenPacketContext(root, metadata)
			}
			if err != nil {
				t.Fatal(err)
			}
			if conn != nil {
				defer conn.Close()
			} else {
				defer packet.Close()
			}
			for _, name := range []string{"failure.adapter.invalid.", "success.adapter.invalid."} {
				question := new(D.Msg)
				question.SetQuestion(name, D.TypeA)
				payload, _ := question.Pack()
				result := make(chan []byte, 1)
				if conn != nil {
					frame := make([]byte, 2+len(payload))
					binary.BigEndian.PutUint16(frame, uint16(len(payload)))
					copy(frame[2:], payload)
					if _, err := conn.Write(frame); err != nil {
						t.Fatal(err)
					}
					go func() {
						header := make([]byte, 2)
						if _, err := io.ReadFull(conn, header); err != nil {
							result <- nil
							return
						}
						answer := make([]byte, binary.BigEndian.Uint16(header))
						if _, err := io.ReadFull(conn, answer); err != nil {
							answer = nil
						}
						result <- answer
					}()
				} else {
					if _, err := packet.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}); err != nil {
						t.Fatal(err)
					}
					go func() {
						answer := make([]byte, 2048)
						n, _, err := packet.ReadFrom(answer)
						if err != nil {
							result <- nil
						} else {
							result <- answer[:n]
						}
					}()
				}
				select {
				case answer := <-result:
					response := new(D.Msg)
					if response.Unpack(answer) != nil || response.Id != question.Id {
						t.Fatal("active DNS association closed instead of replying")
					}
					if name == "failure.adapter.invalid." {
						if response.Rcode != D.RcodeServerFailure {
							t.Fatal("ordinary upstream failure must retain SERVFAIL")
						}
					} else if response.Rcode != D.RcodeSuccess || len(response.Answer) != 1 || response.Answer[0].(*D.A).A.String() != "192.0.2.10" {
						t.Fatal("association must remain usable after its SERVFAIL response")
					}
				case <-time.After(time.Second):
					t.Fatal("active DNS association dropped its reply")
				}
			}
			if protected.Load() == 0 {
				t.Fatal("actual DNS error/recovery exchanges bypassed protection")
			}
		})
	}
}
