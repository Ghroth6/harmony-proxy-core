package policy_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	clock "github.com/metacubex/mihomo/ntp"
)

func publicNTPPacket(request []byte) []byte {
	response := make([]byte, 48)
	response[0] = 4<<3 | 4
	response[1] = 1
	copy(response[24:32], request[40:48])
	stamp := func(out []byte, now time.Time) {
		seconds := uint64(now.Unix() + 2208988800)
		fraction := uint64(now.Nanosecond()) << 32 / 1e9
		binary.BigEndian.PutUint64(out, seconds<<32|fraction)
	}
	now := time.Now().Add(2 * time.Second)
	stamp(response[16:24], now.Add(-time.Minute))
	stamp(response[32:40], now)
	stamp(response[40:48], now)
	return response
}

func TestOriginalNTPUsesOwnedCandidateClockAndRetiresPendingUDP(t *testing.T) {
	for _, mode := range []string{"physical", "named", "pending"} {
		t.Run(mode, func(t *testing.T) {
			peer, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var requests, protected atomic.Int32
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				for {
					packet := make([]byte, 512)
					n, address, err := peer.ReadFrom(packet)
					if err != nil {
						return
					}
					requests.Add(1)
					if mode != "pending" && n >= 48 {
						_, _ = peer.WriteTo(publicNTPPacket(packet), address)
					}
				}
			}()
			t.Cleanup(func() { _ = peer.Close(); <-closed })
			engine, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := engine.Close(); err != nil {
					t.Error(err)
				}
			})
			proxy := ""
			if mode == "named" {
				proxy = "DIRECT"
			}
			input := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nntp: {enable: true, server: 127.0.0.1, port: %d, interval: 1, dialer-proxy: '%s', write-to-system: false}\nrules: ['MATCH,DIRECT']\n", peer.LocalAddr().(*net.UDPAddr).Port, proxy))
			clock.SetOffset(123 * time.Millisecond)
			t.Cleanup(func() { clock.SetOffset(0) })
			plan := engine.Plan("ntp-plan", input, nil)
			if plan.Category != "planned" || !plan.ResourcesComplete {
				t.Fatalf("plan %+v", plan)
			}
			prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if receipt := engine.Validate("ntp-validate", input, prepared); receipt.Category != "pass" {
				t.Fatalf("validate %+v", receipt)
			}
			cfg, err := engine.BuildCandidate(input, prepared)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.NTP == nil || !cfg.NTP.Enable || cfg.NTP.DialerProxy != proxy || cfg.NTP.WriteToSystem || requests.Load() != 0 || clock.GetOffset() != 123*time.Millisecond {
				t.Fatal("NTP fields or inactive preparation changed")
			}
			ctx, _ := activatePublicPolicy(t, cfg, []string{}, &protected)
			if err := cfg.ActivateMobilePolicyResources(ctx); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for requests.Load() == 0 || (mode != "pending" && clock.GetOffset() < time.Second) {
				if time.Now().After(deadline) {
					t.Fatalf("NTP no exchange/offset: requests=%d protection=%d offset=%v", requests.Load(), protected.Load(), clock.GetOffset())
				}
				time.Sleep(5 * time.Millisecond)
			}
			if protected.Load() == 0 {
				t.Fatal("NTP bypassed the actual physical protection hook")
			}
			if mode != "pending" && (clock.GetOffset() < time.Second || clock.GetOffset() > 3*time.Second) {
				t.Fatalf("unexpected public peer offset %s", clock.GetOffset())
			}
			cfg.CancelMobilePolicyServices()
			wait, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := cfg.WaitMobilePolicyServices(wait); err != nil {
				t.Fatal("NTP retirement did not join the actual pending socket", err)
			}
			if clock.GetOffset() != 0 {
				t.Fatal("retired NTP owner retained its offset")
			}
			if err := cfg.ActivateMobilePolicyResources(ctx); err == nil {
				t.Fatal("retired NTP restarted")
			}
		})
	}
}
