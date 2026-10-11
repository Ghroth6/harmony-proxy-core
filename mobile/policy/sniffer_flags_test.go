package policy_test

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
)

func TestOriginalSnifferKeepsForceSkipMappingAndProtocolOverridePolicies(t *testing.T) {
	tests := []struct {
		name, flags, host          string
		mapping, sniffed, override bool
	}{
		{name: "pure IP disabled", flags: " parse-pure-ip: false", sniffed: false},
		{name: "forced original domain", flags: " parse-pure-ip: false\n force-domain: ['forced.example']", host: "forced.example", sniffed: true},
		{name: "forced DNS mapping", flags: " parse-pure-ip: false\n force-dns-mapping: true", host: "mapped.example", mapping: true, sniffed: true},
		{name: "skip original source", flags: " parse-pure-ip: true\n skip-src-address: ['10.111.0.0/30']"},
		{name: "skip original destination", flags: " parse-pure-ip: true\n skip-dst-address: ['192.0.2.0/24']"},
		{name: "skip sniffed domain", flags: " parse-pure-ip: true\n skip-domain: ['documentation.example']"},
		{name: "protocol override", flags: " parse-pure-ip: true", sniffed: true, override: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nsniffer:\n enable: true\n override-destination: false\n%s\n sniff: {HTTP: {ports: [80], override-destination: %t}}\nrules: ['MATCH,REJECT']\n", test.flags, test.override))
			engine, cfg := preparedPublicSniffer(t, raw)
			baseline := engine.ResourceAcquireCount()
			dispatcher, err := sniffer.NewDispatcher(cfg.Sniffer)
			if err != nil || !dispatcher.Enable() {
				t.Fatal("original enabled sniffer was not constructed", err)
			}
			client, inbound := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: documentation.example\r\n\r\n")
			}()
			metadata := &C.Metadata{NetWork: C.TCP, Host: test.host, SrcIP: netip.MustParseAddr("10.111.0.1"), DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80}
			if test.mapping {
				metadata.DNSMode = C.DNSMapping
			}
			sniffed := dispatcher.TCPSniff(N.NewBufferedConn(inbound), metadata)
			_ = inbound.Close()
			_ = client.Close()
			<-done
			if sniffed != test.sniffed {
				t.Fatal("original force/skip policy changed")
			}
			if test.sniffed {
				if metadata.SniffHost != "documentation.example" {
					t.Fatal("original Host was not sniffed")
				}
				if test.override {
					if metadata.Host != "documentation.example" || metadata.DstIP.IsValid() {
						t.Fatal("per-protocol override was lost")
					}
				} else if metadata.Host != test.host || metadata.DstIP.String() != "192.0.2.1" {
					t.Fatal("override=false changed the original destination")
				}
			} else if metadata.SniffHost != "" || metadata.Host != test.host || metadata.DstIP.String() != "192.0.2.1" {
				t.Fatal("skipped sniffing changed metadata")
			}
			if engine.ResourceAcquireCount() != baseline {
				t.Fatal("sniffer preparation or parsing acquired a resource")
			}
		})
	}
}
