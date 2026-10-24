//go:build with_gvisor

package runtime

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// Retain the existing short-history budget. This creation window never owns a
// connection and never admits, limits or selects the authoritative active list.
const maxConnectionHistory = 16

func (e *runEngine) runtimeConnection(info *statistic.TrackerInfo) bool {
	return info != nil && info.Metadata != nil && info.Metadata.Type == C.TUN &&
		info.Metadata.ForwardingGeneration == e.transfer.receipt.Generation &&
		forwarding.Generation(info.Metadata.RequestContext) == e.transfer.receipt.Generation
}

func readableConnection(info *statistic.TrackerInfo, kind C.AdapterType) ConnectionReadable {
	value := ConnectionReadable{SchemaVersion: 1, State: "available", Host: info.Metadata.RuleHost(), RulePayload: info.RulePayload, Chain: append([]string{}, info.Chain...), OutboundType: "unknown"}
	switch kind {
	case C.Direct:
		value.OutboundType = "direct"
	case C.Shadowsocks, C.ShadowsocksR, C.Snell, C.Socks5, C.Http,
		C.Vmess, C.Vless, C.Trojan, C.Hysteria, C.Hysteria2, C.WireGuard,
		C.Tuic, C.Ssh, C.Mieru, C.AnyTLS, C.Sudoku, C.Masque,
		C.TrustTunnel, C.ShadowQuic, C.OpenVPN, C.Tailscale, C.ZeroTier,
		C.EasyTier, C.GostRelay:
		value.OutboundType = strings.ToLower(kind.String())
	}
	valid := utf8.ValidString(value.Host) && len(value.Host) <= 1024 && utf8.ValidString(value.RulePayload) && len(value.RulePayload) <= 1024 && len(value.Chain) <= 8
	for _, label := range value.Chain {
		valid = valid && utf8.ValidString(label) && len(label) <= 256
	}
	if !valid {
		return ConnectionReadable{SchemaVersion: 1, State: "limited", Chain: []string{}, OutboundType: "unknown"}
	}
	return value
}

func (e *runEngine) connectionValue(info *statistic.TrackerInfo, state string, kind C.AdapterType) ConnectionObservation {
	m := info.Metadata
	target := m.DstIP
	port := m.DstPort
	original := false
	if raw, ok := m.RawDstAddr.(interface{ AddrPort() netip.AddrPort }); ok && raw.AddrPort().IsValid() {
		target, port, original = raw.AddrPort().Addr(), raw.AddrPort().Port(), true
	}
	value := ConnectionObservation{ID: info.UUID.String(), State: state, Protocol: strings.ToLower(m.NetWork.String()),
		SourcePort: m.SrcPort, StartedAt: info.Start.UnixMilli(), TargetPort: port, Rule: "redacted", Node: "redacted",
		OriginalDestination: original, Upload: info.UploadTotal.Load(), Download: info.DownloadTotal.Load(), Readable: readableConnection(info, kind)}
	if m.SrcIP.IsValid() {
		value.SourceAddress = m.SrcIP.String()
	}
	if m.DstIP.IsValid() {
		value.DestinationAddress = m.DstIP.String()
	}
	if target.IsValid() {
		value.TargetAddress, value.AddressFamily = target.String(), "ipv6"
		if target.Is4() {
			value.TargetIPv4, value.AddressFamily = target.String(), "ipv4"
		}
	}
	if safeID.MatchString(info.Rule) {
		value.Rule = info.Rule
	}
	if len(info.Chain) > 0 && safeID.MatchString(info.Chain[0]) {
		value.Node = info.Chain[0]
	}
	if e.sourcePolicy {
		value.Attribution = &ConnectionAttribution{RulePayloadDigest: observationDigest(info.RulePayload)}
		if host := normalizedDomain(m.RuleHost()); host != "" {
			value.Attribution.DomainDigest = observationDigest(host)
		}
		if len(info.Chain) > 0 {
			value.Attribution.NodeDigest = observationDigest(info.Chain[0])
		}
	}
	return value
}

func (e *runEngine) pruneDNSFacts() {
	for id, query := range e.dnsFacts {
		tracker := statistic.DefaultManager.Get(id)
		if tracker != nil && e.runtimeConnection(tracker.Info()) {
			continue
		}
		encoded, _ := json.Marshal(query)
		e.dnsFactsBytes -= len(id) + len(encoded)
		delete(e.dnsFacts, id)
	}
}

// This existing fork subscription supplies only a bounded creation history and
// the exact DNS association available at creation. Range is the active authority.
// The positive DNS facts contain values only, never Tracker/Conn/lease owners.
func (e *runEngine) observeConnection(tracker statistic.Tracker) {
	info := tracker.Info()
	if !e.runtimeConnection(info) {
		return
	}
	e.transfer.mu.Lock()
	defer e.transfer.mu.Unlock()
	if e.transfer.ctx.Err() != nil {
		return
	}
	value := e.connectionValue(info, "history", tracker.EgressType())
	var query *DNSQueryObservation
	if e.dns != nil && value.Attribution != nil && value.Attribution.DomainDigest != "" && value.OriginalDestination {
		target, err := netip.ParseAddr(value.TargetAddress)
		if err == nil {
			query = e.dns.queryFor(value.Attribution.DomainDigest, target)
		}
	}
	if query != nil {
		value.Attribution.DNSSequence = query.Sequence
		encoded, _ := json.Marshal(query)
		cost := len(value.ID) + len(encoded)
		if e.dnsFactsBytes+cost > MaxOutputBytes {
			e.pruneDNSFacts()
		}
		if e.dnsFactsBytes+cost <= MaxOutputBytes {
			if e.dnsFacts == nil {
				e.dnsFacts = map[string]DNSQueryObservation{}
			}
			e.dnsFacts[value.ID] = *query
			e.dnsFactsBytes += cost
		} else if e.dnsFactsDropped < MaxObservation {
			e.dnsFactsDropped++
		}
	}
	e.observations = append(e.observations, observation{value: value, info: info, dns: query})
	if len(e.observations) > maxConnectionHistory {
		copy(e.observations, e.observations[1:])
		e.observations[len(e.observations)-1] = observation{}
		e.observations = e.observations[:maxConnectionHistory]
		if e.historyDropped < MaxObservation {
			e.historyDropped++
		}
	}
}

func (e *runEngine) fillConnections(receipt *Receipt) {
	receipt.ConnectionSnapshot = ConnectionSnapshot{CapturedAt: time.Now().UnixMilli(), HistoryDropped: e.historyDropped, DNSFactsDropped: e.dnsFactsDropped}
	records := []observation{}
	returned := map[string]bool{}
	bytes, nodes := 0, 0
	add := func(record observation) bool {
		encoded, _ := json.Marshal(record.value)
		// 17 base values + the readable object/fields/array (7), its
		// labels, and optional attribution object/fields (6). Reserve 1024
		// values for the bounded receipt/resources/DNS envelope. This is a
		// serialization budget, never an activity or admission limit.
		cost := 24 + len(record.value.Readable.Chain)
		if record.value.Attribution != nil {
			cost += 6
		}
		if bytes+len(encoded)+1 > MaxOutputBytes || nodes+cost > MaxOutputNodes-1024 {
			return false
		}
		bytes += len(encoded) + 1
		nodes += cost
		records = append(records, record)
		returned[record.value.ID] = true
		return true
	}
	// Do not consult any observation inventory to choose current activity. The
	// source registry may change during traversal; counters are sampled values.
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		info := tracker.Info()
		if !e.runtimeConnection(info) {
			return true
		}
		receipt.ConnectionSnapshot.Active++
		value := e.connectionValue(info, "active", tracker.EgressType())
		var query *DNSQueryObservation
		if retained, ok := e.dnsFacts[value.ID]; ok {
			query = &retained
		}
		if !add(observation{value: value, dns: query}) {
			receipt.ConnectionSnapshot.ActiveOmitted++
		}
		return true
	})
	// Stable ordering is only presentation. No activity ranking or active-slot
	// reservation can hide another registered flow.
	sort.Slice(records, func(i, j int) bool { return records[i].value.ID < records[j].value.ID })
	for index := range e.observations {
		record := &e.observations[index]
		// Closing after Range must not duplicate this UUID as history in the
		// same nontransactional traversal.
		if returned[record.value.ID] {
			continue
		}
		if record.info != nil {
			if current := statistic.DefaultManager.Get(record.value.ID); current != nil && current.Info() == record.info {
				continue
			}
			record.value.Upload, record.value.Download = record.info.UploadTotal.Load(), record.info.DownloadTotal.Load()
			// Registry removal does not prove the last I/O or resource close
			// has joined. Keep only bounded accounting until real cleanup.
			if receipt.Cleanup == "complete" {
				record.info = nil
			}
		}
		if !add(*record) {
			receipt.ConnectionSnapshot.HistoryOmitted++
		}
	}
	e.pruneDNSFacts()
	for {
		e.writeConnections(receipt, records)
		encoded, err := json.Marshal(receipt)
		if err == nil && len(encoded) <= MaxOutputBytes || len(records) == 0 {
			return
		}
		last := records[len(records)-1].value
		if last.State == "active" {
			receipt.ConnectionSnapshot.ActiveOmitted++
		} else {
			receipt.ConnectionSnapshot.HistoryOmitted++
		}
		records = records[:len(records)-1]
	}
}

func (e *runEngine) writeConnections(receipt *Receipt, records []observation) {
	receipt.ConnectionSnapshot.DNSLinksOmitted = 0
	if e.dns != nil {
		references := []DNSQueryObservation{}
		for _, record := range records {
			if record.dns != nil {
				references = append(references, *record.dns)
			}
		}
		receipt.DNS = e.dns.observationForConnections(references)
	}
	receipt.Connections = make([]ConnectionObservation, 0, len(records))
	for _, record := range records {
		value := record.value
		if value.Attribution != nil {
			attribution := *value.Attribution
			attribution.DNSSequence = 0
			attribution.DNSLinkOmitted = false
			if receipt.DNS != nil && record.dns != nil {
				for _, query := range receipt.DNS.Queries {
					if query.Sequence != record.dns.Sequence || query.QuestionDigest != attribution.DomainDigest || query.Outcome != "response" || query.Rcode != 0 {
						continue
					}
					for _, address := range query.AnswerAddresses {
						if address == value.TargetAddress {
							attribution.DNSSequence = query.Sequence
						}
					}
				}
			}
			if record.dns != nil && attribution.DNSSequence == 0 {
				attribution.DNSLinkOmitted = true
				receipt.ConnectionSnapshot.DNSLinksOmitted++
			}
			value.Attribution = &attribution
		}
		receipt.Connections = append(receipt.Connections, value)
	}
}
