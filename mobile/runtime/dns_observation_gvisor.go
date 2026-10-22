//go:build with_gvisor

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strings"

	D "github.com/miekg/dns"
)

func observationDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizedDomain(value string) string { return strings.TrimSuffix(strings.ToLower(value), ".") }

type observedDNSService struct {
	book      *dnsBook
	transport string
}

// This observes the captured resolver service result, not whether a downstream
// write succeeded, an upstream query occurred, or a response came from cache.
func (s observedDNSService) ServeMsg(ctx context.Context, question *D.Msg) (*D.Msg, error) {
	result, err := s.book.service.ServeMsg(ctx, question)
	value := DNSQueryObservation{Transport: s.transport, Rcode: -1, Outcome: "error", FailureCode: "DNS_SERVICE_ERROR", AnswerAddresses: []string{}}
	name := ""
	if len(question.Question) != 0 {
		name = normalizedDomain(question.Question[0].Name)
		value.QuestionDigest, value.QueryType = observationDigest(name), question.Question[0].Qtype
	}
	if err == nil && result != nil {
		value.Outcome, value.Rcode, value.FailureCode = "response", result.Rcode, ""
		allFake := true
		for _, answer := range result.Answer {
			var address netip.Addr
			switch answer := answer.(type) {
			case *D.A:
				address, _ = netip.AddrFromSlice(answer.A)
				address = address.Unmap()
			case *D.AAAA:
				address, _ = netip.AddrFromSlice(answer.AAAA)
			}
			if !address.IsValid() {
				continue
			}
			if len(value.AnswerAddresses) == MaxDNSAnswers {
				value.AnswersTruncated = true
				continue
			}
			value.AnswerAddresses = append(value.AnswerAddresses, address.String())
			mapped, exists := "", false
			if s.book.mapper != nil && s.book.mapper.IsFakeIP(address) && s.book.mapper.IsExistFakeIP(address) {
				mapped, exists = s.book.mapper.FindHostByIP(address)
			}
			allFake = allFake && exists && normalizedDomain(mapped) == name
		}
		value.FakeIP = allFake && len(value.AnswerAddresses) != 0
	} else if errors.Is(err, context.Canceled) {
		value.Outcome, value.FailureCode = "cancelled", "DNS_CANCELLED"
	} else if errors.Is(err, context.DeadlineExceeded) {
		value.FailureCode = "DNS_TIMEOUT"
	}
	s.book.record(value)
	return result, err
}

func (b *dnsBook) record(value DNSQueryObservation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.observed.Sequence == MaxObservation {
		b.observed.Saturated = true
		if b.observed.Dropped < MaxObservation {
			b.observed.Dropped++
		}
		return
	}
	b.observed.Sequence++
	value.Sequence = b.observed.Sequence
	if len(b.observed.Queries) == MaxDNSObservations {
		b.observed.Queries = b.observed.Queries[1:]
		b.observed.Dropped++
	}
	b.observed.Queries = append(b.observed.Queries, value)
}

func (b *dnsBook) observation() *DNSObservation {
	b.mu.Lock()
	defer b.mu.Unlock()
	value := b.observed
	value.Queries = append([]DNSQueryObservation{}, value.Queries...)
	for index := range value.Queries {
		value.Queries[index].AnswerAddresses = append([]string{}, value.Queries[index].AnswerAddresses...)
	}
	return &value
}

// Preserve an exact, unique result at connection creation. Never recover a
// domain from an address or reconstruct an association after its window expired.
func (b *dnsBook) queryFor(domainDigest string, address netip.Addr) *DNSQueryObservation {
	b.mu.Lock()
	defer b.mu.Unlock()
	var matched *DNSQueryObservation
	for _, value := range b.observed.Queries {
		if value.QuestionDigest != domainDigest || value.Outcome != "response" || value.Rcode != D.RcodeSuccess {
			continue
		}
		for _, answer := range value.AnswerAddresses {
			if answer == address.String() {
				if matched != nil {
					return nil
				}
				copy := value
				copy.AnswerAddresses = append([]string{}, value.AnswerAddresses...)
				matched = &copy
				break
			}
		}
	}
	return matched
}

// Keep the same 16-result budget: confirmed links held by selected connections
// first, then the latest ring results. Sequence and Dropped remain the original
// completion/ring-eviction counters; restoring a linked value never resets them.
func (b *dnsBook) observationForConnections(references []DNSQueryObservation) *DNSObservation {
	value := b.observation()
	queries := make([]DNSQueryObservation, 0, MaxDNSObservations)
	seen := map[uint64]bool{}
	add := func(query DNSQueryObservation) {
		if len(queries) == MaxDNSObservations || seen[query.Sequence] || query.Sequence == 0 || query.Sequence > value.Sequence {
			return
		}
		seen[query.Sequence] = true
		query.AnswerAddresses = append([]string{}, query.AnswerAddresses...)
		queries = append(queries, query)
	}
	for _, query := range references {
		add(query)
	}
	for index := len(value.Queries) - 1; index >= 0; index-- {
		add(value.Queries[index])
	}
	sort.Slice(queries, func(i, j int) bool { return queries[i].Sequence < queries[j].Sequence })
	value.Queries = queries
	return value
}
