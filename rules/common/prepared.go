package common

import (
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/geodata/router"
)

// These constructors preserve ordinary rule types/semantics while binding all
// resource access to a verified candidate. They cannot initialize global data.
func NewPreparedGEOIP(country, adapter string, isSrc, noResolve bool, match func(netip.Addr) bool, matcher func() (router.IPMatcher, error)) *GEOIP {
	return &GEOIP{country: strings.ToLower(country), adapter: adapter, isSourceIP: isSrc, noResolveIP: noResolve, preparedMatch: match, preparedMatcher: matcher}
}
func NewPreparedGEOSITE(country, adapter string, matcher func() (router.DomainMatcher, error)) (*GEOSITE, error) {
	if _, err := matcher(); err != nil {
		return nil, err
	}
	return &GEOSITE{country: country, adapter: adapter, preparedMatcher: matcher}, nil
}
func NewPreparedIPASN(asn, adapter string, isSrc, noResolve bool, lookup func(netip.Addr) (string, string)) *ASN {
	return &ASN{asn: asn, adapter: adapter, isSourceIP: isSrc, noResolveIP: noResolve, preparedLookup: lookup}
}
