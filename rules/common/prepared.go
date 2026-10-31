package common

import (
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/log"
)

// These constructors preserve ordinary rule types/semantics while binding all
// resource access to a verified candidate. They cannot initialize global data.
func NewPreparedGEOIP(country, adapter string, isSrc, noResolve bool, match func(netip.Addr) bool, matcher func() (router.IPMatcher, error)) *GEOIP {
	if matcher != nil {
		if value, err := matcher(); err == nil {
			log.Infoln("Finished initial GeoIP rule %s => %s, records: %d", strings.ToLower(country), adapter, value.Count())
		}
	}
	return &GEOIP{country: strings.ToLower(country), adapter: adapter, isSourceIP: isSrc, noResolveIP: noResolve, preparedMatch: match, preparedMatcher: matcher}
}
func NewPreparedGEOSITE(country, adapter string, matcher func() (router.DomainMatcher, error)) (*GEOSITE, error) {
	value, err := matcher()
	if err != nil {
		return nil, err
	}
	log.Infoln("Finished initial GeoSite rule %s => %s, records: %d", country, adapter, value.Count())
	return &GEOSITE{country: country, adapter: adapter, preparedMatcher: matcher}, nil
}
func NewPreparedIPASN(asn, adapter string, isSrc, noResolve bool, lookup func(netip.Addr) (string, string)) *ASN {
	return &ASN{asn: asn, adapter: adapter, isSourceIP: isSrc, noResolveIP: noResolve, preparedLookup: lookup}
}
