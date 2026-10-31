package geodata

import (
	"errors"
	"net/netip"

	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/mmdb"
	"google.golang.org/protobuf/proto"
)

// VerifyPrepared checks resource loading before a plan may mark it ready.
// MMDB follows upstream open-time validation, with record decoding at lookup.
// Construction and matching below retain instance-scoped bytes.
func VerifyPrepared(kind string, data []byte) error {
	switch kind {
	case "mmdb":
		r, err := mmdb.NewPreparedIP(data)
		if err != nil {
			return err
		}
		return r.Close()
	case "asn":
		r, err := mmdb.NewPreparedASN(data)
		if err != nil {
			return err
		}
		return r.Close()
	case "geoip":
		var list router.GeoIPList
		return proto.Unmarshal(data, &list)
	case "geosite":
		var list router.GeoSiteList
		return proto.Unmarshal(data, &list)
	default:
		return errors.New("unsupported prepared geodata")
	}
}

// Prepared freezes the resource instance and its matcher caches. Global
// country caches and process-wide MMDB readers cannot alias another manifest.
type Prepared struct {
	mu              sync.Mutex
	closed          bool
	loader          Loader
	siteMatcher     string
	data            map[string][]byte
	sites           map[string]router.DomainMatcher
	ips             map[string]router.IPMatcher
	mmdb            *mmdb.IPReader
	asn             *mmdb.ASNReader
	retiredCloseErr error
}

func NewPrepared(data map[string][]byte, loaderName, siteMatcher string) (*Prepared, error) {
	if loaderName == "memc" {
		loaderName = "memconservative"
	}
	loader, err := GetGeoDataLoader(loaderName)
	if err != nil {
		return nil, errors.New("unsupported prepared geodata loader")
	}
	p := &Prepared{loader: loader, siteMatcher: siteMatcher, data: data, sites: map[string]router.DomainMatcher{}, ips: map[string]router.IPMatcher{}}
	for kind, value := range data {
		if err = VerifyPrepared(kind, value); err != nil {
			_ = p.Close()
			return nil, err
		}
		switch kind {
		case "mmdb":
			p.mmdb, err = mmdb.NewPreparedIP(value)
		case "asn":
			p.asn, err = mmdb.NewPreparedASN(value)
		}
		if err != nil {
			_ = p.Close()
			return nil, err
		}
	}
	return p, nil
}

func (p *Prepared) Site(country string) (router.DomainMatcher, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || country == "" {
		return nil, errors.New("prepared geodata unavailable")
	}
	if matcher := p.sites[country]; matcher != nil {
		return matcher, nil
	}
	key := strings.ToLower(country)
	not := strings.HasPrefix(key, "!")
	key = strings.TrimPrefix(key, "!")
	parts := strings.Split(key, "@")
	domains, err := p.loader.LoadSiteByBytes(p.data["geosite"], parts[0])
	if err != nil {
		return nil, errors.New("prepared geosite group missing")
	}
	attrs := parseAttrs(parts[1:])
	if !attrs.IsEmpty() {
		filtered := make([]*router.Domain, 0, len(domains))
		for _, domain := range domains {
			if attrs.Match(domain) {
				filtered = append(filtered, domain)
			}
		}
		domains = filtered
	}
	var matcher router.DomainMatcher
	if p.siteMatcher == "mph" || p.siteMatcher == "hybrid" {
		matcher, err = router.NewMphMatcherGroup(domains)
	} else {
		matcher, err = router.NewSuccinctMatcherGroup(domains)
	}
	if err != nil {
		return nil, errors.New("prepared geosite matcher invalid")
	}
	if not {
		matcher = router.NewNotDomainMatcherGroup(matcher)
	}
	p.sites[country] = matcher
	return matcher, nil
}

func (p *Prepared) IP(country string) (router.IPMatcher, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || country == "" {
		return nil, errors.New("prepared geodata unavailable")
	}
	if matcher := p.ips[country]; matcher != nil {
		return matcher, nil
	}
	key := strings.ToLower(country)
	not := strings.HasPrefix(key, "!")
	key = strings.TrimPrefix(key, "!")
	cidrs, err := p.loader.LoadIPByBytes(p.data["geoip"], key)
	if err != nil {
		return nil, errors.New("prepared geoip group missing")
	}
	matcher, err := router.NewGeoIPMatcher(cidrs)
	if err != nil {
		return nil, errors.New("prepared geoip matcher invalid")
	}
	if not {
		matcher = router.NewNotIpMatcherGroup(matcher)
	}
	p.ips[country] = matcher
	return matcher, nil
}

func (p *Prepared) LookupCode(ip netip.Addr) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.mmdb == nil || !ip.IsValid() {
		return nil
	}
	return p.mmdb.LookupCode(ip.AsSlice())
}
func (p *Prepared) LookupASN(ip netip.Addr) (string, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.asn == nil || !ip.IsValid() {
		return "", ""
	}
	return p.asn.LookupASN(ip.AsSlice())
}
func (p *Prepared) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	errs := []error{p.retiredCloseErr}
	if p.mmdb != nil {
		errs = append(errs, p.mmdb.Close())
	}
	if p.asn != nil {
		errs = append(errs, p.asn.Close())
	}
	p.data = nil
	p.sites = nil
	p.ips = nil
	return errors.Join(errs...)
}

// Replace validates all already-used groups against the new complete database
// before switching readers. Rules keep their scoped getter and see the new data.
func (p *Prepared) Replace(kind string, value []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("prepared geodata unavailable")
	}
	data := make(map[string][]byte, len(p.data))
	for k, v := range p.data {
		data[k] = v
	}
	data[kind] = value
	next := &Prepared{loader: p.loader, siteMatcher: p.siteMatcher, data: data, sites: map[string]router.DomainMatcher{}, ips: map[string]router.IPMatcher{}}
	if err := VerifyPrepared(kind, value); err != nil {
		return err
	}
	var err error
	switch kind {
	case "mmdb":
		next.mmdb, err = mmdb.NewPreparedIP(value)
	case "asn":
		next.asn, err = mmdb.NewPreparedASN(value)
	case "geosite":
		for key := range p.sites {
			if _, err = next.Site(key); err != nil {
				return err
			}
		}
	case "geoip":
		for key := range p.ips {
			if _, err = next.IP(key); err != nil {
				return err
			}
		}
	}
	if err != nil {
		return err
	}
	switch kind {
	case "mmdb":
		if p.mmdb != nil {
			p.retiredCloseErr = errors.Join(p.retiredCloseErr, p.mmdb.Close())
		}
		p.mmdb = next.mmdb
	case "asn":
		if p.asn != nil {
			p.retiredCloseErr = errors.Join(p.retiredCloseErr, p.asn.Close())
		}
		p.asn = next.asn
	case "geosite":
		p.sites = next.sites
	case "geoip":
		p.ips = next.ips
	}
	p.data = data
	return nil
}
