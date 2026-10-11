package memconservative

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"google.golang.org/protobuf/proto"
)

type memConservativeLoader struct {
	geoipcache   GeoIPCache
	geositecache GeoSiteCache
}

func (m *memConservativeLoader) LoadIPByPath(filename, country string) ([]*router.CIDR, error) {
	defer runtime.GC()
	geoip, err := m.geoipcache.Unmarshal(filename, country)
	if err != nil {
		return nil, fmt.Errorf("failed to decode geodata file: %s, base error: %s", filename, err.Error())
	}
	return geoip.Cidr, nil
}

func (m *memConservativeLoader) LoadIPByBytes(geoipBytes []byte, country string) ([]*router.CIDR, error) {
	selected, err := emitBytes(bytes.NewReader(geoipBytes), country)
	if err == nil {
		var entry router.GeoIP
		if err = proto.Unmarshal(selected, &entry); err != nil {
			return nil, err
		}
		return entry.Cidr, nil
	}
	if err == errCodeNotFound {
		return nil, err
	}
	// Match the path loader's protobuf fallback while keeping bytes scoped and
	// avoiding filesystem/global paths or raw resource logging.
	var list router.GeoIPList
	if err = proto.Unmarshal(geoipBytes, &list); err != nil {
		return nil, err
	}
	for _, entry := range list.Entry {
		if strings.EqualFold(entry.CountryCode, country) {
			return entry.Cidr, nil
		}
	}
	return nil, errCodeNotFound
}

func (m *memConservativeLoader) LoadSiteByPath(filename, list string) ([]*router.Domain, error) {
	defer runtime.GC()
	geosite, err := m.geositecache.Unmarshal(filename, list)
	if err != nil {
		return nil, fmt.Errorf("failed to decode geodata file: %s, base error: %s", filename, err.Error())
	}
	return geosite.Domain, nil
}

func (m *memConservativeLoader) LoadSiteByBytes(geositeBytes []byte, list string) ([]*router.Domain, error) {
	selected, err := emitBytes(bytes.NewReader(geositeBytes), list)
	if err == nil {
		var entry router.GeoSite
		if err = proto.Unmarshal(selected, &entry); err != nil {
			return nil, err
		}
		return entry.Domain, nil
	}
	if err == errCodeNotFound {
		return nil, err
	}
	var data router.GeoSiteList
	if err = proto.Unmarshal(geositeBytes, &data); err != nil {
		return nil, err
	}
	for _, entry := range data.Entry {
		if strings.EqualFold(entry.CountryCode, list) {
			return entry.Domain, nil
		}
	}
	return nil, errCodeNotFound
}

func newMemConservativeLoader() geodata.LoaderImplementation {
	return &memConservativeLoader{make(map[string]*router.GeoIP), make(map[string]*router.GeoSite)}
}

func init() {
	geodata.RegisterGeoDataLoaderImplementationCreator("memconservative", newMemConservativeLoader)
}
