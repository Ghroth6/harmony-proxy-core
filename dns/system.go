package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/component/resolver"

	D "github.com/miekg/dns"
)

const (
	SystemDnsFlushTime   = 5 * time.Minute
	SystemDnsDeleteTimes = 12 // 12*5 = 60min
)

type systemDnsClient struct {
	disableTimes uint32
	dnsClient
}

type systemClient struct {
	mu                 sync.Mutex
	dnsClients         map[string]*systemDnsClient
	lastFlush          time.Time
	defaultNS          []dnsClient
	platformGeneration uint64
	platformClients    []dnsClient
}

var ErrNoSystemDNS = errors.New("platform network has no system DNS")

func (c *systemClient) getDnsClients() ([]dnsClient, error) {
	c.mu.Lock()
	if snapshot, enabled := platformnetwork.Current(); enabled {
		defer c.mu.Unlock()
		if c.platformGeneration != snapshot.Generation {
			nameservers := make([]NameServer, 0, len(snapshot.DNS))
			for _, endpoint := range snapshot.DNS {
				nameservers = append(nameservers, NameServer{Addr: endpoint, Net: "udp"})
			}
			c.platformClients = transform(nameservers, nil)
			c.platformGeneration = snapshot.Generation
		}
		if len(c.platformClients) == 0 {
			return nil, ErrNoSystemDNS
		}
		return c.platformClients, nil
	}
	c.mu.Unlock()
	return c.getNativeDnsClients()
}

func platformDNSActive() bool {
	_, enabled := platformnetwork.Generation()
	return enabled
}

func (c *systemClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	dnsClients, err := c.getDnsClients()
	if len(dnsClients) == 0 && len(c.defaultNS) > 0 && !platformDNSActive() {
		dnsClients = c.defaultNS
		err = nil
	}
	if err != nil {
		return
	}
	msg, _, err = batchExchange(ctx, dnsClients, m)
	return
}

// Address implements dnsClient
func (c *systemClient) Address() string {
	dnsClients, _ := c.getDnsClients()
	isDefault := ""
	if len(dnsClients) == 0 && len(c.defaultNS) > 0 && !platformDNSActive() {
		dnsClients = c.defaultNS
		isDefault = "[defaultNS]"
	}
	addrs := make([]string, 0, len(dnsClients))
	for _, c := range dnsClients {
		addrs = append(addrs, c.Address())
	}
	return fmt.Sprintf("system%s(%s)", isDefault, strings.Join(addrs, ","))
}

var _ dnsClient = (*systemClient)(nil)

func newSystemClient() *systemClient {
	return &systemClient{
		dnsClients: map[string]*systemDnsClient{},
	}
}

func init() {
	r := NewResolver(Config{})
	c := newSystemClient()
	c.defaultNS = transform([]NameServer{{Addr: "114.114.114.114:53"}, {Addr: "8.8.8.8:53"}}, nil)
	r.main = []dnsClient{c}
	resolver.SystemResolver = r
}
