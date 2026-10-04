package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/http"
)

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

type providerForApi struct {
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	VehicleType      string            `json:"vehicleType"`
	Proxies          []C.Proxy         `json:"proxies"`
	TestUrl          string            `json:"testUrl"`
	ExpectedStatus   string            `json:"expectedStatus"`
	UpdatedAt        time.Time         `json:"updatedAt,omitempty"`
	SubscriptionInfo *SubscriptionInfo `json:"subscriptionInfo,omitempty"`
}

type baseProvider struct {
	mutex       sync.RWMutex
	name        string
	proxies     []C.Proxy
	healthCheck *HealthCheck
	version     uint32
	closed      bool
}

func (bp *baseProvider) Name() string {
	return bp.name
}

func (bp *baseProvider) Version() uint32 {
	bp.mutex.RLock()
	defer bp.mutex.RUnlock()
	return bp.version
}

func (bp *baseProvider) Initial() error {
	return bp.healthCheck.start()
}

func (bp *baseProvider) HealthCheck() {
	bp.healthCheck.check()
}

func (bp *baseProvider) Type() P.ProviderType {
	return P.Proxy
}

func (bp *baseProvider) Proxies() []C.Proxy {
	bp.mutex.RLock()
	defer bp.mutex.RUnlock()
	return bp.proxies
}

func (bp *baseProvider) Count() int {
	bp.mutex.RLock()
	defer bp.mutex.RUnlock()
	return len(bp.proxies)
}

func (bp *baseProvider) Touch() {
	bp.healthCheck.touch()
}

func (bp *baseProvider) HealthCheckURL() string {
	return bp.healthCheck.url
}

func (bp *baseProvider) RegisterHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	bp.healthCheck.registerHealthCheckTask(url, expectedStatus, filter, interval)
}

func (bp *baseProvider) Close() error {
	bp.Cancel()
	return bp.Wait(context.Background())
}

func (bp *baseProvider) Cancel() {
	bp.mutex.Lock()
	bp.closed = true
	bp.mutex.Unlock()
	bp.healthCheck.cancel()
}

func (bp *baseProvider) Wait(ctx context.Context) error {
	return bp.healthCheck.wait(ctx)
}

// ProxySetProvider for auto gc
type ProxySetProvider struct {
	*proxySetProvider
}

type proxySetProvider struct {
	baseProvider
	*resource.Fetcher[[]C.Proxy]
	subscriptionInfo *SubscriptionInfo
	initialMu        sync.Mutex
	initialized      bool
	retired          map[*retiredProxy]struct{} // guarded by baseProvider.mutex
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	pp.mutex.RLock()
	subscriptionInfo := pp.subscriptionInfo
	pp.mutex.RUnlock()
	return json.Marshal(providerForApi{
		Name:             pp.Name(),
		Type:             pp.Type().String(),
		VehicleType:      pp.VehicleType().String(),
		Proxies:          pp.Proxies(),
		TestUrl:          pp.healthCheck.url,
		ExpectedStatus:   pp.healthCheck.expectedStatus.String(),
		UpdatedAt:        pp.UpdatedAt(),
		SubscriptionInfo: subscriptionInfo,
	})
}

func (pp *proxySetProvider) Name() string {
	return pp.Fetcher.Name()
}

func (pp *proxySetProvider) Update() error {
	_, _, err := pp.Fetcher.Update()
	return errors.Join(err, pp.retirementError())
}

func (pp *proxySetProvider) SideUpdate(buf []byte) ([]C.Proxy, bool, error) {
	proxies, same, err := pp.Fetcher.SideUpdate(buf)
	return proxies, same, errors.Join(err, pp.retirementError())
}

func (pp *proxySetProvider) Initial() error {
	pp.initialMu.Lock()
	defer pp.initialMu.Unlock()
	if pp.initialized {
		return pp.Fetcher.Context().Err()
	}
	if err := pp.baseProvider.Initial(); err != nil {
		return err
	}
	_, err := pp.Fetcher.Initial()
	if err != nil {
		return err
	}
	return pp.Fetcher.Commit(func() error {
		if subscriptionInfo := cachefile.Cache().GetSubscriptionInfo(pp.Name()); subscriptionInfo != "" {
			pp.mutex.Lock()
			pp.subscriptionInfo = NewSubscriptionInfo(subscriptionInfo)
			pp.mutex.Unlock()
		}
		pp.initialized = true
		return nil
	})
}

func (pp *proxySetProvider) Close() error {
	pp.Cancel()
	return pp.Wait(context.Background())
}

func (pp *proxySetProvider) Cancel() {
	// Close the publication fence before baseProvider starts rejecting updates;
	// otherwise a committed fetch could silently lose ownership in setProxies.
	pp.Fetcher.Cancel()
	pp.baseProvider.Cancel()
	pp.forceRetiredProxies()
}

func (pp *proxySetProvider) Wait(ctx context.Context) error {
	return errors.Join(pp.baseProvider.Wait(ctx), pp.Fetcher.Wait(ctx), pp.waitRetiredProxies(ctx))
}

func NewProxySetProvider(name string, interval time.Duration, payload []map[string]any, parser resource.Parser[[]C.Proxy], vehicle P.Vehicle, hc *HealthCheck) (_ *ProxySetProvider, err error) {
	defer closeFailedHealthCheck(hc, &err)
	pd := &proxySetProvider{
		baseProvider: baseProvider{
			name:        name,
			proxies:     []C.Proxy{},
			healthCheck: hc,
		},
	}

	if len(payload) > 0 { // using as fallback proxies
		ps := ProxySchema{Proxies: payload}
		buf, err := yaml.Marshal(ps)
		if err != nil {
			return nil, err
		}
		proxies, err := parser(buf)
		if err != nil {
			return nil, err
		}
		pd.proxies = proxies
		// direct call setProxies on hc to avoid starting a health check process immediately, it should be done by Initial()
		hc.setProxies(proxies)
	}

	fetcher := resource.NewFetcher[[]C.Proxy](name, interval, vehicle, nil, parser, pd.setProxies,
		resource.WithDiscard(func(proxies []C.Proxy) error { return closeCandidateProxies(proxies, pd.Proxies()) }))
	pd.Fetcher = fetcher
	if httpVehicle, ok := vehicle.(*resource.HTTPVehicle); ok {
		httpVehicle.SetInRead(func(resp *http.Response) {
			if subscriptionInfo := resp.Header.Get("subscription-userinfo"); subscriptionInfo != "" {
				cachefile.Cache().SetSubscriptionInfo(name, subscriptionInfo)
				pd.mutex.Lock()
				pd.subscriptionInfo = NewSubscriptionInfo(subscriptionInfo)
				pd.mutex.Unlock()
			}
		})
	}

	wrapper := &ProxySetProvider{pd}
	runtime.SetFinalizer(wrapper, (*ProxySetProvider).Close)
	return wrapper, nil
}

func (pp *ProxySetProvider) Close() error {
	runtime.SetFinalizer(pp, nil)
	return pp.proxySetProvider.Close()
}

// InlineProvider for auto gc
type InlineProvider struct {
	*inlineProvider
}

type inlineProvider struct {
	baseProvider
	updateAt time.Time
}

func (ip *inlineProvider) MarshalJSON() ([]byte, error) {
	ip.mutex.RLock()
	updatedAt := ip.updateAt
	ip.mutex.RUnlock()
	return json.Marshal(providerForApi{
		Name:           ip.Name(),
		Type:           ip.Type().String(),
		VehicleType:    ip.VehicleType().String(),
		Proxies:        ip.Proxies(),
		TestUrl:        ip.healthCheck.url,
		ExpectedStatus: ip.healthCheck.expectedStatus.String(),
		UpdatedAt:      updatedAt,
	})
}

func (ip *inlineProvider) VehicleType() P.VehicleType {
	return P.Inline
}

func (ip *inlineProvider) Update() error {
	ip.mutex.Lock()
	defer ip.mutex.Unlock()
	if ip.closed {
		return context.Canceled
	}
	// make api update happy
	ip.updateAt = time.Now()
	return nil
}

func NewInlineProvider(name string, payload []map[string]any, parser resource.Parser[[]C.Proxy], hc *HealthCheck) (_ *InlineProvider, err error) {
	defer closeFailedHealthCheck(hc, &err)
	ps := ProxySchema{Proxies: payload}
	buf, err := yaml.Marshal(ps)
	if err != nil {
		return nil, err
	}
	proxies, err := parser(buf)
	if err != nil {
		return nil, err
	}
	// direct call setProxies on hc to avoid starting a health check process immediately, it should be done by Initial()
	hc.setProxies(proxies)

	ip := &inlineProvider{
		baseProvider: baseProvider{
			name:        name,
			proxies:     proxies,
			healthCheck: hc,
		},
		updateAt: time.Now(),
	}
	wrapper := &InlineProvider{ip}
	runtime.SetFinalizer(wrapper, (*InlineProvider).Close)
	return wrapper, nil
}

func (ip *InlineProvider) Close() error {
	runtime.SetFinalizer(ip, nil)
	return ip.baseProvider.Close()
}

// CompatibleProvider for auto gc
type CompatibleProvider struct {
	*compatibleProvider
}

type compatibleProvider struct {
	baseProvider
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(providerForApi{
		Name:           cp.Name(),
		Type:           cp.Type().String(),
		VehicleType:    cp.VehicleType().String(),
		Proxies:        cp.Proxies(),
		TestUrl:        cp.healthCheck.url,
		ExpectedStatus: cp.healthCheck.expectedStatus.String(),
	})
}

func (cp *compatibleProvider) Update() error {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	if cp.closed {
		return context.Canceled
	}
	return nil
}

func (cp *compatibleProvider) VehicleType() P.VehicleType {
	return P.Compatible
}

func NewCompatibleProvider(name string, proxies []C.Proxy, hc *HealthCheck) (_ *CompatibleProvider, err error) {
	defer closeFailedHealthCheck(hc, &err)
	if len(proxies) == 0 {
		return nil, errors.New("provider need one proxy at least")
	}

	pd := &compatibleProvider{
		baseProvider: baseProvider{
			name:        name,
			proxies:     proxies,
			healthCheck: hc,
		},
	}

	wrapper := &CompatibleProvider{pd}
	runtime.SetFinalizer(wrapper, (*CompatibleProvider).Close)
	return wrapper, nil
}

func (cp *CompatibleProvider) Close() error {
	runtime.SetFinalizer(cp, nil)
	return cp.compatibleProvider.Close()
}

func NewProxiesParser(pdName string, tunnel C.Tunnel, filter string, excludeFilter string, excludeType string, dialerProxy string, override overrideSchema, ageSecretKey string) (resource.Parser[[]C.Proxy], error) {
	var excludeTypeArray []string
	if excludeType != "" {
		excludeTypeArray = strings.Split(excludeType, "|")
	}

	var excludeFilterRegs []*regexp2.Regexp
	if excludeFilter != "" {
		for _, excludeFilter := range strings.Split(excludeFilter, "`") {
			excludeFilterReg, err := regexp2.Compile(excludeFilter, regexp2.None)
			if err != nil {
				return nil, fmt.Errorf("invalid excludeFilter regex: %w", err)
			}
			excludeFilterRegs = append(excludeFilterRegs, excludeFilterReg)
		}
	}

	var filterRegs []*regexp2.Regexp
	for _, filter := range strings.Split(filter, "`") {
		filterReg, err := regexp2.Compile(filter, regexp2.None)
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
		filterRegs = append(filterRegs, filterReg)
	}

	if ageSecretKey != "" {
		if err := age.VeritySecretKeys(ageSecretKey); err != nil {
			return nil, fmt.Errorf("invalid age-secret-key: %w", err)
		}
	}

	return func(buf []byte) (_ []C.Proxy, err error) {
		schema := &ProxySchema{}

		// decrypt config
		buf, err = age.DecryptBytes(buf, ageSecretKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt config error: %w", err)
		}

		if err := yaml.Unmarshal(buf, schema); err != nil {
			proxies, err1 := convert.ConvertsV2Ray(buf)
			if err1 != nil {
				return nil, fmt.Errorf("%w, %w", err, err1)
			}
			schema.Proxies = proxies
		}

		if schema.Proxies == nil {
			return nil, errors.New("file must have a `proxies` field")
		}

		proxies := []C.Proxy{}
		defer func() {
			if err != nil {
				err = errors.Join(err, closeCandidateProxies(proxies, nil))
			}
		}()
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range filterRegs {
		LOOP1:
			for idx, mapping := range schema.Proxies {
				if len(excludeTypeArray) > 0 {
					mType, ok := mapping["type"]
					if !ok {
						continue
					}
					pType, ok := mType.(string)
					if !ok {
						continue
					}
					for _, excludeType := range excludeTypeArray {
						if strings.EqualFold(pType, excludeType) {
							continue LOOP1
						}
					}
				}
				mName, ok := mapping["name"]
				if !ok {
					continue
				}
				name, ok := mName.(string)
				if !ok {
					continue
				}
				if len(excludeFilterRegs) > 0 {
					for _, excludeFilterReg := range excludeFilterRegs {
						if mat, _ := excludeFilterReg.MatchString(name); mat {
							continue LOOP1
						}
					}
				}
				if len(filter) > 0 {
					if mat, _ := filterReg.MatchString(name); !mat {
						continue
					}
				}
				if _, ok := proxiesSet[name]; ok {
					continue
				}

				if len(dialerProxy) > 0 {
					mapping["dialer-proxy"] = dialerProxy
				}

				err := override.Apply(mapping)
				if err != nil {
					return nil, fmt.Errorf("proxy %d override error: %w", idx, err)
				}

				proxy, err := adapter.ParseProxy(mapping, adapter.WithTunnelForAPI(tunnel), adapter.WithProviderName(pdName))
				if err != nil {
					return nil, fmt.Errorf("proxy %d error: %w", idx, err)
				}

				proxiesSet[name] = struct{}{}
				proxies = append(proxies, proxy)
			}
		}

		if len(proxies) == 0 {
			if len(filter) > 0 {
				return nil, errors.New("doesn't match any proxy, please check your filter")
			}
			return nil, errors.New("file doesn't have any proxy")
		}

		return proxies, nil
	}, nil
}

// Only these newly constructed results belong to this failed parse/update.
// Keep currently published adapters even when a custom parser reuses them.
func closeCandidateProxies(proxies, keep []C.Proxy) error {
	retained := make(map[C.ProxyAdapter]struct{}, len(keep))
	for _, proxy := range keep {
		if proxy != nil {
			retained[proxy.Adapter()] = struct{}{}
		}
	}
	var owned configresources.Set
	count := 0
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}
		if _, ok := retained[proxy.Adapter()]; ok {
			continue
		}
		owned.AddProxy(proxy)
		count++
	}
	if count == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return owned.Close(ctx)
}

// Constructors transfer their health checker only when returning a provider.
// Before Initial it has no workers, but cancellation also releases its context.
func closeFailedHealthCheck(hc *HealthCheck, err *error) {
	if *err != nil {
		hc.cancel()
		*err = errors.Join(*err, hc.wait(context.Background()))
	}
}
