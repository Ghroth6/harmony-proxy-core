package provider

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/sync/errgroup"
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type extraOption struct {
	expectedStatus utils.IntRanges[uint16]
	filters        map[string]struct{}
}

type HealthCheck struct {
	ctx            context.Context
	ctxCancel      context.CancelFunc
	url            string
	extra          map[string]*extraOption
	mu             sync.Mutex
	proxies        []C.Proxy
	interval       time.Duration
	lazy           bool
	expectedStatus utils.IntRanges[uint16]
	lastTouch      atomic.TypedValue[time.Time]
	singleDo       *singledo.Single[struct{}]
	timeout        time.Duration
	started        bool
	closed         bool
	active         int
	done           chan struct{}
}

func (hc *HealthCheck) start() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if hc.closed {
		return context.Canceled
	}
	if hc.started || hc.interval == 0 {
		return nil
	}
	hc.started = true
	hc.active++
	go hc.process(hc.interval)
	return nil
}

func (hc *HealthCheck) finish() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.active--
	if hc.closed && hc.active == 0 {
		close(hc.done)
	}
}

func (hc *HealthCheck) process(interval time.Duration) {
	defer hc.finish()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	hc.check()
	for {
		select {
		case <-ticker.C:
			lastTouch := hc.lastTouch.Load()
			since := time.Since(lastTouch)
			if !hc.lazy || since < interval {
				hc.check()
			} else {
				log.Debugln("Skip once health check because we are lazy")
			}
		case <-hc.ctx.Done():
			return
		}
	}
}

func (hc *HealthCheck) setProxies(proxies []C.Proxy) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if !hc.closed {
		hc.proxies = append([]C.Proxy(nil), proxies...)
	}
}

func (hc *HealthCheck) registerHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	url = strings.TrimSpace(url)
	if len(url) == 0 || url == hc.url {
		log.Debugln("ignore invalid health check url: %s", url)
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()
	if hc.closed {
		return
	}

	// if the provider has not set up health checks, then modify it to be the same as the group's interval
	if hc.interval == 0 {
		hc.interval = time.Duration(interval) * time.Second
	}

	if hc.extra == nil {
		hc.extra = make(map[string]*extraOption)
	}

	// prioritize the use of previously registered configurations, especially those from provider
	if _, ok := hc.extra[url]; ok {
		// provider default health check does not set filter
		if url != hc.url && len(filter) != 0 {
			splitAndAddFiltersToExtra(filter, hc.extra[url])
		}

		log.Debugln("health check url: %s exists", url)
		return
	}

	option := &extraOption{filters: map[string]struct{}{}, expectedStatus: expectedStatus}
	splitAndAddFiltersToExtra(filter, option)
	hc.extra[url] = option
}

func splitAndAddFiltersToExtra(filter string, option *extraOption) {
	filter = strings.TrimSpace(filter)
	if len(filter) != 0 {
		for _, regex := range strings.Split(filter, "`") {
			regex = strings.TrimSpace(regex)
			if len(regex) != 0 {
				option.filters[regex] = struct{}{}
			}
		}
	}
}

func (hc *HealthCheck) auto() bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return !hc.closed && hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now())
}

func (hc *HealthCheck) checkAsync() {
	hc.mu.Lock()
	if hc.closed {
		hc.mu.Unlock()
		return
	}
	hc.active++
	hc.mu.Unlock()
	go func() {
		defer hc.finish()
		hc.check()
	}()
}

func (hc *HealthCheck) check() {
	hc.mu.Lock()
	if hc.closed || len(hc.proxies) == 0 {
		hc.mu.Unlock()
		return
	}
	hc.active++
	proxies := append([]C.Proxy(nil), hc.proxies...)
	extra := make(map[string]*extraOption, len(hc.extra))
	for url, option := range hc.extra {
		copyOption := &extraOption{expectedStatus: option.expectedStatus, filters: make(map[string]struct{}, len(option.filters))}
		for filter := range option.filters {
			copyOption.filters[filter] = struct{}{}
		}
		extra[url] = copyOption
	}
	hc.mu.Unlock()
	defer hc.finish()

	_, _, _ = hc.singleDo.Do(func() (struct{}, error) {
		id := utils.NewUUIDV4().String()
		log.Debugln("Start New Health Checking {%s}", id)
		b := new(errgroup.Group)
		b.SetLimit(10)

		// execute default health check
		option := &extraOption{filters: nil, expectedStatus: hc.expectedStatus}
		hc.execute(b, proxies, hc.url, id, option)

		// execute extra health check
		if len(extra) != 0 {
			for url, option := range extra {
				hc.execute(b, proxies, url, id, option)
			}
		}
		_ = b.Wait()
		log.Debugln("Finish A Health Checking {%s}", id)
		return struct{}{}, nil
	})
}

func (hc *HealthCheck) execute(b *errgroup.Group, proxies []C.Proxy, url, uid string, option *extraOption) {
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		log.Debugln("Health Check has been skipped due to testUrl is empty, {%s}", uid)
		return
	}

	var filterReg *regexp2.Regexp
	var expectedStatus utils.IntRanges[uint16]
	if option != nil {
		expectedStatus = option.expectedStatus
		if len(option.filters) != 0 {
			filters := make([]string, 0, len(option.filters))
			for filter := range option.filters {
				filters = append(filters, filter)
			}

			filterReg = regexp2.MustCompile(strings.Join(filters, "|"), regexp2.None)
		}
	}

	for _, proxy := range proxies {
		if hc.ctx.Err() != nil {
			return
		}
		// skip proxies that do not require health check
		if filterReg != nil {
			if match, _ := filterReg.MatchString(proxy.Name()); !match {
				continue
			}
		}

		p := proxy
		b.Go(func() error {
			ctx, cancel := context.WithTimeout(hc.ctx, hc.timeout)
			defer cancel()
			ctx = adapter.WithURLTestCommitGuard(ctx, hc.commit)
			if ctx.Err() != nil {
				return nil
			}
			log.Debugln("Health Checking, proxy: %s, url: %s, id: {%s}", p.Name(), url, uid)
			_, _ = p.URLTest(ctx, url, expectedStatus)
			log.Debugln("Health Checked, proxy: %s, url: %s, alive: %t, delay: %d ms uid: {%s}", p.Name(), url, p.AliveForTestUrl(url), p.LastDelayForTestUrl(url), uid)
			return nil
		})
	}
}

func (hc *HealthCheck) commit(action func()) bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if hc.closed {
		return false
	}
	action()
	return true
}

func (hc *HealthCheck) cancel() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if !hc.closed {
		hc.closed = true
		hc.ctxCancel()
		if hc.active == 0 {
			close(hc.done)
		}
	}
}

func (hc *HealthCheck) wait(ctx context.Context) error {
	select {
	case <-hc.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func NewHealthCheck(proxies []C.Proxy, url string, timeout uint, interval uint, lazy bool, expectedStatus utils.IntRanges[uint16]) *HealthCheck {
	if url == "" {
		expectedStatus = nil
		interval = 0
	}
	if timeout == 0 {
		timeout = 5000
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthCheck{
		ctx:            ctx,
		ctxCancel:      cancel,
		proxies:        proxies,
		url:            url,
		timeout:        time.Duration(timeout) * time.Millisecond,
		extra:          map[string]*extraOption{},
		interval:       time.Duration(interval) * time.Second,
		lazy:           lazy,
		expectedStatus: expectedStatus,
		singleDo:       singledo.NewSingle[struct{}](time.Second),
		done:           make(chan struct{}),
	}
}
