package http

import (
	"context"
	"errors"
	"io"
	"net"
	URL "net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"

	"github.com/metacubex/http"
)

var (
	ua string
)

func UA() string {
	return ua
}

func SetUA(UA string) {
	ua = UA
}

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader, options ...Option) (*http.Response, error) {
	ctx, finish, err := forwarding.AcquireManagementNetwork(ctx)
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			finish()
		}
	}()
	opt := option{}
	for _, o := range options {
		o(&opt)
	}
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	if err != nil {
		return nil, err
	}

	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UA())
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(opt.caOption)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		// from http.DefaultTransport
		DisableKeepAlives:     runtime.GOOS == "android",
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(_ context.Context, network, address string) (conn net.Conn, err error) {
			// A transport can detach both cancellation and the lifetime of a dial
			// from Do. Retain the original attempt until even late dials finish.
			dialCtx, finishDial, err := forwarding.AcquireManagementNetwork(ctx)
			if err != nil {
				return nil, err
			}
			defer finishDial()
			defer func() {
				if err == nil && conn != nil {
					conn, err = forwarding.OwnNetworkConn(ctx, conn)
				}
			}()
			if opt.dialer != nil {
				return opt.dialer.DialContext(ctx, network, address)
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// Transport may detach request cancellation from its dialing context.
			// This transport serves one request, so give the internal root request
			// the original caller context instead of the pooled-dial context.
			conn, err = inner.HandleTcpContext(ctx, inner.GetTunnel(), address, opt.specialProxy)
			if err == nil {
				return conn, nil
			}
			// Bootstrap without an initialized tunnel historically uses the normal
			// dialer. A selected proxy or a cancelled/rejected request must never
			// silently change its routing policy to DIRECT.
			if opt.specialProxy != "" || !errors.Is(err, inner.ErrTunnelUninitialized) {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return dialer.DialContext(dialCtx, network, address)
		},
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{Transport: transport}
	response, err := client.Do(req)
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			// Cancellation closes the internal pipe as well as the HTTP request.
			// Either transport observation may win; report the caller's cause,
			// not a racing EOF/closed-pipe error produced by that cancellation.
			var requestErr *URL.Error
			if errors.As(err, &requestErr) {
				copy := *requestErr
				copy.Err = cause
				err = &copy
			} else {
				err = cause
			}
		}
	}
	if response != nil && err == nil {
		response.Body = &requestBody{ReadCloser: response.Body, finish: func() { transport.CloseIdleConnections(); finish() }}
		handedOff = true
	} else {
		transport.CloseIdleConnections()
	}
	return response, err
}

type requestBody struct {
	io.ReadCloser
	once   sync.Once
	finish func()
	err    error
}

func (b *requestBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close(); b.finish() })
	return b.err
}

type Option func(opt *option)

type option struct {
	specialProxy string
	dialer       C.Dialer
	caOption     ca.Option
}

func WithSpecialProxy(name string) Option {
	return func(opt *option) {
		opt.specialProxy = name
	}
}

func WithDialer(dialer C.Dialer) Option {
	return func(opt *option) {
		opt.dialer = dialer
	}
}

func WithCAOption(caOption ca.Option) Option {
	return func(opt *option) {
		opt.caOption = caOption
	}
}
