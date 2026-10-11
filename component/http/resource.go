package http

import (
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/metacubex/http"
)

// WithResourceRequest selects the mobile resource acquisition policy. Each
// actual GET attempt, including redirects, belongs to the caller's same owner.
// Ordinary upstream HTTP clients keep their original redirect behavior.
func WithResourceRequest(attempt func(), retainCloseFailure func(io.Closer, error)) Option {
	return func(opt *option) {
		opt.resource = &resourceRequest{attempt: attempt, retainCloseFailure: retainCloseFailure}
	}
}

type resourceRequest struct {
	attempt            func()
	retainCloseFailure func(io.Closer, error)
	declaredHeaders    []string
	crossedOrigin      bool
	closeFailed        atomic.Bool
}

func (r *resourceRequest) redirect(req *http.Request, via []*http.Request) error {
	if len(via) > 5 {
		return errors.New("RESOURCE_HTTP_REDIRECT_LIMIT")
	}
	if req.URL.User != nil || req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return errors.New("RESOURCE_HTTP_REDIRECT_INVALID")
	}
	previous := via[len(via)-1].URL
	if previous.Scheme == "https" && req.URL.Scheme == "http" {
		return errors.New("RESOURCE_HTTP_REDIRECT_DOWNGRADE")
	}
	if resourceOrigin(previous) != resourceOrigin(req.URL) {
		r.crossedOrigin = true
	}
	if r.crossedOrigin {
		// Client.Do copies the original headers again for every later redirect.
		// Keep the taint, including a return to the initial origin, rather than
		// only clearing the first cross-origin request.
		for _, name := range r.declaredHeaders {
			req.Header.Del(name)
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Cookie2", "Referer"} {
			req.Header.Del(name)
		}
	}
	return req.Context().Err()
}

func resourceOrigin(value *url.URL) string {
	port := value.Port()
	if port == "" {
		if value.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(value.Scheme) + "://" + strings.ToLower(value.Hostname()) + ":" + port
}

type resourceTransport struct {
	base   http.RoundTripper
	policy *resourceRequest
}

func (r *resourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != "GET" || r.policy.closeFailed.Load() {
		return nil, errors.New("RESOURCE_HTTP_REQUEST_INVALID")
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if r.policy.attempt != nil {
		r.policy.attempt()
	}
	response, err := r.base.RoundTrip(req)
	if response != nil && response.Body != nil {
		response.Body = &resourceBody{ReadCloser: response.Body, policy: r.policy}
	}
	return response, err
}

type resourceBody struct {
	io.ReadCloser
	policy *resourceRequest
	once   sync.Once
	err    error
}

func (b *resourceBody) Close() error {
	b.once.Do(func() {
		b.err = b.ReadCloser.Close()
		if b.err != nil {
			b.policy.closeFailed.Store(true)
			if b.policy.retainCloseFailure != nil {
				b.policy.retainCloseFailure(b.ReadCloser, b.err)
			}
		}
	})
	return b.err
}
