package http

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/metacubex/http"
)

// WithResourceRequest tracks the mobile resource acquisition lifetime. Each
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
	closeFailed        atomic.Bool
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
