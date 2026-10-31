// Package observation carries the embedding application's diagnostic policy.
// Limits affect copied observations only, never proxy admission or DNS replies.
package observation

import (
	"errors"
	"sync/atomic"
)

type Limits struct {
	ReplyBytes, ReplyValues                             int
	Connections, DNSQueries, DNSAnswers, ResourceEvents int
}

var application atomic.Pointer[Limits]

// Configure is called once by the application library at initialization.
// Without an application policy the core retains no diagnostic history.
func Configure(value Limits) error {
	if value.ReplyBytes <= 0 || value.ReplyBytes > 1<<31-1 || value.ReplyValues <= 0 ||
		value.Connections < 0 || value.DNSQueries < 0 || value.DNSAnswers < 0 || value.ResourceEvents < 0 {
		return errors.New("invalid observation policy")
	}
	if old := application.Load(); old != nil {
		if *old == value {
			return nil
		}
		return errors.New("observation policy already configured")
	}
	if !application.CompareAndSwap(nil, &value) {
		return Configure(value)
	}
	return nil
}

func Current() Limits {
	if value := application.Load(); value != nil {
		return *value
	}
	return Limits{ReplyBytes: 1<<31 - 1, ReplyValues: 1<<31 - 1}
}
