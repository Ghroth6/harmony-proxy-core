package resource

import "context"

type observerKey struct{}

// WithObserver counts runtime acquisition attempts without changing vehicles,
// subscription headers, proxy selection or upstream cache behavior.
func WithObserver(ctx context.Context, observer func()) context.Context {
	return context.WithValue(ctx, observerKey{}, observer)
}
func observer(ctx context.Context) func() {
	fn, _ := ctx.Value(observerKey{}).(func())
	return fn
}
