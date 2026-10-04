package resource

import (
	"context"
	"github.com/metacubex/mihomo/component/forwarding"
)

type commitGuardKey struct{}

// WithCommitGuard binds result publication to an owner's lifetime. A guard must
// check that lifetime and execute action as one short critical section. It must
// not hold that section while waiting for network I/O, parsers or retired work.
// When a guard is present it decides validity, independently of a request's
// timeout (a completed timeout may itself be a result that needs publication).
func WithCommitGuard(ctx context.Context, guard func(func() error) error) context.Context {
	if parent, ok := ctx.Value(commitGuardKey{}).(func(func() error) error); ok {
		child := guard
		guard = func(action func() error) error {
			return parent(func() error { return child(action) })
		}
	}
	return context.WithValue(ctx, commitGuardKey{}, guard)
}

// Commit publishes a short result while its owner is current. Unguarded callers
// retain ordinary context cancellation semantics. Callers that also need to
// reject a request timeout must check ctx.Err before committing.
func Commit(ctx context.Context, action func() error) error {
	commit := func() error { return forwarding.CommitManagementNetwork(ctx, action) }
	if guard, ok := ctx.Value(commitGuardKey{}).(func(func() error) error); ok {
		return guard(commit)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return commit()
}
