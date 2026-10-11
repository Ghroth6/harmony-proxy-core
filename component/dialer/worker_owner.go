package dialer

import (
	"context"
	"io"
	"net"
)

// WorkerOwner is optional per-operation ownership, separate from the physical
// path epoch. Admission occurs before launching a racer or asynchronous Close;
// completion follows the actual worker and all of its late socket cleanup.
type WorkerOwner interface {
	AcquireWorker(context.Context) (context.Context, func(), error)
	RetainWorkerCloseFailure(io.Closer, error)
}

func closeWorkerConn(ctx context.Context, conn net.Conn) {
	if err := conn.Close(); err != nil {
		if owner, ok := ctx.Value(workerOwnerKey{}).(WorkerOwner); ok {
			owner.RetainWorkerCloseFailure(conn, err)
		}
	}
}

type workerOwnerKey struct{}

func WithWorkerOwner(ctx context.Context, owner WorkerOwner) context.Context {
	return context.WithValue(ctx, workerOwnerKey{}, owner)
}

func acquireWorker(ctx context.Context) (context.Context, func(), error) {
	if owner, ok := ctx.Value(workerOwnerKey{}).(WorkerOwner); ok {
		return owner.AcquireWorker(ctx)
	}
	return ctx, func() {}, nil
}
