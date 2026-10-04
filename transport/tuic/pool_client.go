package tuic

import (
	"context"
	"errors"
	list "github.com/bahlo/generic-list-go"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tuic/types"
	"net"
	"sync"
	"time"
)

type PoolClient struct {
	newClientOptionV4      *ClientOptionV4
	newClientOptionV5      *ClientOptionV5
	dialFn                 DialFunc
	mu                     sync.Mutex
	tcpClients, udpClients list.List[Client]
	ctx                    context.Context
	cancel                 context.CancelFunc
	closed                 bool
	pending                sync.WaitGroup
	closeOnce              sync.Once
	closeErr               error
}

func (t *PoolClient) begin(parent context.Context) (context.Context, func(), error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, nil, types.ClientClosed
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(t.ctx, cancel)
	t.pending.Add(1)
	return ctx, func() { stop(); cancel(); t.pending.Done() }, nil
}

func (t *PoolClient) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	ctx, finish, err := t.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	client, err := t.getClient(false, false)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		client, err = t.getClient(false, true)
		if err == nil {
			conn, err = client.DialContext(ctx, metadata)
		}
	}
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, errors.Join(types.ClientClosed, conn.Close())
	}
	return N.NewRefConn(conn, t), nil
}

func (t *PoolClient) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	ctx, finish, err := t.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	client, err := t.getClient(true, false)
	if err != nil {
		return nil, err
	}
	pc, err := client.ListenPacket(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		client, err = t.getClient(true, true)
		if err == nil {
			pc, err = client.ListenPacket(ctx, metadata)
		}
	}
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, errors.Join(types.ClientClosed, pc.Close())
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *PoolClient) getClient(udp, forceNew bool) (Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, types.ClientClosed
	}
	clients := &t.tcpClients
	if udp {
		clients = &t.udpClients
	}
	var best Client
	if !forceNew {
		for it := clients.Front(); it != nil; it = it.Next() {
			if best == nil || it.Value.OpenStreams() < best.OpenStreams() {
				best = it.Value
			}
		}
	}
	for it := clients.Front(); it != nil; {
		next := it.Next()
		client := it.Value
		if client != best && client.OpenStreams() == 0 && time.Since(client.LastVisited()) > 30*time.Minute {
			t.closeErr = errors.Join(t.closeErr, client.Close())
			clients.Remove(it)
		}
		it = next
	}
	if best == nil {
		if t.newClientOptionV4 != nil {
			best = NewClientV4(t.newClientOptionV4, udp, t.dialFn)
		} else {
			best = NewClientV5(t.newClientOptionV5, udp, t.dialFn)
		}
		clients.PushFront(best)
	}
	best.SetLastVisited(time.Now())
	return best, nil
}

// Close rejects new streams, cancels pending construction, and closes all
// established clients. It waits for construction and protocol workers to end.
func (t *PoolClient) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.cancel()
		var clients []Client
		for _, group := range []*list.List[Client]{&t.tcpClients, &t.udpClients} {
			for it := group.Front(); it != nil; it = it.Next() {
				clients = append(clients, it.Value)
			}
		}
		t.mu.Unlock()
		var wg sync.WaitGroup
		var errMu sync.Mutex
		for _, client := range clients {
			wg.Add(1)
			go func(client Client) {
				defer wg.Done()
				err := client.Close()
				errMu.Lock()
				t.closeErr = errors.Join(t.closeErr, err)
				errMu.Unlock()
			}(client)
		}
		wg.Wait()
		t.pending.Wait()
	})
	return t.closeErr
}

func NewPoolClientV4(clientOption *ClientOptionV4, dialFn DialFunc) *PoolClient {
	ctx, cancel := context.WithCancel(context.Background())
	p := &PoolClient{dialFn: dialFn, ctx: ctx, cancel: cancel}
	newClientOption := *clientOption
	p.newClientOptionV4 = &newClientOption
	return p
}

func NewPoolClientV5(clientOption *ClientOptionV5, dialFn DialFunc) *PoolClient {
	ctx, cancel := context.WithCancel(context.Background())
	p := &PoolClient{dialFn: dialFn, ctx: ctx, cancel: cancel}
	newClientOption := *clientOption
	p.newClientOptionV5 = &newClientOption
	return p
}
