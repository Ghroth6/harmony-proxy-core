package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/forwarding"
	D "github.com/miekg/dns"
)

var (
	ErrResolverNotActive = errors.New("DNS owner not active")
	ErrResolverRetired   = errors.New("DNS owner retired")
)

// ResolverOwner belongs to one candidate. Preparing it opens no network;
// activation freezes its run values and management path. Cancellation cannot
// discard a live worker, a late socket result, or an uncertain Close.
type ResolverOwner struct {
	mu           sync.Mutex
	changed      chan struct{}
	active       bool
	retired      bool
	root         context.Context
	cancel       context.CancelFunc
	pending      int
	conns        map[*resolverConn]struct{}
	packets      map[*resolverPacketConn]struct{}
	closers      map[io.Closer]*resolverCloser
	closeErrs    []error
	failedCloses map[io.Closer]error
}

func NewResolverOwner() *ResolverOwner {
	return &ResolverOwner{changed: make(chan struct{}), conns: map[*resolverConn]struct{}{}, packets: map[*resolverPacketConn]struct{}{}, closers: map[io.Closer]*resolverCloser{}}
}

func (o *ResolverOwner) notifyLocked() { close(o.changed); o.changed = make(chan struct{}) }

func (o *ResolverOwner) Activate(parent context.Context) error {
	if parent == nil {
		return ErrResolverNotActive
	}
	o.mu.Lock()
	if o.retired || o.active {
		o.mu.Unlock()
		return ErrResolverRetired
	}
	if err := parent.Err(); err != nil {
		o.mu.Unlock()
		return err
	}
	o.root, o.cancel = context.WithCancel(forwarding.SharedManagementNetworkContext(parent))
	o.active = true
	root := o.root
	o.pending++ // admitted before launch; explicit Cancel also wakes the watcher.
	go func() {
		defer o.finishIO()
		select {
		case <-parent.Done():
		case <-root.Done():
		}
		o.Cancel()
	}()
	o.mu.Unlock()
	return nil
}

func (o *ResolverOwner) Cancel() {
	o.mu.Lock()
	if o.retired {
		o.mu.Unlock()
		return
	}
	o.retired = true
	if o.cancel != nil {
		o.cancel()
	}
	conns := make([]*resolverConn, 0, len(o.conns))
	for conn := range o.conns {
		conns = append(conns, conn)
	}
	packets := make([]*resolverPacketConn, 0, len(o.packets))
	for conn := range o.packets {
		packets = append(packets, conn)
	}
	closers := make([]*resolverCloser, 0, len(o.closers))
	for _, closer := range o.closers {
		o.pending++
		closers = append(closers, closer)
	}
	o.notifyLocked()
	o.mu.Unlock()
	for _, conn := range conns {
		go conn.Close() // the socket's reservation remains until real Close returns.
	}
	for _, conn := range packets {
		go conn.Close()
	}
	for _, closer := range closers {
		go closer.close() // includes transport pool and protocol worker retirement.
	}
}

func (o *ResolverOwner) Wait(ctx context.Context) error {
	for {
		o.mu.Lock()
		if !o.retired {
			o.mu.Unlock()
			return ErrResolverNotActive
		}
		if o.pending == 0 {
			err := errors.Join(o.closeErrs...)
			o.mu.Unlock()
			return err
		}
		changed := o.changed
		o.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (o *ResolverOwner) Close(ctx context.Context) error { o.Cancel(); return o.Wait(ctx) }

type resolverOwnerKey struct{}

type resolverValues struct {
	context.Context
	root context.Context
}

func (c resolverValues) Value(key any) any {
	if value := c.root.Value(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}

func (o *ResolverOwner) begin(parent context.Context) (context.Context, func(), error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	o.mu.Lock()
	if o.retired {
		o.mu.Unlock()
		return nil, nil, ErrResolverRetired
	}
	if !o.active {
		o.mu.Unlock()
		return nil, nil, ErrResolverNotActive
	}
	o.pending++
	root := o.root
	o.mu.Unlock()
	ctx, cancel := context.WithCancel(resolverValues{Context: parent, root: root})
	ctx = context.WithValue(ctx, resolverOwnerKey{}, o)
	ctx = dialer.WithWorkerOwner(ctx, o)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(root, func() { defer close(callbackDone); cancel() })
	if root.Err() != nil {
		cancel()
	}
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			cancel()
			if !stop() {
				<-callbackDone
			}
			o.mu.Lock()
			o.pending--
			o.notifyLocked()
			o.mu.Unlock()
		})
	}, nil
}

func (o *ResolverOwner) AcquireWorker(ctx context.Context) (context.Context, func(), error) {
	return o.begin(ctx)
}

// A worker reports a real Close failure before releasing its reservation. Keep
// the actual socket reference: the result is unknown, never successful cleanup.
func (o *ResolverOwner) RetainWorkerCloseFailure(closer io.Closer, err error) {
	o.mu.Lock()
	if o.failedCloses == nil {
		o.failedCloses = make(map[io.Closer]error)
	}
	if _, exists := o.failedCloses[closer]; !exists {
		o.failedCloses[closer] = err
		o.closeErrs = append(o.closeErrs, err)
	}
	o.notifyLocked()
	o.mu.Unlock()
}

func resolverOwner(ctx context.Context) *ResolverOwner {
	owner, _ := ctx.Value(resolverOwnerKey{}).(*ResolverOwner)
	return owner
}

func (o *ResolverOwner) commit(action func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired || !o.active {
		return ErrResolverRetired
	}
	return action()
}

func (r *Resolver) dnsOwner() *ResolverOwner { return r.owner }

func (r *Resolver) launch(ctx context.Context, work func(context.Context)) bool {
	var owner *ResolverOwner
	if r != nil {
		owner = r.owner
	}
	return owner.launch(ctx, work)
}

func (o *ResolverOwner) launch(ctx context.Context, work func(context.Context)) bool {
	if o == nil {
		go work(ctx)
		return true
	}
	ctx, finish, err := o.begin(ctx)
	if err != nil {
		return false
	}
	go func() { defer finish(); work(ctx) }()
	return true
}

// A reservation is taken before DoChan can schedule the shared call. The
// result drain remains owned even if every individual waiter cancels first.
func (r *Resolver) exchangeGroup(ctx context.Context, key string, work func(context.Context) (*D.Msg, error)) <-chan singleflight.Result[*D.Msg] {
	if r.owner == nil {
		return r.group.DoChan(key, func() (*D.Msg, error) { return work(ctx) })
	}
	ctx, finish, err := r.owner.begin(ctx)
	result := make(chan singleflight.Result[*D.Msg], 1)
	if err != nil {
		result <- singleflight.Result[*D.Msg]{Val: &D.Msg{MsgHdr: D.MsgHdr{Opcode: 3}}, Err: err}
		return result
	}
	shared := r.group.DoChan(key, func() (*D.Msg, error) { return work(ctx) })
	go func() { defer finish(); result <- <-shared }()
	return result
}

// A successful dial can return after cancellation. Its caller already holds a
// worker reservation, so the late socket is registered and actually closed
// before that reservation can finish.
func (o *ResolverOwner) ownConn(conn net.Conn) (*resolverConn, error) {
	owned := &resolverConn{Conn: conn, owner: o}
	o.mu.Lock()
	o.pending++
	o.conns[owned] = struct{}{}
	retired := o.retired
	o.mu.Unlock()
	if retired {
		return owned, errors.Join(ErrResolverRetired, owned.Close())
	}
	return owned, nil
}

type resolverConn struct {
	net.Conn
	owner *ResolverOwner
	once  sync.Once
	err   error
}

// Socket Close can return before an in-progress transport Read resumes. Track
// each actual I/O call separately so Wait also joins its return boundary.
func (o *ResolverOwner) beginIO() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired {
		return ErrResolverRetired
	}
	o.pending++
	return nil
}

func (o *ResolverOwner) finishIO() {
	o.mu.Lock()
	o.pending--
	o.notifyLocked()
	o.mu.Unlock()
}

func (c *resolverConn) Read(p []byte) (int, error) {
	if err := c.owner.beginIO(); err != nil {
		return 0, err
	}
	defer c.owner.finishIO()
	return c.Conn.Read(p)
}

func (c *resolverConn) Write(p []byte) (int, error) {
	if err := c.owner.beginIO(); err != nil {
		return 0, err
	}
	defer c.owner.finishIO()
	return c.Conn.Write(p)
}

func (c *resolverConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		c.owner.pending--
		if c.err == nil {
			delete(c.owner.conns, c)
		} else {
			c.owner.closeErrs = append(c.owner.closeErrs, c.err)
		}
		c.owner.notifyLocked()
		c.owner.mu.Unlock()
	})
	return c.err
}

type resolverCloser struct {
	owner  *ResolverOwner
	closer io.Closer
	once   sync.Once
}

func (o *ResolverOwner) ownCloser(closer io.Closer) {
	if o == nil {
		return
	}
	o.mu.Lock()
	if _, exists := o.closers[closer]; exists {
		o.mu.Unlock()
		return
	}
	owned := &resolverCloser{owner: o, closer: closer}
	o.closers[closer] = owned
	retired := o.retired
	if retired {
		o.pending++
	}
	o.mu.Unlock()
	if retired {
		owned.close() // late transport admission cannot escape retirement.
	}
}

func (c *resolverCloser) close() {
	c.once.Do(func() {
		err := c.closer.Close()
		c.owner.mu.Lock()
		if err != nil {
			c.owner.closeErrs = append(c.owner.closeErrs, err)
		}
		c.owner.pending--
		c.owner.notifyLocked()
		c.owner.mu.Unlock()
	})
}

func (o *ResolverOwner) ownClient(client dnsClient) {
	if o == nil {
		return
	}
	for {
		wrapper, ok := client.(interface{ Unwrap() dnsClient })
		if !ok {
			break
		}
		client = wrapper.Unwrap()
	}
	if closer, ok := client.(io.Closer); ok {
		o.ownCloser(closer)
	}
}

func (o *ResolverOwner) ownPacketConn(conn net.PacketConn) (*resolverPacketConn, error) {
	owned := &resolverPacketConn{PacketConn: conn, owner: o}
	o.mu.Lock()
	o.pending++
	o.packets[owned] = struct{}{}
	retired := o.retired
	o.mu.Unlock()
	if retired {
		return owned, errors.Join(ErrResolverRetired, owned.Close())
	}
	return owned, nil
}

type resolverPacketConn struct {
	net.PacketConn
	owner *ResolverOwner
	once  sync.Once
	err   error
}

func (c *resolverPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if err := c.owner.beginIO(); err != nil {
		return 0, nil, err
	}
	defer c.owner.finishIO()
	return c.PacketConn.ReadFrom(p)
}

func (c *resolverPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.owner.beginIO(); err != nil {
		return 0, err
	}
	defer c.owner.finishIO()
	return c.PacketConn.WriteTo(p, addr)
}

func (c *resolverPacketConn) Close() error {
	c.once.Do(func() {
		c.err = c.PacketConn.Close()
		c.owner.mu.Lock()
		c.owner.pending--
		if c.err == nil {
			delete(c.owner.packets, c)
		} else {
			c.owner.closeErrs = append(c.owner.closeErrs, c.err)
		}
		c.owner.notifyLocked()
		c.owner.mu.Unlock()
	})
	return c.err
}
