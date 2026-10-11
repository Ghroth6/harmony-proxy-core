package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/bbolt"
)

var (
	ErrStateInactive = errors.New("POLICY_FAKEIP_STATE_INACTIVE")
	ErrStateFailed   = errors.New("POLICY_FAKEIP_STATE_FAILED")
	ErrStateClose    = errors.New("POLICY_FAKEIP_STATE_CLOSE_FAILED")
)

const MaxStateBytes = 64 << 20

// StateFiles is the trusted directory authority, not a YAML or RPC path.
// *os.Root implements it. The open-file boundary also permits real host-file
// fault tests without substituting a database or fake-IP algorithm.
type StateFiles interface {
	Mkdir(string, os.FileMode) error
	OpenFile(string, int, os.FileMode) (*os.File, error)
	Stat(string) (os.FileInfo, error)
}

// ScopedPersistence borrows the candidate's trusted root. Construction and pool
// registration do no I/O; Activate restores both pools before DNS admission.
// The candidate resource owner must pin that root until Wait succeeds.
type ScopedPersistence struct {
	mu            sync.Mutex
	files         StateFiles
	path          string
	pools         []*Pool
	db            *bbolt.DB
	file          *os.File
	active        bool
	retired       bool
	err           error
	closeErr      error
	closeDone     chan struct{}
	failure       func()
	failureCalled bool
}

func NewScopedPersistence(files StateFiles, inputDigest string) (*ScopedPersistence, error) {
	if files == nil || len(inputDigest) != 71 || !strings.HasPrefix(inputDigest, "sha256:") || strings.Trim(inputDigest[7:], "0123456789abcdef") != "" {
		return nil, ErrStateFailed
	}
	return &ScopedPersistence{files: files, path: "state/fakeip/" + inputDigest[7:] + ".db"}, nil
}

// SetFailureHandler is bound before activation. A sticky read/write failure
// cancels the actual policy owner; it never becomes a successful DNS answer.
func (s *ScopedPersistence) SetFailureHandler(handler func()) {
	s.mu.Lock()
	s.failure = handler
	s.mu.Unlock()
}

func (s *ScopedPersistence) register(pool *Pool) (store, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active || s.retired || s.db != nil {
		return nil, ErrStateInactive
	}
	for _, present := range s.pools {
		if present.IPNet().Addr().Is6() == pool.IPNet().Addr().Is6() {
			return nil, ErrStateFailed
		}
	}
	s.pools = append(s.pools, pool)
	return &scopedStore{owner: s, bucket: []byte(pool.IPNet().Masked().String())}, nil
}

func (s *ScopedPersistence) Activate() (err error) {
	s.mu.Lock()
	if s.active {
		err = s.err
		s.mu.Unlock()
		return
	}
	if s.retired || s.err != nil || s.db != nil {
		s.mu.Unlock()
		return ErrStateInactive
	}
	if info, statErr := s.files.Stat(s.path); statErr == nil {
		if !info.Mode().IsRegular() || info.Size() > MaxStateBytes {
			s.mu.Unlock()
			return s.fail(ErrStateFailed)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		s.mu.Unlock()
		return s.fail(ErrStateFailed)
	}
	for _, path := range []string{"state", "state/fakeip"} {
		if err = s.files.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			s.mu.Unlock()
			return s.fail(ErrStateFailed)
		}
	}
	// bbolt's internal open-error cleanup does not return its Close result.
	// Capture the real file so such an unknown close cannot lose its owner.
	s.db, err = bbolt.Open(s.path, 0o600, &bbolt.Options{Timeout: time.Second, MaxSize: MaxStateBytes, NoStatistics: true, OpenFile: func(path string, flag int, mode os.FileMode) (*os.File, error) {
		file, openErr := s.files.OpenFile(path, flag, mode)
		if file != nil {
			s.file = file
		}
		return file, openErr
	}})
	if err != nil {
		if s.file != nil {
			s.closeErr = ErrStateClose
		}
		s.mu.Unlock()
		return s.fail(ErrStateFailed)
	}
	pools := append([]*Pool(nil), s.pools...)
	s.mu.Unlock()
	// Pool operations take their pool mutex before the database mutex. Keep the
	// same order here; public lookups still reject until every pool is restored.
	for _, pool := range pools {
		pool.mux.Lock()
		err = pool.store.(*scopedStore).restore(pool)
		pool.mux.Unlock()
		if err != nil {
			return s.fail(err)
		}
	}
	s.mu.Lock()
	if s.retired || s.err != nil {
		err = ErrStateInactive
	} else {
		s.active = true
	}
	s.mu.Unlock()
	return
}

func (s *ScopedPersistence) fail(err error) error {
	s.mu.Lock()
	if s.err == nil {
		s.err = ErrStateFailed
	}
	handler := s.failure
	call := !s.failureCalled && handler != nil
	if call {
		s.failureCalled = true
	}
	s.mu.Unlock()
	if call {
		handler()
	}
	return ErrStateFailed
}

func (s *ScopedPersistence) Error() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *ScopedPersistence) Cancel() {
	s.mu.Lock()
	s.retired = true
	s.active = false
	s.mu.Unlock()
}

func (s *ScopedPersistence) Close() error {
	s.Cancel()
	return s.Wait(context.Background())
}

// Wait starts one real Sync/Close after DNS waiters have joined. Timeout or
// failure retains the DB and file references; a second Wait never retries an
// unknown Close or replaces its result with bbolt's later idempotent success.
func (s *ScopedPersistence) Wait(ctx context.Context) error {
	s.mu.Lock()
	if !s.retired {
		s.mu.Unlock()
		return ErrStateInactive
	}
	if s.closeDone == nil {
		s.closeDone = make(chan struct{})
		go s.close()
	}
	done := s.closeDone
	s.mu.Unlock()
	select {
	case <-done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *ScopedPersistence) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer close(s.closeDone)
	if s.db == nil {
		return
	}
	if err := s.db.Sync(); err != nil {
		s.closeErr = ErrStateClose
	}
	if err := s.db.Close(); err != nil {
		s.closeErr = ErrStateClose
	}
	if s.closeErr == nil {
		s.db, s.file = nil, nil
	}
}

type scopedStore struct {
	owner  *ScopedPersistence
	bucket []byte
}

func (s *scopedStore) restore(pool *Pool) error {
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.db == nil || o.retired || o.err != nil {
		return ErrStateInactive
	}
	return o.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		for _, name := range []string{"hosts", "addresses", "state"} {
			if _, err = bucket.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		state := bucket.Bucket([]byte("state"))
		offset := state.Get([]byte("offset"))
		if len(offset) != 0 {
			value, err := netip.ParseAddr(string(offset))
			if err != nil || !pool.ipnet.Contains(value) || value.Less(pool.first.Prev()) || !value.Less(pool.last) {
				return ErrStateFailed
			}
			pool.offset = value
		} else if bucket.Bucket([]byte("addresses")).Stats().KeyN != 0 {
			return ErrStateFailed
		}
		cycle := state.Get([]byte("cycle"))
		if len(cycle) > 1 || (len(cycle) == 1 && cycle[0] > 1) {
			return ErrStateFailed
		}
		pool.cycle = len(cycle) == 1 && cycle[0] == 1
		return nil
	})
}

func (s *scopedStore) lookup(pool *Pool, host string) (netip.Addr, error) {
	o := s.owner
	o.mu.Lock()
	if !o.active || o.retired || o.err != nil {
		err := o.err
		if err == nil {
			err = ErrStateInactive
		}
		o.mu.Unlock()
		return netip.Addr{}, err
	}
	var result netip.Addr
	before, cycle := pool.offset, pool.cycle
	err := o.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(s.bucket)
		if bucket == nil {
			return ErrStateFailed
		}
		hosts, addresses := bucket.Bucket([]byte("hosts")), bucket.Bucket([]byte("addresses"))
		if hosts == nil || addresses == nil {
			return ErrStateFailed
		}
		if value := hosts.Get([]byte(host)); value != nil {
			var err error
			result, err = netip.ParseAddr(string(value))
			if err != nil || !pool.ipnet.Contains(result) || result.Less(pool.first) || !result.Less(pool.last) || string(addresses.Get(value)) != host {
				return ErrStateFailed
			}
			return nil
		}
		result = pool.next()
		key := []byte(result.String())
		if oldHost := addresses.Get(key); oldHost != nil {
			if err := hosts.Delete(oldHost); err != nil {
				return err
			}
		}
		if err := hosts.Put([]byte(host), key); err != nil {
			return err
		}
		if err := addresses.Put(key, []byte(host)); err != nil {
			return err
		}
		return s.state(bucket, pool)
	})
	if err != nil {
		pool.offset, pool.cycle = before, cycle
	}
	o.mu.Unlock()
	if err != nil {
		return netip.Addr{}, o.fail(err)
	}
	return result, nil
}

func (s *scopedStore) state(bucket *bbolt.Bucket, pool *Pool) error {
	state := bucket.Bucket([]byte("state"))
	if state == nil {
		return ErrStateFailed
	}
	if err := state.Put([]byte("offset"), []byte(pool.offset.String())); err != nil {
		return err
	}
	cycle := byte(0)
	if pool.cycle {
		cycle = 1
	}
	return state.Put([]byte("cycle"), []byte{cycle})
}

func (s *scopedStore) GetByHost(host string) (netip.Addr, bool) {
	var address netip.Addr
	value, ok := s.read("hosts", []byte(host))
	if ok {
		address, _ = netip.ParseAddr(string(value))
	}
	return address, ok && address.IsValid()
}
func (s *scopedStore) GetByIP(address netip.Addr) (string, bool) {
	value, ok := s.read("addresses", []byte(address.String()))
	return string(value), ok
}
func (s *scopedStore) read(name string, key []byte) ([]byte, bool) {
	o := s.owner
	o.mu.Lock()
	if !o.active || o.retired || o.err != nil {
		o.mu.Unlock()
		return nil, false
	}
	var value []byte
	err := o.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(s.bucket)
		if bucket == nil || bucket.Bucket([]byte(name)) == nil {
			return ErrStateFailed
		}
		value = append([]byte(nil), bucket.Bucket([]byte(name)).Get(key)...)
		return nil
	})
	o.mu.Unlock()
	if err != nil {
		o.fail(err)
	}
	return value, err == nil && len(value) != 0
}
func (s *scopedStore) Exist(address netip.Addr) bool { _, ok := s.GetByIP(address); return ok }

// All scoped mapping writes use lookup's single atomic transaction. These
// legacy store mutators and CloneTo are never used to import another policy's
// state. Reaching one rejects rather than copying a global cache silently.
func (s *scopedStore) PutByHost(string, netip.Addr) { s.owner.fail(ErrStateFailed) }
func (s *scopedStore) PutByIP(netip.Addr, string)   { s.owner.fail(ErrStateFailed) }
func (s *scopedStore) DelByIP(netip.Addr)           { s.owner.fail(ErrStateFailed) }
func (s *scopedStore) CloneTo(store)                {}
func (s *scopedStore) FlushFakeIP() error {
	o := s.owner
	o.mu.Lock()
	if !o.active || o.retired || o.err != nil {
		o.mu.Unlock()
		return ErrStateInactive
	}
	err := o.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.DeleteBucket(s.bucket); err != nil {
			return err
		}
		bucket, err := tx.CreateBucket(s.bucket)
		if err != nil {
			return err
		}
		for _, name := range []string{"hosts", "addresses", "state"} {
			if _, err = bucket.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
	o.mu.Unlock()
	if err != nil {
		return o.fail(err)
	}
	return nil
}
