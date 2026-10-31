package fakeip

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/log"
)

var (
	ErrStateInactive = errors.New("POLICY_FAKEIP_STATE_INACTIVE")
	ErrStateFailed   = errors.New("POLICY_FAKEIP_STATE_FAILED")
	ErrStateClose    = errors.New("POLICY_FAKEIP_STATE_CLOSE_FAILED")
)

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
	mu        sync.Mutex
	files     StateFiles
	path      string
	pools     []*Pool
	db        *bbolt.DB
	file      *os.File
	active    bool
	retired   bool
	closeErr  error
	closeDone chan struct{}
}

func NewScopedPersistence(files StateFiles, inputDigest string) (*ScopedPersistence, error) {
	if files == nil || len(inputDigest) != 71 || !strings.HasPrefix(inputDigest, "sha256:") || strings.Trim(inputDigest[7:], "0123456789abcdef") != "" {
		return nil, ErrStateFailed
	}
	return &ScopedPersistence{files: files, path: "state/fakeip/" + inputDigest[7:] + ".db"}, nil
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
		s.mu.Unlock()
		return
	}
	if s.retired || s.db != nil {
		s.mu.Unlock()
		return ErrStateInactive
	}
	if info, statErr := s.files.Stat(s.path); statErr == nil {
		if !info.Mode().IsRegular() {
			s.mu.Unlock()
			return s.unavailable(ErrStateFailed)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		s.mu.Unlock()
		return s.unavailable(statErr)
	}
	for _, path := range []string{"state", "state/fakeip"} {
		if err = s.files.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			s.mu.Unlock()
			return s.unavailable(err)
		}
	}
	// bbolt's internal open-error cleanup does not return its Close result.
	// Capture the real file so such an unknown close cannot lose its owner.
	s.db, err = bbolt.Open(s.path, 0o600, &bbolt.Options{Timeout: time.Second, NoStatistics: true, OpenFile: func(path string, flag int, mode os.FileMode) (*os.File, error) {
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
		return s.unavailable(err)
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
			s.warn(err)
		}
	}
	s.mu.Lock()
	if s.retired {
		err = ErrStateInactive
	} else {
		s.active = true
		err = nil
	}
	s.mu.Unlock()
	return
}

// As with the upstream cachefile, unavailable persistence is reported through
// the core log. It does not cancel unrelated DNS, connections or policy tasks.
func (s *ScopedPersistence) unavailable(err error) error {
	s.mu.Lock()
	s.active = !s.retired
	retired := s.retired
	s.mu.Unlock()
	s.warn(err)
	if retired {
		return ErrStateInactive
	}
	return nil
}

func (s *ScopedPersistence) warn(err error) {
	log.Warnln("[CacheFile] fake-IP state %s: %s", s.path, err)
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

// A legal root DNS question is represented by an empty host after trimming its
// trailing dot. Prefix every host key/value so it has a nonempty, unambiguous
// database representation without changing the host returned by LookBack.
func scopedHostKey(host string) []byte {
	return append([]byte{0}, host...)
}

func (s *scopedStore) restore(pool *Pool) error {
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.db == nil || o.retired {
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
	if !o.active || o.retired {
		o.mu.Unlock()
		return netip.Addr{}, ErrStateInactive
	}
	if o.db == nil {
		o.mu.Unlock()
		return pool.next(), nil
	}
	var result netip.Addr
	hostKey := scopedHostKey(host)
	err := o.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(s.bucket)
		if bucket == nil {
			return ErrStateFailed
		}
		hosts, addresses := bucket.Bucket([]byte("hosts")), bucket.Bucket([]byte("addresses"))
		if hosts == nil || addresses == nil {
			return ErrStateFailed
		}
		if value := hosts.Get(hostKey); value != nil {
			var err error
			result, err = netip.ParseAddr(string(value))
			if err != nil || !pool.ipnet.Contains(result) || result.Less(pool.first) || !result.Less(pool.last) || !bytes.Equal(addresses.Get(value), hostKey) {
			result = netip.Addr{}
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
		if err := hosts.Put(hostKey, key); err != nil {
			return err
		}
		if err := addresses.Put(key, hostKey); err != nil {
			return err
		}
		return s.state(bucket, pool)
	})
	o.mu.Unlock()
	if err != nil {
		o.warn(err)
		if !result.IsValid() {
			result = pool.next()
		}
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
	value, ok := s.read("hosts", scopedHostKey(host))
	if ok {
		address, _ = netip.ParseAddr(string(value))
	}
	return address, ok && address.IsValid()
}
func (s *scopedStore) GetByIP(address netip.Addr) (string, bool) {
	value, ok := s.read("addresses", []byte(address.String()))
	if !ok {
		return "", false
	}
	if value[0] != 0 {
		s.owner.warn(ErrStateFailed)
		return "", false
	}
	return string(value[1:]), true
}
func (s *scopedStore) read(name string, key []byte) ([]byte, bool) {
	o := s.owner
	o.mu.Lock()
	if !o.active || o.retired || o.db == nil {
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
		o.warn(err)
	}
	return value, err == nil && len(value) != 0
}
func (s *scopedStore) Exist(address netip.Addr) bool { _, ok := s.GetByIP(address); return ok }

// All scoped mapping writes use lookup's single atomic transaction. These
// legacy store mutators and CloneTo are never used to import another policy's
// state. Report unexpected use without cancelling the runtime.
func (s *scopedStore) PutByHost(string, netip.Addr) { s.owner.warn(ErrStateFailed) }
func (s *scopedStore) PutByIP(netip.Addr, string)   { s.owner.warn(ErrStateFailed) }
func (s *scopedStore) DelByIP(netip.Addr)           { s.owner.warn(ErrStateFailed) }
func (s *scopedStore) CloneTo(store)                {}
func (s *scopedStore) FlushFakeIP() error {
	o := s.owner
	o.mu.Lock()
	if !o.active || o.retired {
		o.mu.Unlock()
		return ErrStateInactive
	}
	if o.db == nil {
		o.mu.Unlock()
		return nil
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
		o.warn(err)
	}
	return err
}
