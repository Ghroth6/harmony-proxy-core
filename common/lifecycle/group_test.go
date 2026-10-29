package lifecycle_test

import (
	"errors"
	"github.com/metacubex/mihomo/common/lifecycle"
	"testing"
)

type failedResource struct {
	err            error
	starts, closes int
}

func (r *failedResource) Start() error { r.starts++; return r.err }
func (r *failedResource) Close() error { r.closes++; return nil }

func TestSharedResourceRetainsStartFailureAndCleanup(t *testing.T) {
	for _, active := range []bool{false, true} {
		g := &lifecycle.Group{}
		if active {
			if err := g.Activate(); err != nil {
				t.Fatal(err)
			}
		}
		failure := errors.New("partial resource start")
		r := &failedResource{err: failure}
		factory := func() lifecycle.Resource { return r }
		_, err := g.GetOrAdd("key", factory)
		if !active {
			if err != nil {
				t.Fatal(err)
			}
			err = g.Activate()
		}
		if !errors.Is(err, failure) {
			t.Fatalf("lost initial failure: %v", err)
		}
		for i := 0; i < 3; i++ {
			if _, err = g.GetOrAdd("key", func() lifecycle.Resource { t.Fatal("retried failed resource implicitly"); return nil }); !errors.Is(err, failure) {
				t.Fatalf("reuse hid failure: %v", err)
			}
		}
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		if r.starts != 1 || r.closes != 1 {
			t.Fatalf("starts=%d closes=%d", r.starts, r.closes)
		}
	}
}

func TestDeferredProviderResourcesWaitForSuccessfulPublication(t *testing.T) {
	root := &lifecycle.Group{}
	if err := root.Activate(); err != nil {
		t.Fatal(err)
	}
	child := &lifecycle.Group{}
	remove, err := root.Adopt(child, true)
	if err != nil {
		t.Fatal(err)
	}
	started, closed := 0, 0
	if err = child.Add(func() error { started++; return nil }, func() error { closed++; return nil }); err != nil {
		t.Fatal(err)
	}
	if started != 0 {
		t.Fatal("parser registered resources before publication")
	}
	if err = child.Close(); err != nil {
		t.Fatal(err)
	}
	remove()
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	if started != 0 || closed != 1 {
		t.Fatal("discarded parse must close once without activating")
	}
}

func TestPublishedResourcesActivateOnceAndLateConstructionIsRejected(t *testing.T) {
	root := &lifecycle.Group{}
	child := &lifecycle.Group{}
	remove, err := root.Adopt(child, false)
	if err != nil {
		t.Fatal(err)
	}
	started, closed := 0, 0
	if err = child.Add(func() error { started++; return nil }, func() error { closed++; return nil }); err != nil {
		t.Fatal(err)
	}
	if started != 0 {
		t.Fatal("preparation activated resources")
	}
	if err = root.Activate(); err != nil {
		t.Fatal(err)
	}
	if err = root.Activate(); err != nil {
		t.Fatal(err)
	}
	if err = child.Close(); err != nil {
		t.Fatal(err)
	}
	remove()
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	if started != 1 || closed != 1 {
		t.Fatal("resource lifecycle was duplicated")
	}
	if err = child.Add(func() error { started++; return nil }, func() error { closed++; return nil }); err == nil {
		t.Fatal("retired resource reopened")
	}
	if started != 1 || closed != 2 {
		t.Fatal("late resource ownership was lost")
	}
}
