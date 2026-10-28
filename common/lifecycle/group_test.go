package lifecycle_test

import (
	"github.com/metacubex/mihomo/common/lifecycle"
	"testing"
)

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
