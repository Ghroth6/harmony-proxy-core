package resource

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/common/utils"
	"os"
	"path/filepath"
	"testing"
)

func TestLatestFetchResultDistinguishesCachedInitializationAndActualAttempts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.yaml")
	if err := os.WriteFile(path, []byte("cached"), 0600); err != nil {
		t.Fatal(err)
	}
	reads := 0
	body := []byte("cached")
	var readErr error
	vehicle := &testVehicle{path: path, read: func(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
		reads++
		return body, utils.MakeHash(body), readErr
	}}
	f := NewFetcher("results", 0, vehicle, nil, parseString, nil)
	defer f.Close()
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}
	if reads != 0 || f.LastResult().State != "" {
		t.Fatal("cache loading claimed a new fetch", reads, f.LastResult())
	}
	if _, same, err := f.Update(); err != nil || !same || f.LastResult().State != "unchanged" || f.LastResult().At.IsZero() {
		t.Fatal("unchanged attempt missing", f.LastResult(), err)
	}
	body = []byte("new")
	if _, same, err := f.Update(); err != nil || same || f.LastResult().State != "updated" {
		t.Fatal("new content missing", f.LastResult(), err)
	}
	readErr = errors.New("unavailable")
	if _, _, err := f.Update(); err == nil || f.LastResult().State != "failed" {
		t.Fatal("failed attempt missing", f.LastResult())
	}
	prior := f.LastResult()
	readErr = context.Canceled
	_, _, _ = f.Update()
	if f.LastResult() != prior {
		t.Fatal("retirement replaced last useful attempt")
	}
}
