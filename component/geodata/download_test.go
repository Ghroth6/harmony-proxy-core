package geodata

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
)

func downloadNetwork(t *testing.T) {
	t.Helper()
	previous := inner.GetTunnel()
	inner.New(nil)
	t.Cleanup(func() { inner.New(previous) })
	forwarding.EnableManagementNetwork()
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		forwarding.CancelManagementNetwork()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := forwarding.WaitManagementNetwork(ctx); err != nil {
			t.Error(err)
		}
	})
}

func assertDownloadTarget(t *testing.T, target, want string, exists bool) {
	t.Helper()
	got, err := os.ReadFile(target)
	if !exists {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected target: %q %v", got, err)
		}
	} else if err != nil || string(got) != want {
		t.Fatalf("target = %q, %v; want %q", got, err, want)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".download-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary downloads remain: %v %v", matches, err)
	}
}

func TestInitialDownloadCancellationPreservesTargetAndRecovers(t *testing.T) {
	downloadNetwork(t)
	for _, exists := range []bool{false, true} {
		t.Run(fmt.Sprint("cached=", exists), func(t *testing.T) {
			if err := forwarding.ResumeManagementNetwork(); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			target := filepath.Join(dir, "GeoIP.dat")
			old := "old cache must remain complete"
			if exists {
				if err := os.WriteFile(target, []byte(old), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			started := make(chan struct{})
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("partial"))
					w.(http.Flusher).Flush()
					close(started)
					<-r.Context().Done()
					return
				}
				_, _ = w.Write([]byte("new"))
			}))
			defer server.Close()
			done := make(chan error, 1)
			go func() { done <- downloadToPath(server.URL, target) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("download did not start")
			}
			// The server has sent data, but even the previous target's prefix
			// must remain untouched while the body is still being transferred.
			if exists {
				b, err := os.ReadFile(target)
				if err != nil || string(b) != old {
					t.Fatalf("in-progress transfer damaged target: %q %v", b, err)
				}
			}
			forwarding.CancelManagementNetwork()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled download succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("download ignored cancellation")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := forwarding.WaitManagementNetwork(ctx); err != nil {
				t.Fatal(err)
			}
			assertDownloadTarget(t, target, old, exists)
			if err := forwarding.ResumeManagementNetwork(); err != nil {
				t.Fatal(err)
			}
			if err := downloadToPath(server.URL, target); err != nil {
				t.Fatal(err)
			}
			assertDownloadTarget(t, target, "new", true)
		})
	}
}

func TestInitialDownloadRejectsHTTPFailureAndTruncatedBody(t *testing.T) {
	downloadNetwork(t)
	for _, status := range []int{http.StatusNoContent, http.StatusPartialContent, http.StatusNotFound, http.StatusServiceUnavailable, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "GeoSite.dat")
			if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if status == http.StatusOK {
					w.Header().Set("Content-Length", "100")
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte("invalid or incomplete"))
			}))
			defer server.Close()
			if err := downloadToPath(server.URL, target); err == nil {
				t.Fatal("failed response replaced target")
			}
			assertDownloadTarget(t, target, "original", true)
		})
	}
}

func TestInitialDownloadFailedPublishPreservesTarget(t *testing.T) {
	downloadNetwork(t)
	target := filepath.Join(t.TempDir(), "GeoIP.dat")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(target, "keep")
	if err := os.WriteFile(child, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("new")) }))
	defer server.Close()
	if err := downloadToPath(server.URL, target); err == nil {
		t.Fatal("unexpected successful replacement of directory")
	}
	assertDownloadTarget(t, child, "original", true)
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(target), ".GeoIP.dat.download-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary downloads remain: %v %v", matches, err)
	}
}

func TestGeodataInitializersPreserveFailedReplacement(t *testing.T) {
	downloadNetwork(t)
	oldHome := C.Path.HomeDir()
	oldGeoSiteURL, oldGeoIPURL, oldMMDBURL, oldASNURL := geoSiteUrl, geoIpUrl, mmdbUrl, asnUrl
	oldSite, oldIP, oldASN, oldMode := initGeoSite, initGeoIP, initASN, geoMode
	defer func() {
		C.SetHomeDir(oldHome)
		geoSiteUrl, geoIpUrl, mmdbUrl, asnUrl = oldGeoSiteURL, oldGeoIPURL, oldMMDBURL, oldASNURL
		initGeoSite, initGeoIP, initASN, geoMode = oldSite, oldIP, oldASN, oldMode
		ClearGeoSiteCache()
		ClearGeoIPCache()
	}()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	geoSiteUrl, geoIpUrl, mmdbUrl, asnUrl = server.URL, server.URL, server.URL, server.URL
	for _, name := range []string{"GeoSite", "GeoIP", "MMDB", "ASN"} {
		t.Run(name, func(t *testing.T) {
			C.SetHomeDir(t.TempDir())
			initGeoSite, initGeoIP, initASN = false, 0, false
			ClearGeoSiteCache()
			ClearGeoIPCache()
			var target string
			var initialize func() error
			switch name {
			case "GeoSite":
				target, initialize = C.Path.GeoSite(), InitGeoSite
			case "GeoIP":
				geoMode = true
				target, initialize = C.Path.GeoIP(), InitGeoIP
			case "MMDB":
				geoMode = false
				target, initialize = C.Path.MMDB(), InitGeoIP
			case "ASN":
				target, initialize = C.Path.ASN(), InitASN
			}
			if err := os.WriteFile(target, []byte("previous invalid cache"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := initialize(); err == nil {
				t.Fatal("failed initialization succeeded")
			}
			assertDownloadTarget(t, target, "previous invalid cache", true)
		})
	}
}
