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
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"
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
			valid := geoIPDownloadFixture(t)
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
				_, _ = w.Write(valid)
			}))
			defer server.Close()
			done := make(chan error, 1)
			go func() { done <- downloadToPath(server.URL, target, validateGeoIPDownload) }()
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
			if err := downloadToPath(server.URL, target, validateGeoIPDownload); err != nil {
				t.Fatal(err)
			}
			assertDownloadTarget(t, target, string(valid), true)
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
			if err := downloadToPath(server.URL, target, validateGeoSiteDownload); err == nil {
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
	valid := geoIPDownloadFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(valid) }))
	defer server.Close()
	if err := downloadToPath(server.URL, target, validateGeoIPDownload); err == nil {
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

func geoIPDownloadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "CN", Cidr: []*router.CIDR{{Ip: []byte{10, 0, 0, 0}, Prefix: 8}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func geoSiteDownloadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "CN", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "example.invalid"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mmdbDownloadFixture(t *testing.T) []byte {
	t.Helper()
	// A synthetic, empty IPv4 tree with one node and both branches marked
	// absent. No third-party database, network access or binary fixture is used.
	b := []byte{0, 0, 1, 0, 0, 1}
	b = append(b, make([]byte, 16)...)
	b = append(b, []byte("\xab\xcd\xefMaxMind.com")...)
	b = append(b, 0xe7) // map with seven metadata entries
	str := func(value string) { b = append(b, byte(0x40|len(value))); b = append(b, value...) }
	number := func(key string, value byte) { str(key); b = append(b, 0xc1, value) }
	number("node_count", 1)
	number("record_size", 24)
	number("ip_version", 4)
	number("binary_format_major_version", 2)
	number("binary_format_minor_version", 0)
	str("database_type")
	str("SyntheticTest")
	str("description")
	b = append(b, 0xe1)
	str("en")
	str("Synthetic empty database")
	r, err := maxminddb.FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Verify(); err != nil {
		t.Fatal("invalid MMDB test fixture:", err)
	}
	return b
}

func TestGeodataInitializersRejectInvalid200ThenPublishValidCandidate(t *testing.T) {
	downloadNetwork(t)
	oldHome := C.Path.HomeDir()
	oldGeoSiteURL, oldGeoIPURL, oldMMDBURL, oldASNURL := geoSiteUrl, geoIpUrl, mmdbUrl, asnUrl
	oldSite, oldIP, oldASN, oldMode, oldLoader := initGeoSite, initGeoIP, initASN, geoMode, geoLoaderName
	defer func() {
		C.SetHomeDir(oldHome)
		geoSiteUrl, geoIpUrl, mmdbUrl, asnUrl = oldGeoSiteURL, oldGeoIPURL, oldMMDBURL, oldASNURL
		initGeoSite, initGeoIP, initASN, geoMode, geoLoaderName = oldSite, oldIP, oldASN, oldMode, oldLoader
		ClearGeoSiteCache()
		ClearGeoIPCache()
	}()
	geoLoaderName = "standard"
	for _, name := range []string{"GeoSite", "GeoIP", "MMDB", "ASN"} {
		for _, exists := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cached=%t", name, exists), func(t *testing.T) {
				C.SetHomeDir(t.TempDir())
				initGeoSite, initGeoIP, initASN = false, 0, false
				ClearGeoSiteCache()
				ClearGeoIPCache()
				var target string
				var initialize func() error
				var valid []byte
				switch name {
				case "GeoSite":
					target, initialize, valid = C.Path.GeoSite(), InitGeoSite, geoSiteDownloadFixture(t)
				case "GeoIP":
					geoMode = true
					target, initialize, valid = C.Path.GeoIP(), InitGeoIP, geoIPDownloadFixture(t)
				case "MMDB":
					geoMode = false
					target, initialize, valid = C.Path.MMDB(), InitGeoIP, mmdbDownloadFixture(t)
				case "ASN":
					target, initialize, valid = C.Path.ASN(), InitASN, mmdbDownloadFixture(t)
				}
				old := "original invalid cache"
				if exists {
					if err := os.WriteFile(target, []byte(old), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				var serveValid atomic.Bool
				var requests atomic.Int32
				invalid := []byte("<html>invalid geodata</html>")
				if name == "MMDB" || name == "ASN" {
					// Metadata still decodes, but the tree points outside the data
					// section. Opening alone must not validate this candidate.
					invalid = append([]byte(nil), valid...)
					invalid[0], invalid[1], invalid[2] = 0xff, 0xff, 0xff
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					if serveValid.Load() {
						_, _ = w.Write(valid)
					} else {
						_, _ = w.Write(invalid)
					}
				}))
				defer server.Close()
				geoSiteUrl, geoIpUrl, mmdbUrl, asnUrl = server.URL, server.URL, server.URL, server.URL
				if err := initialize(); err == nil {
					t.Fatal("HTTP 200 invalid content was treated as initialized")
				}
				assertDownloadTarget(t, target, old, exists)
				serveValid.Store(true)
				if err := initialize(); err != nil {
					t.Fatalf("valid retry failed: %v", err)
				}
				assertDownloadTarget(t, target, string(valid), true)
				before := requests.Load()
				if err := initialize(); err != nil {
					t.Fatal(err)
				}
				if requests.Load() != before {
					t.Fatal("successful initialization was not retained")
				}
			})
		}
	}
}
