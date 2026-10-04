package updater

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
	"google.golang.org/protobuf/proto"
)

func geoTestEnvironment(t *testing.T) {
	t.Helper()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	oldTunnel := inner.GetTunnel()
	inner.New(nil)
	oldETag := resource.ETag()
	resource.SetETag(false)
	oldIP, oldSite, oldMMDB, oldASN := geodata.GeoIpUrl(), geodata.GeoSiteUrl(), geodata.MmdbUrl(), geodata.ASNUrl()
	t.Cleanup(func() {
		geodata.SetGeoIpUrl(oldIP)
		geodata.SetGeoSiteUrl(oldSite)
		geodata.SetMmdbUrl(oldMMDB)
		geodata.SetASNUrl(oldASN)
		resource.SetETag(oldETag)
		inner.New(oldTunnel)
		C.SetHomeDir(oldHome)
	})
}

type geoTestTarget struct {
	name   string
	setURL func(string)
	path   func() string
	update func(context.Context) error
}

func geoTestTargets() []geoTestTarget {
	return []geoTestTarget{
		{"MMDB", geodata.SetMmdbUrl, C.Path.MMDB, UpdateMMDBContext},
		{"ASN", geodata.SetASNUrl, C.Path.ASN, UpdateASNContext},
		{"GeoIP", geodata.SetGeoIpUrl, C.Path.GeoIP, UpdateGeoIpContext},
		{"GeoSite", geodata.SetGeoSiteUrl, C.Path.GeoSite, UpdateGeoSiteContext},
	}
}

func TestGeoUpdatesCancelRealDownloadsWithoutOverwritingFiles(t *testing.T) {
	geoTestEnvironment(t)
	for _, target := range geoTestTargets() {
		t.Run(target.name, func(t *testing.T) {
			started, released := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				close(started)
				select {
				case <-r.Context().Done():
				case <-released:
				}
			}))
			defer func() { close(released); server.Close() }()
			target.setURL(server.URL)
			original := []byte("original " + target.name)
			if err := os.WriteFile(target.path(), original, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- target.update(ctx) }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("download never reached local HTTP server")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("update failed to return after cancellation")
			}
			got, err := os.ReadFile(target.path())
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("canceled download changed file: %q, %v", got, err)
			}
		})
	}
}

func validGeoSite(t *testing.T, value string) []byte {
	t.Helper()
	data, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{
		CountryCode: "CN", Domain: []*router.Domain{{Type: router.Domain_Full, Value: value}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func validGeoIP(t *testing.T) []byte {
	t.Helper()
	data, err := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{
		CountryCode: "CN", Cidr: []*router.CIDR{{Ip: []byte{10, 0, 0, 0}, Prefix: 8}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func serveGeoData(t *testing.T, data []byte, target geoTestTarget) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
	t.Cleanup(server.Close)
	target.setURL(server.URL)
}

func TestGeoSiteValidatedDownloadCannotCommitAfterOwnerRetirement(t *testing.T) {
	geoTestEnvironment(t)
	target := geoTestTargets()[3]
	original := validGeoSite(t, "old.example")
	if err := os.WriteFile(target.path(), original, 0600); err != nil {
		t.Fatal(err)
	}
	serveGeoData(t, validGeoSite(t, "new.example"), target)
	retired := errors.New("configuration retired")
	commits := 0
	ctx := resource.WithCommitGuard(context.Background(), func(action func() error) error {
		commits++
		if commits == 2 {
			return retired
		} // Response complete, real protobuf validation has passed.
		return action()
	})
	if err := target.update(ctx); !errors.Is(err, retired) {
		t.Fatalf("retired commit returned %v", err)
	}
	if commits != 2 {
		t.Fatalf("did not reach validated file commit: %d", commits)
	}
	got, err := os.ReadFile(target.path())
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("retired update changed old file: %v", err)
	}
}

func TestGeoSiteCallerCancellationAtCommitPreservesOldFile(t *testing.T) {
	geoTestEnvironment(t)
	target := geoTestTargets()[3]
	original := validGeoSite(t, "old.example")
	if err := os.WriteFile(target.path(), original, 0600); err != nil {
		t.Fatal(err)
	}
	serveGeoData(t, validGeoSite(t, "new.example"), target)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	commits := 0
	ctx = resource.WithCommitGuard(ctx, func(action func() error) error {
		commits++
		if commits == 2 {
			cancel()
		} // Owner is still current, but this particular update was canceled.
		return action()
	})
	if err := target.update(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled commit returned %v", err)
	}
	got, err := os.ReadFile(target.path())
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("canceled commit changed old file: %v", err)
	}
}

func TestGeoUpdatesSameHashDoNotHideCancellation(t *testing.T) {
	geoTestEnvironment(t)
	for _, target := range geoTestTargets() {
		t.Run(target.name, func(t *testing.T) {
			data := []byte("unchanged bytes") // Same-hash path must skip parsing.
			if err := os.WriteFile(target.path(), data, 0600); err != nil {
				t.Fatal(err)
			}
			serveGeoData(t, data, target)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = resource.WithCommitGuard(ctx, func(action func() error) error {
				err := action()
				cancel() // Cancellation arrives just after the complete HTTP response.
				return err
			})
			if err := target.update(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("same-hash result hid cancellation: %v", err)
			}
		})
	}
}

func TestGeoDataValidDownloadsCommitAndInvalidDownloadsKeepOldFiles(t *testing.T) {
	geoTestEnvironment(t)
	for _, target := range geoTestTargets()[2:] {
		t.Run(target.name, func(t *testing.T) {
			data := validGeoIP(t)
			if target.name == "GeoSite" {
				data = validGeoSite(t, "valid.example")
			}
			serveGeoData(t, data, target)
			var commits atomic.Int32
			ctx := resource.WithCommitGuard(context.Background(), func(action func() error) error { commits.Add(1); return action() })
			if err := target.update(ctx); err != nil {
				t.Fatalf("valid download: %v", err)
			}
			got, err := os.ReadFile(target.path())
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("validated bytes not saved: %v", err)
			}
			if commits.Load() != 2 {
				t.Fatalf("expected response and final publication: %d", commits.Load())
			}
			serveGeoData(t, []byte("invalid protobuf"), target)
			if err := target.update(context.Background()); err == nil {
				t.Fatal("invalid download succeeded")
			}
			got, err = os.ReadFile(target.path())
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("invalid download replaced valid file: %v", err)
			}
		})
	}
}
