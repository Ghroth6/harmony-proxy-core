package geodata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/geodata/router"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"github.com/oschwald/maxminddb-golang"
)

var (
	initGeoSite bool
	initGeoIP   int
	initASN     bool

	initGeoSiteMutex sync.Mutex
	initGeoIPMutex   sync.Mutex
	initASNMutex     sync.Mutex

	geoIpEnable   atomic.Bool
	geoSiteEnable atomic.Bool
	asnEnable     atomic.Bool

	geoIpUrl   string
	mmdbUrl    string
	geoSiteUrl string
	asnUrl     string
)

func GeoIpUrl() string {
	return geoIpUrl
}

func SetGeoIpUrl(url string) {
	geoIpUrl = url
}

func MmdbUrl() string {
	return mmdbUrl
}

func SetMmdbUrl(url string) {
	mmdbUrl = url
}

func GeoSiteUrl() string {
	return geoSiteUrl
}

func SetGeoSiteUrl(url string) {
	geoSiteUrl = url
}

func ASNUrl() string {
	return asnUrl
}

func SetASNUrl(url string) {
	asnUrl = url
}

func downloadToPath(url, path string, validate func([]byte) error) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	return downloadToPathContext(ctx, url, path, validate)
}

func downloadToPathContext(ctx context.Context, url, path string, validate func([]byte) error) (err error) {
	ctx, finish, err := forwarding.AcquireManagementNetwork(ctx)
	if err != nil {
		return err
	}
	defer finish()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return err
	}
	bodyClosed := false
	defer func() {
		if !bodyClosed {
			err = errors.Join(err, resp.Body.Close())
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}

	// Keep the original target throughout the transfer. A same-directory
	// rename publishes a complete file without a remove-then-rename gap.
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".download-*")
	if err != nil {
		return err
	}
	tempPath := f.Name()
	fileClosed := false
	defer func() {
		if !fileClosed {
			err = errors.Join(err, f.Close())
		}
		if removeErr := os.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	bodyErr := resp.Body.Close()
	bodyClosed = true
	if bodyErr != nil {
		return bodyErr
	}
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	closeErr := f.Close()
	fileClosed = true
	if closeErr != nil {
		return closeErr
	}
	data, err := os.ReadFile(tempPath)
	if err != nil {
		return err
	}
	if err := validate(data); err != nil {
		return fmt.Errorf("invalid downloaded geodata: %w", err)
	}
	return forwarding.CommitManagementNetwork(ctx, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return os.Rename(tempPath, path)
	})
}

// Validate the candidate bytes through the standard decoder, without reading
// the published path or invoking Init* again. Failed candidates never replace
// even a previous invalid cache, so a later retry has a recoverable target.
func validateGeoIPDownload(data []byte) error {
	loader, err := GetGeoDataLoader("standard")
	if err != nil {
		return err
	}
	cidrs, err := loader.LoadIPByBytes(data, "cn")
	if err != nil {
		return err
	}
	_, err = router.NewGeoIPMatcher(cidrs)
	return err
}

func validateGeoSiteDownload(data []byte) error {
	loader, err := GetGeoDataLoader("standard")
	if err != nil {
		return err
	}
	domains, err := loader.LoadSiteByBytes(data, "cn")
	if err != nil {
		return err
	}
	if geoSiteMatcher == "mph" {
		_, err = router.NewMphMatcherGroup(domains)
	} else {
		_, err = router.NewSuccinctMatcherGroup(domains)
	}
	return err
}

func validateMMDBDownload(data []byte) error {
	reader, err := maxminddb.FromBytes(data)
	if err != nil {
		return err
	}
	return errors.Join(reader.Verify(), reader.Close())
}

func InitGeoSite() error {
	geoSiteEnable.Store(true)
	initGeoSiteMutex.Lock()
	defer initGeoSiteMutex.Unlock()
	if _, err := os.Stat(C.Path.GeoSite()); os.IsNotExist(err) {
		log.Infoln("Can't find GeoSite.dat, start download")
		if err := downloadToPath(GeoSiteUrl(), C.Path.GeoSite(), validateGeoSiteDownload); err != nil {
			return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
		}
		log.Infoln("Download GeoSite.dat finish")
		initGeoSite = false
	}
	if !initGeoSite {
		if err := Verify(C.GeositeName); err != nil {
			log.Warnln("GeoSite.dat invalid, download replacement: %s", err)
			if err := downloadToPath(GeoSiteUrl(), C.Path.GeoSite(), validateGeoSiteDownload); err != nil {
				return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
			}
		}
		initGeoSite = true
	}
	return nil
}

func InitGeoIP() error {
	geoIpEnable.Store(true)
	initGeoIPMutex.Lock()
	defer initGeoIPMutex.Unlock()
	if GeodataMode() {
		if _, err := os.Stat(C.Path.GeoIP()); os.IsNotExist(err) {
			log.Infoln("Can't find GeoIP.dat, start download")
			if err := downloadToPath(GeoIpUrl(), C.Path.GeoIP(), validateGeoIPDownload); err != nil {
				return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
			}
			log.Infoln("Download GeoIP.dat finish")
			initGeoIP = 0
		}

		if initGeoIP != 1 {
			if err := Verify(C.GeoipName); err != nil {
				log.Warnln("GeoIP.dat invalid, download replacement: %s", err)
				if err := downloadToPath(GeoIpUrl(), C.Path.GeoIP(), validateGeoIPDownload); err != nil {
					return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
				}
			}
			initGeoIP = 1
		}
		return nil
	}

	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		log.Infoln("Can't find MMDB, start download")
		if err := downloadToPath(MmdbUrl(), C.Path.MMDB(), validateMMDBDownload); err != nil {
			return fmt.Errorf("can't download MMDB: %s", err.Error())
		}
	}

	if initGeoIP != 2 {
		if !mmdb.Verify(C.Path.MMDB()) {
			log.Warnln("MMDB invalid, download replacement")
			if err := downloadToPath(MmdbUrl(), C.Path.MMDB(), validateMMDBDownload); err != nil {
				return fmt.Errorf("can't download MMDB: %s", err.Error())
			}
		}
		initGeoIP = 2
	}
	return nil
}

func InitASN() error {
	asnEnable.Store(true)
	initASNMutex.Lock()
	defer initASNMutex.Unlock()
	if _, err := os.Stat(C.Path.ASN()); os.IsNotExist(err) {
		log.Infoln("Can't find ASN.mmdb, start download")
		if err := downloadToPath(ASNUrl(), C.Path.ASN(), validateMMDBDownload); err != nil {
			return fmt.Errorf("can't download ASN.mmdb: %s", err.Error())
		}
		log.Infoln("Download ASN.mmdb finish")
		initASN = false
	}
	if !initASN {
		if !mmdb.Verify(C.Path.ASN()) {
			log.Warnln("ASN invalid, download replacement")
			if err := downloadToPath(ASNUrl(), C.Path.ASN(), validateMMDBDownload); err != nil {
				return fmt.Errorf("can't download ASN: %s", err.Error())
			}
		}
		initASN = true
	}
	return nil
}

func GeoIpEnable() bool {
	return geoIpEnable.Load()
}

func GeoSiteEnable() bool {
	return geoSiteEnable.Load()
}

func ASNEnable() bool {
	return asnEnable.Load()
}
