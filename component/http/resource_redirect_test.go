package http

import (
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type resourceLoopbackDialer struct {
	C.Dialer
	address string
}

func (d resourceLoopbackDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func TestResourceRedirectHeadersMatchOrdinaryUpstreamClient(t *testing.T) {
	var observed [][4]string
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		observed = append(observed, [4]string{r.Host, r.Header.Get("X-Source"), r.Header.Get("Authorization"), r.Header.Get("Cookie")})
		switch r.URL.Path {
		case "/start":
			stdhttp.Redirect(w, r, "http://different.example/next", stdhttp.StatusFound)
		case "/next":
			stdhttp.Redirect(w, r, "http://origin.example/end", stdhttp.StatusFound)
		default:
			_, _ = io.WriteString(w, "complete")
		}
	}))
	defer server.Close()
	dialer := resourceLoopbackDialer{address: strings.TrimPrefix(server.URL, "http://")}
	headers := map[string][]string{"X-Source": {"ordinary-value"}, "Authorization": {"fixture-token"}, "Cookie": {"fixture-cookie"}}
	var baseline [][4]string
	for _, resource := range []bool{false, true} {
		observed = nil
		attempts := 0
		options := []Option{WithDialer(dialer)}
		if resource {
			options = append(options, WithResourceRequest(func() { attempts++ }, nil))
		}
		response, err := HttpRequest(context.Background(), "http://origin.example/start", "GET", headers, nil, options...)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || string(body) != "complete" {
			t.Fatal(err, closeErr, string(body))
		}
		if !resource {
			baseline = append([][4]string(nil), observed...)
			if len(baseline) != 3 || baseline[1][1] != "ordinary-value" || baseline[1][2] != "" || baseline[1][3] != "" {
				t.Fatal("upstream must preserve ordinary headers and strip cross-host credentials", baseline)
			}
		} else if !reflect.DeepEqual(observed, baseline) || attempts != 3 {
			t.Fatal("resource acquisition changed upstream redirects", observed, baseline, attempts)
		}
	}
}
