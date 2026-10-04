package route

import (
	"context"
	"encoding/base64"
	"io"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func dohRouter() http.Handler {
	return http.HandlerFunc(dohHandler)
}

func dohHandler(w http.ResponseWriter, r *http.Request) {
	queryCtx, finish, err := dns.BeginExternalQuery(r.Context())
	if err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.PlainText(w, r, err.Error())
		return
	}
	defer finish()
	ctx, cancel := context.WithTimeout(queryCtx, resolver.DefaultDNSTimeout)
	defer cancel()
	if resolver.DefaultResolver == nil {
		render.Status(r, http.StatusInternalServerError)
		render.PlainText(w, r, "DNS section is disabled")
		return
	}

	var dnsData []byte
	switch r.Method {
	case "GET":
		dnsData, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	case "POST":
		if r.Header.Get("Content-Type") != "application/dns-message" {
			render.Status(r, http.StatusInternalServerError)
			render.PlainText(w, r, "invalid content-type")
			return
		}
		reader := io.LimitReader(r.Body, 65535) // according to rfc8484, the maximum size of the DNS message is 65535 bytes
		// Closing a server request body can wait for the peer to send more
		// bytes. Interrupt its socket read instead, without closing the shared
		// HTTP server. Join the callback before this handler can return.
		readCancelled := make(chan struct{})
		stopRead := context.AfterFunc(ctx, func() {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now())
			close(readCancelled)
		})
		dnsData, err = io.ReadAll(reader)
		if !stopRead() {
			<-readCancelled
		}
		_ = r.Body.Close()
	default:
		render.Status(r, http.StatusMethodNotAllowed)
		render.PlainText(w, r, "method not allowed")
		return
	}
	if ctx.Err() != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.PlainText(w, r, "external DNS query cancelled")
		return
	}
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.PlainText(w, r, err.Error())
		return
	}

	dnsData, err = resolver.RelayDnsPacket(ctx, dnsData, dnsData)
	if ctx.Err() != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.PlainText(w, r, "external DNS query cancelled")
		return
	}
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.PlainText(w, r, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dnsData)
}
