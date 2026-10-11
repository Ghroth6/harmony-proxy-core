package content

import (
	"encoding/base64"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

func decodeBase64(text string) ([]byte, error) {
	var last error
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := encoding.Strict().DecodeString(text)
		if err == nil {
			return decoded, nil
		}
		last = err
	}
	return nil, last
}
func decodeComponent(text string) (string, bool) {
	value, err := url.PathUnescape(text)
	return value, err == nil && utf8.ValidString(value)
}

func parseLink(line string) (node map[string]any, name, protocol, code string) {
	protocol = "unknown"
	code = "ENTRY_LINK_INVALID"
	index := strings.Index(line, "://")
	if index <= 0 {
		return
	}
	scheme := strings.ToLower(line[:index])
	switch scheme {
	case "ss", "trojan", "vmess", "vless", "anytls", "hysteria2":
		protocol = scheme
	case "hy2":
		protocol = "hysteria2"
	default:
		code = "ENTRY_PROTOCOL_UNSUPPORTED"
		return
	}
	if protocol == "anytls" {
		return parseAnyTLS(line)
	}
	if protocol == "trojan" {
		return parseTrojan(line)
	}
	if protocol == "vless" {
		return parseVLESS(line)
	}
	if protocol == "vmess" {
		return parseVMess(line)
	}
	if protocol == "hysteria2" {
		return parseHysteria2(line)
	}
	if protocol != "ss" {
		code = "ENTRY_PROTOCOL_UNSUPPORTED"
		return
	}
	authority := line[index+3:]
	if split := strings.IndexByte(authority, '#'); split >= 0 {
		var ok bool
		name, ok = decodeComponent(authority[split+1:])
		if !ok {
			return
		}
		authority = authority[:split]
	}
	udp := false
	if split := strings.IndexByte(authority, '?'); split >= 0 {
		q, err := url.ParseQuery(authority[split+1:])
		if err != nil {
			return
		}
		for key, values := range q {
			if key != "udp" {
				code = "ENTRY_PARAMETER_UNSUPPORTED"
				return
			}
			if len(values) != 1 {
				code = "ENTRY_PARAMETER_DUPLICATE"
				return
			}
		}
		var failure string
		udp, _, failure = queryBool(q, "udp")
		if failure != "" {
			code = failure
			return
		}
		authority = authority[:split]
	}
	authority = strings.TrimSuffix(authority, "/")
	whole := !strings.Contains(authority, "@")
	if whole {
		decoded, err := decodeBase64(authority)
		if err != nil || !utf8.Valid(decoded) {
			return
		}
		authority = string(decoded)
	}
	at := strings.LastIndexByte(authority, '@')
	if at <= 0 {
		return
	}
	credentials, endpoint := authority[:at], authority[at+1:]
	if !whole {
		if strings.Count(authority, "@") != 1 {
			return
		}
		if !strings.Contains(credentials, ":") {
			decoded, err := decodeBase64(credentials)
			if err != nil || !utf8.Valid(decoded) {
				return
			}
			credentials = string(decoded)
		} else {
			var ok bool
			credentials, ok = decodeComponent(credentials)
			if !ok {
				return
			}
		}
	}
	colon := strings.IndexByte(credentials, ':')
	if colon <= 0 || colon == len(credentials)-1 {
		return
	}
	server, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return
	}
	node = map[string]any{"name": "selected-node", "type": "ss", "server": server, "port": port, "cipher": credentials[:colon], "password": credentials[colon+1:], "udp": udp}
	code = ""
	return
}

func parseHysteria2(line string) (node map[string]any, name, protocol, code string) {
	protocol = "hysteria2"
	var u *url.URL
	var q url.Values
	node, u, q, code = parseURI(line, protocol)
	if code != "" {
		return
	}
	name = u.Fragment
	for key := range q {
		switch key {
		case "sni", "alpn", "insecure", "allowInsecure", "hpkp", "obfs", "obfs-password":
		default:
			code = "ENTRY_PARAMETER_UNSUPPORTED"
			return
		}
	}
	password := u.User.Username()
	if tail, present := u.User.Password(); present {
		password += ":" + tail
	}
	if password == "" || !utf8.ValidString(password) {
		code = "ENTRY_LINK_INVALID"
		return
	}
	node["password"] = password
	for _, key := range []string{"obfs", "obfs-password"} {
		if values, present := q[key]; present {
			node[key] = values[0]
		}
	}
	code = applyTLSQuery(node, q, "sni")
	return
}

func parseURI(line, protocol string) (node map[string]any, u *url.URL, q url.Values, code string) {
	code = "ENTRY_LINK_INVALID"
	var err error
	u, err = url.Parse(line)
	if err != nil || u.User == nil || u.Hostname() == "" || u.Path != "" && u.Path != "/" {
		return
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return
	}
	q, err = url.ParseQuery(u.RawQuery)
	if err != nil {
		return
	}
	for _, values := range q {
		if len(values) != 1 {
			code = "ENTRY_PARAMETER_DUPLICATE"
			return
		}
		if !utf8.ValidString(values[0]) {
			return
		}
	}
	if !utf8.ValidString(u.Fragment) || !utf8.ValidString(u.User.Username()) {
		return
	}
	node = map[string]any{"name": "selected-node", "type": protocol, "server": u.Hostname(), "port": port, "udp": true}
	code = ""
	return
}

func applyTLSQuery(node map[string]any, q url.Values, sniField string) string {
	for source, target := range map[string]string{"sni": sniField, "fp": "client-fingerprint", "hpkp": "fingerprint"} {
		if values, ok := q[source]; ok {
			node[target] = values[0]
		}
	}
	if values, ok := q["alpn"]; ok {
		node["alpn"] = strings.Split(values[0], ",")
	}
	for _, binding := range []struct {
		keys   []string
		target string
	}{{[]string{"insecure", "allowInsecure"}, "skip-cert-verify"}, {[]string{"udp"}, "udp"}} {
		value, present, code := queryBool(q, binding.keys...)
		if code != "" {
			return code
		}
		if present {
			node[binding.target] = value
		}
	}
	return ""
}

func applyTransport(node map[string]any, q url.Values) string {
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	if header, present := q["headerType"]; present && header[0] != "none" && header[0] != "" {
		if header[0] != "http" || network != "tcp" {
			return "ENTRY_TRANSPORT_UNSUPPORTED"
		}
		network = "http"
	}
	if network == "http" && q.Get("type") == "http" {
		network = "h2"
	}
	if ws, present, code := queryBool(q, "ws"); code != "" {
		return code
	} else if present {
		if _, duplicate := q["type"]; duplicate {
			return "ENTRY_PARAMETER_DUPLICATE"
		}
		if ws {
			network = "ws"
		}
	}
	path := q.Get("path")
	if value, present := q["wspath"]; present {
		if _, duplicate := q["path"]; duplicate {
			return "ENTRY_PARAMETER_DUPLICATE"
		}
		path = value[0]
	}
	node["network"] = network
	switch network {
	case "tcp":
		if path != "" || q.Get("host") != "" || q.Get("serviceName") != "" || q.Get("mode") != "" {
			return "ENTRY_PARAMETER_UNSUPPORTED"
		}
	case "ws":
		if q.Get("serviceName") != "" || q.Get("mode") != "" {
			return "ENTRY_PARAMETER_UNSUPPORTED"
		}
		opts := map[string]any{}
		if path != "" {
			opts["path"] = path
		}
		if host := q.Get("host"); host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		node["ws-opts"] = opts
	case "grpc":
		if path != "" || q.Get("host") != "" || (q.Has("mode") && q.Get("mode") != "gun") {
			return "ENTRY_PARAMETER_UNSUPPORTED"
		}
		opts := map[string]any{}
		if q.Has("serviceName") {
			opts["grpc-service-name"] = q.Get("serviceName")
		}
		node["grpc-opts"] = opts
	case "h2":
		if q.Has("mode") || q.Has("serviceName") {
			return "ENTRY_PARAMETER_UNSUPPORTED"
		}
		opts := map[string]any{}
		if q.Has("path") {
			opts["path"] = path
		}
		if q.Has("host") {
			opts["host"] = strings.Split(q.Get("host"), ",")
		}
		node["h2-opts"] = opts
	case "http":
		if q.Has("mode") || q.Has("serviceName") {
			return "ENTRY_PARAMETER_UNSUPPORTED"
		}
		opts := map[string]any{}
		if q.Has("path") {
			opts["path"] = strings.Split(path, ",")
		}
		if q.Has("host") {
			opts["headers"] = map[string]any{"Host": strings.Split(q.Get("host"), ",")}
		}
		node["http-opts"] = opts
	case "xhttp":
		if q.Has("serviceName") {
			return "ENTRY_PARAMETER_UNSUPPORTED"
		}
		opts := map[string]any{}
		for _, key := range []string{"path", "host", "mode"} {
			if q.Has(key) {
				opts[key] = q.Get(key)
			}
		}
		node["xhttp-opts"] = opts
	default:
		return "ENTRY_TRANSPORT_UNSUPPORTED"
	}
	return ""
}

func parseTrojan(line string) (node map[string]any, name, protocol, code string) {
	protocol = "trojan"
	var u *url.URL
	var q url.Values
	node, u, q, code = parseURI(line, protocol)
	if code != "" {
		return
	}
	name = u.Fragment
	for key := range q {
		switch key {
		case "sni", "alpn", "insecure", "allowInsecure", "fp", "type", "hpkp", "udp", "ws", "wspath", "path", "host", "serviceName", "mode":
		default:
			code = "ENTRY_PARAMETER_UNSUPPORTED"
			return
		}
	}
	// Trojan's password is the whole original userinfo value, URI decoded once.
	password := u.User.Username()
	if tail, present := u.User.Password(); present {
		password += ":" + tail
	}
	if password == "" || !utf8.ValidString(password) {
		code = "ENTRY_LINK_INVALID"
		return
	}
	node["password"] = password
	if code = applyTLSQuery(node, q, "sni"); code != "" {
		return
	}
	code = applyTransport(node, q)
	return
}

func parseVLESS(line string) (node map[string]any, name, protocol, code string) {
	protocol = "vless"
	var u *url.URL
	var q url.Values
	node, u, q, code = parseURI(line, protocol)
	if code != "" {
		return
	}
	name = u.Fragment
	for key := range q {
		switch key {
		case "sni", "alpn", "insecure", "allowInsecure", "fp", "type", "hpkp", "udp", "path", "host", "serviceName", "mode", "security", "encryption", "flow", "pbk", "sid", "headerType", "packetEncoding":
		default:
			code = "ENTRY_PARAMETER_UNSUPPORTED"
			return
		}
	}
	if _, present := u.User.Password(); present {
		code = "ENTRY_LINK_INVALID"
		return
	}
	node["uuid"] = u.User.Username()
	if encryption, present := q["encryption"]; present {
		node["encryption"] = encryption[0]
	}
	if flow, present := q["flow"]; present {
		node["flow"] = flow[0]
	}
	if packet, present := q["packetEncoding"]; present {
		node["packet-encoding"] = packet[0]
	}
	security := q.Get("security")
	switch security {
	case "", "none":
		node["tls"] = false
	case "tls":
		node["tls"] = true
	case "reality":
		node["tls"] = true
		if q.Get("pbk") == "" {
			code = "ENTRY_PARAMETER_INVALID"
			return
		}
		node["reality-opts"] = map[string]any{"public-key": q.Get("pbk"), "short-id": q.Get("sid")}
	default:
		code = "ENTRY_SECURITY_UNSUPPORTED"
		return
	}
	if security != "reality" && (q.Has("pbk") || q.Has("sid")) {
		code = "ENTRY_PARAMETER_UNSUPPORTED"
		return
	}
	if code = applyTLSQuery(node, q, "servername"); code != "" {
		return
	}
	code = applyTransport(node, q)
	return
}
func queryBool(q url.Values, keys ...string) (bool, bool, string) {
	present := false
	result := false
	for _, key := range keys {
		if values, ok := q[key]; ok {
			if present {
				return false, true, "ENTRY_PARAMETER_DUPLICATE"
			}
			present = true
			switch values[0] {
			case "true", "1":
				result = true
			case "false", "0":
				result = false
			default:
				return false, true, "ENTRY_PARAMETER_INVALID"
			}
		}
	}
	return result, present, ""
}
func parseAnyTLS(line string) (node map[string]any, name, protocol, code string) {
	protocol = "anytls"
	var u *url.URL
	var q url.Values
	node, u, q, code = parseURI(line, protocol)
	if code != "" {
		return
	}
	name = u.Fragment
	for key := range q {
		switch key {
		case "sni", "alpn", "insecure", "allowInsecure", "fp", "type", "hpkp", "udp":
		default:
			code = "ENTRY_PARAMETER_UNSUPPORTED"
			return
		}
	}
	password, exists := u.User.Password()
	if !exists {
		password = u.User.Username()
	}
	if password == "" || !utf8.ValidString(password) {
		code = "ENTRY_LINK_INVALID"
		return
	}
	node["password"] = password
	if network, ok := q["type"]; ok && network[0] != "tcp" {
		code = "ENTRY_TRANSPORT_UNSUPPORTED"
		return
	}
	if sni, ok := q["sni"]; ok {
		node["sni"] = sni[0]
	}
	if fp, ok := q["fp"]; ok {
		node["client-fingerprint"] = fp[0]
	}
	if alpn, ok := q["alpn"]; ok {
		node["alpn"] = strings.Split(alpn[0], ",")
	}
	if pin, ok := q["hpkp"]; ok {
		node["fingerprint"] = pin[0]
	}
	value, present, failure := queryBool(q, "insecure", "allowInsecure")
	if failure != "" {
		code = failure
		return
	}
	if present {
		node["skip-cert-verify"] = value
	}
	value, present, failure = queryBool(q, "udp")
	if failure != "" {
		code = failure
		return
	}
	if present {
		node["udp"] = value
	}
	return
}
