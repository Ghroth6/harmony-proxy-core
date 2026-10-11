package content

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/metacubex/mihomo/mobile/internal/jsonvalue"
)

func vmessScalar(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	default:
		return "", false
	}
}

func parseVMess(line string) (node map[string]any, name, protocol, code string) {
	protocol = "vmess"
	code = "ENTRY_LINK_INVALID"
	payload := line[strings.Index(line, "://")+3:]
	decoded, err := decodeBase64(payload)
	if err != nil || !utf8.Valid(decoded) || len(decoded) > MaxInputBytes {
		return
	}
	if err := jsonvalue.Validate(decoded); err != nil {
		if errors.Is(err, jsonvalue.ErrDuplicate) {
			code = "ENTRY_PARAMETER_DUPLICATE"
		}
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.UseNumber()
	var source map[string]any
	if decoder.Decode(&source) != nil || source == nil {
		return
	}
	for key := range source {
		switch key {
		case "v", "ps", "add", "port", "id", "aid", "scy", "security", "net", "type", "host", "path", "tls", "sni", "alpn", "fp", "allowInsecure":
		default:
			code = "ENTRY_PARAMETER_UNSUPPORTED"
			return
		}
	}
	text := make(map[string]string)
	for key, value := range source {
		if key == "allowInsecure" {
			continue
		}
		v, ok := vmessScalar(value)
		if !ok {
			code = "ENTRY_PARAMETER_INVALID"
			return
		}
		text[key] = v
	}
	if version := text["v"]; version != "" && version != "2" {
		code = "ENTRY_PARAMETER_UNSUPPORTED"
		return
	}
	name = text["ps"]
	port, err := strconv.Atoi(text["port"])
	if err != nil {
		return
	}
	aid := 0
	if value, present := text["aid"]; present {
		aid, err = strconv.Atoi(value)
		if err != nil {
			return
		}
	}
	cipher := text["scy"]
	if value, present := text["security"]; present {
		if _, duplicate := text["scy"]; duplicate {
			code = "ENTRY_PARAMETER_DUPLICATE"
			return
		}
		cipher = value
	}
	if cipher == "" {
		cipher = "auto"
	}
	node = map[string]any{"name": "selected-node", "type": "vmess", "server": text["add"], "port": port, "uuid": text["id"], "alterId": aid, "cipher": cipher, "udp": true}
	switch text["tls"] {
	case "", "none":
		node["tls"] = false
	case "tls":
		node["tls"] = true
	default:
		code = "ENTRY_SECURITY_UNSUPPORTED"
		return
	}
	q := url.Values{}
	for _, key := range []string{"host", "path", "sni", "alpn", "fp"} {
		if value, present := text[key]; present && value != "" {
			q.Set(key, value)
		}
	}
	if network := text["net"]; network != "" {
		q.Set("type", network)
	}
	if header := text["type"]; header != "" && header != "none" {
		q.Set("headerType", header)
	}
	if value, present := source["allowInsecure"]; present {
		switch flag := value.(type) {
		case bool:
			q.Set("allowInsecure", strconv.FormatBool(flag))
		case string:
			q.Set("allowInsecure", flag)
		default:
			code = "ENTRY_PARAMETER_INVALID"
			return
		}
	}
	if code = applyTLSQuery(node, q, "servername"); code != "" {
		return
	}
	code = applyTransport(node, q)
	return
}
