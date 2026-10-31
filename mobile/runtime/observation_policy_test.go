package runtime

import O "github.com/metacubex/mihomo/mobile/observation"

// Host fixture of the application's published diagnostic envelope.
func init() {
	if err := O.Configure(O.Limits{ReplyBytes: 1 << 20, ReplyValues: 65536, Connections: 16, DNSQueries: 16, DNSAnswers: 4, ResourceEvents: 128}); err != nil {
		panic(err)
	}
}
