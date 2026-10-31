package policy

import "github.com/metacubex/mihomo/mobile/observation"

func init() {
	if err := observation.Configure(observation.Limits{ReplyBytes: 1 << 20, ReplyValues: 65536, Connections: 16, DNSQueries: 16, DNSAnswers: 4, ResourceEvents: 128}); err != nil {
		panic(err)
	}
}
