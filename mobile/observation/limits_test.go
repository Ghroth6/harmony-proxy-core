package observation

import "testing"

func TestApplicationOwnsObservationRetention(t *testing.T) {
	if initial := Current(); initial.Connections != 0 || initial.DNSQueries != 0 || initial.ResourceEvents != 0 {
		t.Fatalf("core installed an application history policy: %+v", initial)
	}
	if err := Configure(Limits{ReplyBytes: -1, ReplyValues: 1}); err == nil {
		t.Fatal("accepted an unrepresentable reply envelope")
	}
	configured := Limits{ReplyBytes: 2 << 20, ReplyValues: 100000, Connections: 100, DNSQueries: 101, DNSAnswers: 20, ResourceEvents: 200}
	if err := Configure(configured); err != nil {
		t.Fatal(err)
	}
	if actual := Current(); actual != configured {
		t.Fatalf("application policy was clipped to former core values: %+v", actual)
	}
	if err := Configure(configured); err != nil {
		t.Fatalf("idempotent initialization failed: %v", err)
	}
	changed := configured
	changed.Connections++
	if err := Configure(changed); err == nil || Current() != configured {
		t.Fatal("changed observation policy after process initialization")
	}
}
