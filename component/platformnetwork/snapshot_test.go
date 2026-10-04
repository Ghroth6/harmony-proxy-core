package platformnetwork

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func testSnapshot(generation uint64) Snapshot {
	return Snapshot{Generation: generation, NetworkID: 41, Online: true,
		DNS: []string{"192.0.2.53", "[2001:db8::53]:5353"},
		Interfaces: []Interface{{Name: "synthetic0", MTU: 1500, Up: true,
			Addresses: []string{"192.0.2.7/24", "2001:db8::7/64"},
			Routes:    []Route{{Destination: "0.0.0.0/0", Gateway: "192.0.2.1"}},
		}},
	}
}

func TestSnapshotValidationAndIsolation(t *testing.T) {
	var store store
	input := testSnapshot(1)
	if err := store.publish(input); err != nil {
		t.Fatal(err)
	}
	input.DNS[0] = "bad"
	input.Interfaces[0].Addresses[0] = "bad"
	input.Interfaces[0].Routes[0].Destination = "bad"
	saved := store.value.Load()
	if saved.DNS[0] != "192.0.2.53:53" || saved.Interfaces[0].Addresses[0] != "192.0.2.7/24" || saved.Interfaces[0].Routes[0].Destination != "0.0.0.0/0" {
		t.Fatalf("caller mutated published snapshot: %+v", saved)
	}
	copy := clone(*saved)
	copy.Interfaces[0].Addresses[0] = "changed"
	copy.Interfaces[0].Routes[0].Gateway = "changed"
	if saved.Interfaces[0].Addresses[0] != "192.0.2.7/24" || saved.Interfaces[0].Routes[0].Gateway != "192.0.2.1" {
		t.Fatal("read copy aliases state")
	}
	for name, mutate := range map[string]func(*Snapshot){
		"zero generation":                func(s *Snapshot) { s.Generation = 0 },
		"negative network":               func(s *Snapshot) { s.NetworkID = -1 },
		"offline with data":              func(s *Snapshot) { s.Online = false },
		"online without interface":       func(s *Snapshot) { s.Interfaces = nil },
		"bad DNS":                        func(s *Snapshot) { s.DNS[0] = "dns.example:53" },
		"zero DNS port":                  func(s *Snapshot) { s.DNS[0] = "192.0.2.53:0" },
		"bad address":                    func(s *Snapshot) { s.Interfaces[0].Addresses[0] = "192.0.2.1/33" },
		"bad route":                      func(s *Snapshot) { s.Interfaces[0].Routes[0].Destination = "invalid" },
		"wrong gateway family":           func(s *Snapshot) { s.Interfaces[0].Routes[0].Gateway = "2001:db8::1" },
		"unknown index encoded negative": func(s *Snapshot) { s.Interfaces[0].Index = -1 },
		"duplicate name":                 func(s *Snapshot) { s.Interfaces = append(s.Interfaces, s.Interfaces[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := testSnapshot(2)
			mutate(&bad)
			if err := store.publish(bad); err == nil {
				t.Fatal("accepted invalid snapshot")
			}
			if store.value.Load() != saved {
				t.Fatal("invalid input replaced state")
			}
		})
	}
	for _, generation := range []uint64{1, 1} {
		if err := store.publish(testSnapshot(generation)); !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("expected stale error: %v", err)
		}
	}
}

func TestConcurrentPublicationKeepsNewestWholeSnapshot(t *testing.T) {
	var store store
	var workers sync.WaitGroup
	for generation := uint64(1); generation <= 128; generation++ {
		workers.Add(1)
		go func(generation uint64) {
			defer workers.Done()
			snapshot := testSnapshot(generation)
			snapshot.NetworkID = int64(generation)
			snapshot.Interfaces[0].Name = fmt.Sprintf("net%d", generation)
			if err := store.publish(snapshot); err != nil && !errors.Is(err, ErrStaleGeneration) {
				t.Errorf("publish: %v", err)
			}
			observed := store.value.Load()
			if observed.NetworkID != int64(observed.Generation) || observed.Interfaces[0].Name != fmt.Sprintf("net%d", observed.Generation) {
				t.Error("torn snapshot")
			}
		}(generation)
	}
	workers.Wait()
	if store.value.Load().Generation != 128 {
		t.Fatal("older publication won")
	}
	if err := store.publish(Snapshot{Generation: 129}); err != nil {
		t.Fatal(err)
	}
	if store.value.Load().Online || len(store.value.Load().DNS) != 0 {
		t.Fatal("offline retained prior state")
	}
}
