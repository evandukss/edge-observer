package observer

import "testing"

func TestZoneIsObserver(t *testing.T) {
	if Zone != "observer" {
		t.Fatalf("Zone = %q, want %q", Zone, "observer")
	}
}
