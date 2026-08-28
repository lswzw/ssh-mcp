package hardening

import "testing"

func TestDisableCoreDumpsIsAvailable(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Fatalf("DisableCoreDumps() error = %v", err)
	}
}
