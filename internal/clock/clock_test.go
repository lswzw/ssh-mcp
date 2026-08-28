package clock

import "testing"

func TestNowUsesBeijingTime(t *testing.T) {
	value := Now()
	_, offset := value.Zone()
	if offset != 8*60*60 {
		t.Fatalf("Now() offset = %d, want +08:00", offset)
	}
}
