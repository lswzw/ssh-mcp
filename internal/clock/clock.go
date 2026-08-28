// Package clock provides the service-wide civil time zone.
package clock

import "time"

var beijing = loadBeijing()

func loadBeijing() *time.Location {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err == nil {
		return location
	}
	return time.FixedZone("CST", 8*60*60)
}

// Now returns the current instant represented in Beijing time.
func Now() time.Time {
	return time.Now().In(beijing)
}

// InBeijing preserves an instant while representing it in Beijing time.
func InBeijing(value time.Time) time.Time {
	return value.In(beijing)
}
