//go:build aix || android || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris

package app

import (
	"os"
	"strconv"
)

func platformAuditUserFallback() string {
	if uid := os.Getuid(); uid >= 0 {
		return strconv.Itoa(uid)
	}
	return "unknown"
}
