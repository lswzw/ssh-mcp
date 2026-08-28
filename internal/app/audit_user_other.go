//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !hurd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris && !windows

package app

func platformAuditUserFallback() string { return "unknown" }
