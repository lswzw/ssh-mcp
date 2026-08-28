//go:build !windows

package hardening

import "syscall"

// DisableCoreDumps prevents process memory, which can contain decrypted
// credentials, from being written to a core file on Unix hosts.
func DisableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}
