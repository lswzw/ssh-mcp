//go:build windows

package hardening

// DisableCoreDumps is intentionally a no-op on Windows. Windows Error
// Reporting and dump collection are controlled by system policy rather than
// a per-process RLIMIT_CORE equivalent. The process never opts into local
// dump creation; deployment policy must control WER collection separately.
func DisableCoreDumps() error {
	return nil
}
