//go:build !linux && !darwin && !windows

package paths

import "path/filepath"

// Keep unsupported operating systems buildable with the historical layout.
// They must opt into a reviewed platform backend before being advertised.
func platformDefaultRoots(executable string) (Roots, error) {
	configDir := filepath.Dir(executable)
	return Prepare(configDir, filepath.Join(configDir, runtimeDirectoryName))
}
