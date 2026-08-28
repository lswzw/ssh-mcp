//go:build darwin || windows

package paths

import (
	"path/filepath"
)

// Keep the state and runtime files beside the executable on every supported
// platform so the complete installation directory can be moved as one unit.
func platformDefaultRoots(executable string) (Roots, error) {
	configDir := filepath.Dir(executable)
	return Prepare(configDir, filepath.Join(configDir, runtimeDirectoryName))
}
