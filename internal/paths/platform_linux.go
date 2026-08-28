//go:build linux

package paths

import (
	"path/filepath"
)

func platformDefaultRoots(executable string) (Roots, error) {
	configDir := filepath.Dir(executable)
	return Prepare(configDir, filepath.Join(configDir, runtimeDirectoryName))
}
