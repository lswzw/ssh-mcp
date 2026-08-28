//go:build !windows

package paths

import "os"

func platformReplaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
