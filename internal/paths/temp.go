package paths

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxTempCreateAttempts = 10000

// createTemp mirrors the collision behavior of os.CreateTemp while opening
// generated files with the normal default creation mode rather than any fixed
// mode. The operating system applies its ordinary defaults.
func createTemp(directory, pattern string) (*os.File, error) {
	if filepath.Base(pattern) != pattern {
		return nil, fmt.Errorf("temporary file pattern must not contain a path separator")
	}
	for attempt := 0; attempt < maxTempCreateAttempts; attempt++ {
		suffix, err := tempSuffix()
		if err != nil {
			return nil, fmt.Errorf("generate temporary file name: %w", err)
		}
		name := pattern
		if index := strings.LastIndex(pattern, "*"); index >= 0 {
			name = pattern[:index] + suffix + pattern[index+1:]
		} else {
			name = pattern + suffix
		}
		file, err := os.OpenFile(filepath.Join(directory, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	return nil, fmt.Errorf("create temporary file: too many name collisions")
}

func tempSuffix() (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}
