package paths

import (
	"errors"
	"fmt"
	"os"
)

const runtimeDirectoryName = ".ssh-mcp-runtime"

type Roots struct {
	ConfigDir  string
	RuntimeDir string
}

func Default() (Roots, error) {
	executable, err := os.Executable()
	if err != nil {
		return Roots{}, fmt.Errorf("resolve ssh-mcp executable: %w", err)
	}

	return defaultRoots(executable)
}

func defaultRoots(executable string) (Roots, error) {
	if executable == "" {
		return Roots{}, errors.New("ssh-mcp executable path is empty")
	}
	return platformDefaultRoots(executable)
}

func Prepare(configDir, runtimeDir string) (Roots, error) {
	if err := EnsureDirectory(configDir); err != nil {
		return Roots{}, fmt.Errorf("prepare config directory: %w", err)
	}
	if err := EnsureDirectory(runtimeDir); err != nil {
		return Roots{}, fmt.Errorf("prepare runtime directory: %w", err)
	}

	return Roots{ConfigDir: configDir, RuntimeDir: runtimeDir}, nil
}

// EnsureRegularFile verifies that path is a regular, non-symbolic-link file.
// It intentionally leaves the existing file's permissions unchanged.
func EnsureRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("file must be a regular file")
	}

	return nil
}

// EnsureDirectory creates path when needed and verifies that it is a real
// directory. New directories use the platform's ordinary default creation
// behavior, including the process umask where applicable.
func EnsureDirectory(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	if err := os.MkdirAll(path, 0o777); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("directory must not be a symbolic link")
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	return nil
}

// CreateTemp creates a temporary file with the platform's ordinary default
// file mode. The file remains open so callers can write and sync it before
// replacing a target.
func CreateTemp(directory, pattern string) (*os.File, error) {
	if err := EnsureDirectory(directory); err != nil {
		return nil, err
	}
	return createTemp(directory, pattern)
}

// ReplaceFile replaces destination with source using the strongest
// platform-native replacement operation available. Callers should keep both
// paths in the same directory when they require an atomic replacement.
func ReplaceFile(source, destination string) error {
	if source == "" || destination == "" {
		return errors.New("source and destination paths are required")
	}
	return platformReplaceFile(source, destination)
}

// SyncDirectory persists directory metadata where the platform exposes a
// directory-sync primitive. Windows has no equivalent directory fsync; its
// replacement backend uses write-through semantics and this function is a
// documented no-op there.
func SyncDirectory(path string) error {
	if path == "" {
		return errors.New("directory path is required")
	}
	return platformSyncDirectory(path)
}
