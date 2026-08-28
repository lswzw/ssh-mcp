package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrepareCreatesDirectories(t *testing.T) {
	root := t.TempDir()
	roots, err := Prepare(filepath.Join(root, "config"), filepath.Join(root, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	assertDirectory(t, roots.ConfigDir)
	assertDirectory(t, roots.RuntimeDir)
}

func TestDefaultRootsUseExecutableDirectory(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "service", "ssh-mcp")

	roots, err := defaultRoots(executable)
	if err != nil {
		t.Fatalf("defaultRoots() error = %v", err)
	}
	if want := filepath.Dir(executable); roots.ConfigDir != want {
		t.Errorf("ConfigDir = %q, want executable directory %q", roots.ConfigDir, want)
	}
	if want := filepath.Join(filepath.Dir(executable), runtimeDirectoryName); roots.RuntimeDir != want {
		t.Errorf("RuntimeDir = %q, want %q", roots.RuntimeDir, want)
	}
}

func TestEnsureRegularFileAcceptsExistingFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "credentials.db")
	if err := os.WriteFile(file, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := EnsureRegularFile(file); err != nil {
		t.Fatalf("EnsureRegularFile() error = %v", err)
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not expose POSIX permission bits through os.FileMode; the
	// platform reports ordinary writable files as 0666 regardless of creation
	// mode. Unix platforms retain and can assert the existing mode exactly.
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o644 {
			t.Errorf("file mode = %04o, want existing mode 0644 unchanged", got)
		}
	}
}

func TestReplaceFileReplacesDestinationAndRemovesSource(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ReplaceFile(source, destination); err != nil {
		t.Fatalf("ReplaceFile() error = %v", err)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source stat error = %v, want not exist", err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != "new" {
		t.Errorf("destination contents = %q, want new", got)
	}
	if err := SyncDirectory(directory); err != nil {
		t.Fatalf("SyncDirectory() error = %v", err)
	}
}

func assertDirectory(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("%q is not a directory", path)
	}
}
