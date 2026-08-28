package terminal

import (
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

func TestResolveUsesGNOMETerminalThenXTerminalEmulator(t *testing.T) {
	t.Parallel()

	launcher, err := resolveForOS("linux", "", func(name string) (string, error) {
		if name == "gnome-terminal" {
			return "/usr/bin/gnome-terminal", nil
		}
		return "", errors.New("not found")
	})
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if launcher.program != "/usr/bin/gnome-terminal" || !reflect.DeepEqual(launcher.prefix, []string{"--"}) {
		t.Fatalf("GNOME launcher = %#v", launcher)
	}

	launcher, err = resolveForOS("linux", "", func(name string) (string, error) {
		if name == "x-terminal-emulator" {
			return "/usr/bin/x-terminal-emulator", nil
		}
		return "", errors.New("not found")
	})
	if err != nil {
		t.Fatalf("resolve() fallback error = %v", err)
	}
	if launcher.program != "/usr/bin/x-terminal-emulator" || !reflect.DeepEqual(launcher.prefix, []string{"-e"}) {
		t.Fatalf("fallback launcher = %#v", launcher)
	}
}

func TestResolveDarwinUsesAppleScriptTerminalLauncher(t *testing.T) {
	t.Parallel()

	launcher, err := resolveForOS("darwin", "", func(name string) (string, error) {
		if name == "osascript" {
			return "/usr/bin/osascript", nil
		}
		return "", errors.New("not found")
	})
	if err != nil {
		t.Fatalf("resolve darwin error = %v", err)
	}
	if launcher.program != "/usr/bin/osascript" || launcher.mode != launcherMacOSTerminal {
		t.Fatalf("darwin launcher = %#v", launcher)
	}

	var started *exec.Cmd
	launcher.start = func(command *exec.Cmd) error {
		started = command
		return nil
	}
	if err := launcher.StartWithEnvironment([]string{"DISPLAY=:1", "SECRET=must-not-leak"}, "/Applications/ssh mcp", "tui", "a'b"); err != nil {
		t.Fatalf("StartWithEnvironment() error = %v", err)
	}
	if started == nil || started.Path != "/usr/bin/osascript" {
		t.Fatalf("started command = %#v", started)
	}
	if len(started.Args) != 3 || started.Args[1] != "-e" {
		t.Fatalf("osascript args = %#v", started.Args)
	}
	wantScript := `tell application "Terminal" to do script "env 'DISPLAY=:1' '/Applications/ssh mcp' 'tui' 'a'\"'\"'b'"`
	if started.Args[2] != wantScript {
		t.Fatalf("osascript script = %q, want %q", started.Args[2], wantScript)
	}
}

func TestResolveCustomLauncherAndBuildsDirectCommand(t *testing.T) {
	t.Parallel()

	launcher, err := resolve("custom-terminal --hold {command}", func(string) (string, error) {
		return "", errors.New("lookup should not be called")
	})
	if err != nil {
		t.Fatalf("resolve custom error = %v", err)
	}
	if launcher.program != "custom-terminal" || !reflect.DeepEqual(launcher.prefix, []string{"--hold"}) {
		t.Fatalf("custom launcher = %#v", launcher)
	}

	var started *exec.Cmd
	launcher.start = func(command *exec.Cmd) error {
		started = command
		return nil
	}
	if err := launcher.Start("/opt/ssh-mcp", "tui", "--socket", "/tmp/control.sock"); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if started == nil || started.Path != "custom-terminal" {
		t.Fatalf("started command = %#v", started)
	}
	if want := []string{"custom-terminal", "--hold", "/opt/ssh-mcp", "tui", "--socket", "/tmp/control.sock"}; !reflect.DeepEqual(started.Args, want) {
		t.Fatalf("command args = %#v, want %#v", started.Args, want)
	}
}

func TestResolveCustomLauncherPreservesQuotedWindowsPath(t *testing.T) {
	t.Parallel()

	launcher, err := resolve(`"C:\Program Files\Windows Terminal\wt.exe" -w 0 new-tab {command}`, func(string) (string, error) {
		return "", errors.New("lookup should not be called")
	})
	if err != nil {
		t.Fatalf("resolve quoted custom launcher error = %v", err)
	}
	if launcher.program != `C:\Program Files\Windows Terminal\wt.exe` {
		t.Fatalf("launcher program = %q", launcher.program)
	}
	if want := []string{"-w", "0", "new-tab"}; !reflect.DeepEqual(launcher.prefix, want) {
		t.Fatalf("launcher prefix = %#v, want %#v", launcher.prefix, want)
	}
}

func TestLauncherMergesProvidedEnvironment(t *testing.T) {
	t.Parallel()

	launcher := newLauncher("custom-terminal", []string{"--"})
	var started *exec.Cmd
	launcher.start = func(command *exec.Cmd) error {
		started = command
		return nil
	}
	if err := launcher.StartWithEnvironment([]string{"DISPLAY=:1", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"}, "/opt/ssh-mcp", "tui"); err != nil {
		t.Fatalf("StartWithEnvironment() error = %v", err)
	}
	if started == nil {
		t.Fatal("terminal command was not started")
	}
	for _, want := range []string{"DISPLAY=:1", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"} {
		if !containsEnvironment(started.Env, want) {
			t.Fatalf("terminal environment = %#v, missing %q", started.Env, want)
		}
	}
}

func TestDefaultCandidatesCoverSupportedHosts(t *testing.T) {
	t.Parallel()

	for _, goos := range []string{"linux", "darwin", "windows"} {
		if candidates := defaultCandidates(goos); len(candidates) == 0 {
			t.Fatalf("defaultCandidates(%q) returned no terminal candidates", goos)
		}
	}
}

func TestResolveWindowsCmdFallbackUsesDirectConsoleMode(t *testing.T) {
	t.Parallel()

	launcher, err := resolveForOS("windows", "", func(name string) (string, error) {
		if name == "cmd.exe" {
			return `C:\\Windows\\System32\\cmd.exe`, nil
		}
		return "", errors.New("not found")
	})
	if err != nil {
		t.Fatalf("resolve Windows fallback error = %v", err)
	}
	if launcher.mode != launcherWindowsConsole {
		t.Fatalf("Windows fallback mode = %d, want launcherWindowsConsole", launcher.mode)
	}
	if len(launcher.prefix) != 0 {
		t.Fatalf("Windows fallback prefix = %#v, want no cmd.exe command", launcher.prefix)
	}
}

func TestConfiguredCmdUsesDirectConsoleMode(t *testing.T) {
	t.Parallel()

	launcher, err := resolveForOS("windows", "cmd", func(string) (string, error) {
		return "", errors.New("lookup should not be called")
	})
	if err != nil {
		t.Fatalf("resolve cmd error = %v", err)
	}
	if launcher.mode != launcherWindowsConsole {
		t.Fatalf("configured cmd mode = %d, want launcherWindowsConsole", launcher.mode)
	}
}

func containsEnvironment(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestResolveAcceptsDocumentedSimpleTerminalNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		configured string
		prefix     []string
	}{
		{configured: "gnome-terminal", prefix: []string{"--"}},
		{configured: "/usr/bin/gnome-terminal", prefix: []string{"--"}},
		{configured: "x-terminal-emulator", prefix: []string{"-e"}},
	}
	for _, test := range tests {
		launcher, err := resolve(test.configured, func(string) (string, error) {
			return "", errors.New("lookup should not be called")
		})
		if err != nil {
			t.Fatalf("resolve(%q) error = %v", test.configured, err)
		}
		if !reflect.DeepEqual(launcher.prefix, test.prefix) {
			t.Fatalf("resolve(%q) prefix = %#v, want %#v", test.configured, launcher.prefix, test.prefix)
		}
	}
}

func TestResolveRejectsUnsafeOrIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	for _, configured := range []string{
		"custom-terminal",
		"custom-terminal ; {command}",
		"{command}",
		`"unterminated {command}`,
		"cmd.exe /c {command}",
	} {
		if _, err := resolve(configured, func(string) (string, error) { return "", nil }); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("resolve(%q) error = %v, want ErrInvalidConfiguration", configured, err)
		}
	}
}
