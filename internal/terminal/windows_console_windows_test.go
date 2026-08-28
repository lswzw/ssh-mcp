//go:build windows

package terminal

import (
	"os/exec"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsConsoleLauncherStartsTargetWithoutCmd(t *testing.T) {
	launcher := newWindowsConsoleLauncher("cmd.exe")
	var started *exec.Cmd
	launcher.start = func(command *exec.Cmd) error {
		started = command
		return nil
	}

	program := `C:\\private&path\\ssh-mcp.exe`
	args := []string{"tui", "--socket", `C:\\private&path\\control.sock`, "--token", "token"}
	if err := launcher.Start(program, args...); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if started == nil || started.Path != program {
		t.Fatalf("started path = %#v, want %q", started, program)
	}
	if want := append([]string{program}, args...); !reflect.DeepEqual(started.Args, want) {
		t.Fatalf("started args = %#v, want %#v", started.Args, want)
	}
	if started.SysProcAttr == nil || started.SysProcAttr.CreationFlags&windows.CREATE_NEW_CONSOLE == 0 {
		t.Fatalf("SysProcAttr = %#v, want CREATE_NEW_CONSOLE", started.SysProcAttr)
	}
}
