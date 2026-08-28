//go:build darwin || linux

package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func startDaemonProcess(ctx context.Context) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve ssh-mcp executable: %w", err)
	}
	startupReader, startupWriter, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create daemon startup pipe: %w", err)
	}
	defer startupReader.Close()
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		_ = startupWriter.Close()
		return fmt.Errorf("open daemon output sink: %w", err)
	}
	defer devNull.Close()
	command := exec.Command(executable, "daemon")
	command.Stdout = devNull
	command.Stderr = devNull
	command.ExtraFiles = []*os.File{startupWriter}
	command.Env = append(os.Environ(), daemonStartupFDEnv+"="+strconv.Itoa(daemonStartupChildFD))
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		_ = startupWriter.Close()
		return fmt.Errorf("start ssh-mcp daemon: %w", err)
	}
	if err := startupWriter.Close(); err != nil {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		return fmt.Errorf("close daemon startup pipe: %w", err)
	}
	if err := waitForDaemonStartup(ctx, startupReader); err != nil {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		return err
	}
	return command.Process.Release()
}
