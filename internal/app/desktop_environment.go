package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ssh-mcp/internal/paths"
)

const desktopEnvironmentFileName = "desktop-environment.json"

type desktopEnvironment struct {
	Display               string `json:"display,omitempty"`
	WaylandDisplay        string `json:"wayland_display,omitempty"`
	XAuthority            string `json:"xauthority,omitempty"`
	DBusSessionBusAddress string `json:"dbus_session_bus_address,omitempty"`
	XDGRuntimeDir         string `json:"xdg_runtime_dir,omitempty"`
	Term                  string `json:"term,omitempty"`
	TermProgram           string `json:"term_program,omitempty"`
	WTSession             string `json:"wt_session,omitempty"`
	ComSpec               string `json:"comspec,omitempty"`
}

func desktopEnvironmentFromOS(getenv func(string) string) desktopEnvironment {
	return desktopEnvironment{
		Display:               getenv("DISPLAY"),
		WaylandDisplay:        getenv("WAYLAND_DISPLAY"),
		XAuthority:            getenv("XAUTHORITY"),
		DBusSessionBusAddress: getenv("DBUS_SESSION_BUS_ADDRESS"),
		XDGRuntimeDir:         getenv("XDG_RUNTIME_DIR"),
		Term:                  getenv("TERM"),
		TermProgram:           getenv("TERM_PROGRAM"),
		WTSession:             getenv("WT_SESSION"),
		ComSpec:               firstNonEmpty(getenv("ComSpec"), getenv("COMSPEC")),
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (e desktopEnvironment) empty() bool {
	return e.Display == "" && e.WaylandDisplay == "" && e.XAuthority == "" && e.DBusSessionBusAddress == "" && e.XDGRuntimeDir == "" && e.Term == "" && e.TermProgram == "" && e.WTSession == "" && e.ComSpec == ""
}

func (e desktopEnvironment) commandEnvironment(base []string) []string {
	values := e.values()
	result := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if ok && isDesktopEnvironmentKey(key) {
			continue
		}
		result = append(result, entry)
	}
	for _, entry := range values {
		if entry != "" {
			result = append(result, entry)
		}
	}
	return result
}

func (e desktopEnvironment) values() []string {
	return []string{
		desktopEnvironmentValue("DISPLAY", e.Display),
		desktopEnvironmentValue("WAYLAND_DISPLAY", e.WaylandDisplay),
		desktopEnvironmentValue("XAUTHORITY", e.XAuthority),
		desktopEnvironmentValue("DBUS_SESSION_BUS_ADDRESS", e.DBusSessionBusAddress),
		desktopEnvironmentValue("XDG_RUNTIME_DIR", e.XDGRuntimeDir),
		desktopEnvironmentValue("TERM", e.Term),
		desktopEnvironmentValue("TERM_PROGRAM", e.TermProgram),
		desktopEnvironmentValue("WT_SESSION", e.WTSession),
		desktopEnvironmentValue("ComSpec", e.ComSpec),
	}
}

func desktopEnvironmentValue(key, value string) string {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return ""
	}
	return key + "=" + value
}

func isDesktopEnvironmentKey(key string) bool {
	switch key {
	case "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "TERM", "TERM_PROGRAM", "WT_SESSION", "ComSpec", "COMSPEC":
		return true
	default:
		return false
	}
}

func loadDesktopEnvironment(path string) (desktopEnvironment, error) {
	if err := paths.EnsureRegularFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return desktopEnvironment{}, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return desktopEnvironment{}, nil
	}
	if err != nil {
		return desktopEnvironment{}, fmt.Errorf("open desktop environment: %w", err)
	}
	defer file.Close()
	var environment desktopEnvironment
	if err := json.NewDecoder(io.LimitReader(file, 8<<10)).Decode(&environment); err != nil {
		return desktopEnvironment{}, fmt.Errorf("decode desktop environment: %w", err)
	}
	return environment, nil
}

func saveDesktopEnvironment(path string, environment desktopEnvironment) error {
	if environment.empty() {
		return nil
	}
	encoded, err := json.Marshal(environment)
	if err != nil {
		return fmt.Errorf("encode desktop environment: %w", err)
	}
	directory := filepath.Dir(path)
	if err := paths.EnsureDirectory(directory); err != nil {
		return fmt.Errorf("prepare desktop environment directory: %w", err)
	}
	temporary, err := paths.CreateTemp(directory, ".desktop-environment-*")
	if err != nil {
		return fmt.Errorf("create desktop environment file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write desktop environment: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync desktop environment: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close desktop environment: %w", err)
	}
	if err := paths.ReplaceFile(temporaryPath, path); err != nil {
		return fmt.Errorf("replace desktop environment: %w", err)
	}
	if err := paths.SyncDirectory(directory); err != nil {
		return fmt.Errorf("sync desktop environment directory: %w", err)
	}
	return paths.EnsureRegularFile(path)
}
