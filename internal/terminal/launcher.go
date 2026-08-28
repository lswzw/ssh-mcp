// Package terminal starts the independent TUI process. Direct launchers use
// structured arguments; the macOS Terminal adapter quotes the command before
// handing it to Terminal's interactive shell. A configured terminal command
// uses a literal {command} placeholder.
package terminal

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

var (
	ErrNoTerminal           = errors.New("no supported terminal emulator was found")
	ErrInvalidConfiguration = errors.New("invalid terminal launcher configuration")
)

type Launcher struct {
	program string
	prefix  []string
	mode    launcherMode
	start   func(*exec.Cmd) error
}

type launcherMode uint8

const (
	launcherDirect launcherMode = iota
	launcherMacOSTerminal
	launcherWindowsConsole
)

func Resolve(configured string) (*Launcher, error) {
	return resolve(configured, exec.LookPath)
}

func resolve(configured string, lookPath func(string) (string, error)) (*Launcher, error) {
	return resolveForOS(runtime.GOOS, configured, lookPath)
}

func resolveForOS(goos, configured string, lookPath func(string) (string, error)) (*Launcher, error) {
	if strings.TrimSpace(configured) != "" {
		return parseConfiguredLauncher(configured, goos)
	}
	for _, candidate := range defaultCandidates(goos) {
		if program, err := lookPath(candidate.program); err == nil {
			launcher := newLauncher(program, candidate.prefix)
			launcher.mode = candidate.mode
			return launcher, nil
		}
	}
	return nil, ErrNoTerminal
}

type launcherCandidate struct {
	program string
	prefix  []string
	mode    launcherMode
}

func defaultCandidates(goos string) []launcherCandidate {
	switch goos {
	case "darwin":
		return []launcherCandidate{{program: "osascript", mode: launcherMacOSTerminal}}
	case "windows":
		// Windows Terminal is preferred. When it is unavailable, probing cmd.exe
		// establishes that the command processor is present, while the launcher
		// creates the TUI process directly in a new console. Do not route its
		// variable path and token arguments through cmd.exe /c.
		return []launcherCandidate{{program: "wt.exe", prefix: []string{}}, {program: "cmd.exe", mode: launcherWindowsConsole}}
	default:
		return []launcherCandidate{{program: "gnome-terminal", prefix: []string{"--"}}, {program: "x-terminal-emulator", prefix: []string{"-e"}}}
	}
}

func (l *Launcher) Start(program string, args ...string) error {
	return l.StartWithEnvironment(nil, program, args...)
}

func (l *Launcher) StartWithEnvironment(environment []string, program string, args ...string) error {
	if l == nil || l.program == "" || program == "" || l.start == nil {
		return ErrInvalidConfiguration
	}
	var command *exec.Cmd
	switch l.mode {
	case launcherDirect:
		commandArgs := make([]string, 0, len(l.prefix)+1+len(args))
		commandArgs = append(commandArgs, l.prefix...)
		commandArgs = append(commandArgs, program)
		commandArgs = append(commandArgs, args...)
		command = exec.Command(l.program, commandArgs...)
	case launcherMacOSTerminal:
		command = exec.Command(l.program, "-e", macOSTerminalScript(program, args, environment))
	case launcherWindowsConsole:
		// cmd.exe has its own command-line parser, so os/exec argument escaping
		// does not protect paths containing cmd metacharacters. CreateProcess with
		// CREATE_NEW_CONSOLE gives the fallback the same separate-window behavior
		// without introducing a command interpreter.
		command = exec.Command(program, args...)
		if err := configureWindowsConsole(command); err != nil {
			return err
		}
	default:
		return ErrInvalidConfiguration
	}
	if environment != nil {
		command.Env = mergedEnvironment(environment)
	}
	if err := l.start(command); err != nil {
		return fmt.Errorf("start TUI terminal: %w", err)
	}
	return nil
}

func newLauncher(program string, prefix []string) *Launcher {
	return &Launcher{program: program, prefix: prefix, start: func(command *exec.Cmd) error {
		return command.Start()
	}}
}

func newMacOSTerminalLauncher(program string) *Launcher {
	launcher := newLauncher(program, nil)
	launcher.mode = launcherMacOSTerminal
	return launcher
}

func newWindowsConsoleLauncher(program string) *Launcher {
	launcher := newLauncher(program, nil)
	launcher.mode = launcherWindowsConsole
	return launcher
}

func parseConfiguredLauncher(configured, goos string) (*Launcher, error) {
	if strings.ContainsAny(configured, ";|&$`<>\n\r") {
		return nil, ErrInvalidConfiguration
	}
	parts, err := splitLauncherConfiguration(configured)
	if err != nil {
		return nil, err
	}
	if len(parts) == 1 {
		base := strings.ToLower(filepath.Base(parts[0]))
		switch base {
		case "gnome-terminal":
			return newLauncher(parts[0], []string{"--"}), nil
		case "x-terminal-emulator":
			return newLauncher(parts[0], []string{"-e"}), nil
		case "open":
			if goos == "darwin" {
				return newMacOSTerminalLauncher("osascript"), nil
			}
			return newLauncher(parts[0], []string{"-a", "Terminal"}), nil
		case "osascript":
			if goos == "darwin" {
				return newMacOSTerminalLauncher(parts[0]), nil
			}
			return newLauncher(parts[0], nil), nil
		case "wt", "wt.exe":
			return newLauncher(parts[0], nil), nil
		case "cmd", "cmd.exe":
			return newWindowsConsoleLauncher(parts[0]), nil
		default:
			return nil, ErrInvalidConfiguration
		}
	}
	if parts[0] == "{command}" {
		return nil, ErrInvalidConfiguration
	}
	base := strings.ToLower(filepath.Base(parts[0]))
	// A cmd.exe prefix would restore shell parsing for the untrusted-at-launch
	// executable path, socket path, and capability token. The supported simple
	// cmd shorthand selects launcherWindowsConsole above instead.
	if base == "cmd" || base == "cmd.exe" {
		return nil, ErrInvalidConfiguration
	}
	placeholder := -1
	for index, part := range parts {
		if part == "{command}" {
			if placeholder != -1 {
				return nil, ErrInvalidConfiguration
			}
			placeholder = index
		}
	}
	if placeholder == -1 || placeholder != len(parts)-1 {
		return nil, ErrInvalidConfiguration
	}
	return newLauncher(parts[0], parts[1:placeholder]), nil
}

func macOSTerminalScript(program string, args, environment []string) string {
	parts := make([]string, 0, len(args)+len(environment)+2)
	for _, entry := range terminalEnvironmentAssignments(environment) {
		if len(parts) == 0 {
			parts = append(parts, "env")
		}
		parts = append(parts, shellQuote(entry))
	}
	parts = append(parts, shellQuote(program))
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	command := strings.Join(parts, " ")
	return `tell application "Terminal" to do script "` + escapeAppleScriptString(command) + `"`
}

func terminalEnvironmentAssignments(environment []string) []string {
	allowed := map[string]struct{}{
		"DISPLAY":                  {},
		"WAYLAND_DISPLAY":          {},
		"XAUTHORITY":               {},
		"DBUS_SESSION_BUS_ADDRESS": {},
		"XDG_RUNTIME_DIR":          {},
		"TERM":                     {},
		"TERM_PROGRAM":             {},
		"WT_SESSION":               {},
	}
	values := make([]string, 0, len(allowed))
	seen := make(map[string]struct{}, len(allowed))
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, ok := allowed[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok || strings.ContainsRune(value, '\x00') {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, key+"="+value)
	}
	return values
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func escapeAppleScriptString(value string) string {
	var escaped strings.Builder
	escaped.Grow(len(value))
	for _, character := range value {
		switch character {
		case '\\':
			escaped.WriteString(`\\`)
		case '"':
			escaped.WriteString(`\"`)
		case '\r', '\n':
			escaped.WriteByte(' ')
		default:
			escaped.WriteRune(character)
		}
	}
	return escaped.String()
}

// splitLauncherConfiguration accepts a small, shell-free command-line
// language. Quotes group paths containing spaces; backslashes escape only a
// quote, a backslash, or whitespace so Windows paths remain intact.
func splitLauncherConfiguration(value string) ([]string, error) {
	runes := []rune(value)
	parts := make([]string, 0, 4)
	var current strings.Builder
	var quote rune
	token := false
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		if character == '\x00' || unicode.IsControl(character) {
			return nil, ErrInvalidConfiguration
		}
		if quote != 0 {
			if character == quote {
				quote = 0
				token = true
				continue
			}
			if character == '\\' && quote == '"' && index+1 < len(runes) && launcherEscapeTarget(runes[index+1]) {
				index++
				current.WriteRune(runes[index])
				token = true
				continue
			}
			current.WriteRune(character)
			token = true
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			token = true
			continue
		}
		if unicode.IsSpace(character) {
			if token {
				parts = append(parts, current.String())
				current.Reset()
				token = false
			}
			continue
		}
		if character == '\\' && index+1 < len(runes) && launcherEscapeTarget(runes[index+1]) {
			index++
			current.WriteRune(runes[index])
			token = true
			continue
		}
		current.WriteRune(character)
		token = true
	}
	if quote != 0 || token && current.Len() == 0 {
		return nil, ErrInvalidConfiguration
	}
	if token {
		parts = append(parts, current.String())
	}
	if len(parts) == 0 {
		return nil, ErrInvalidConfiguration
	}
	return parts, nil
}

func launcherEscapeTarget(character rune) bool {
	return character == '\\' || character == '\'' || character == '"' || unicode.IsSpace(character)
}

func mergedEnvironment(override []string) []string {
	values := append([]string(nil), os.Environ()...)
	positions := make(map[string]int, len(values))
	for index, entry := range values {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			positions[key] = index
		}
	}
	for _, entry := range override {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		if index, ok := positions[key]; ok {
			values[index] = entry
			continue
		}
		positions[key] = len(values)
		values = append(values, entry)
	}
	return values
}
