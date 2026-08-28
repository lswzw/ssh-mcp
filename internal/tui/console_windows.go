//go:build windows

package tui

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
)

// platformProgramOptions opens the console explicitly. The Windows terminal
// fallback creates a new console without inheriting the daemon's standard I/O;
// passing these handles to Bubble Tea keeps both rendering and input attached
// to that new console.
func platformProgramOptions() ([]tea.ProgramOption, func(), error) {
	input, output, err := tea.OpenTTY()
	if err != nil {
		return nil, nil, fmt.Errorf("open Windows console: %w", err)
	}
	return []tea.ProgramOption{tea.WithInput(input), tea.WithOutput(output)}, func() {
		_ = input.Close()
		_ = output.Close()
	}, nil
}
