//go:build !windows

package tui

import tea "charm.land/bubbletea/v2"

func platformProgramOptions() ([]tea.ProgramOption, func(), error) {
	return nil, func() {}, nil
}
