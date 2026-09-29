package tui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"ssh-mcp/internal/control"
	"ssh-mcp/internal/store"
)

type languageTrackingCaller struct {
	lastMethod string
	lastParams any
}

func (c *languageTrackingCaller) Call(_ context.Context, method string, params any, _ any) error {
	c.lastMethod = method
	c.lastParams = params
	return nil
}

func TestTUILanguageToggle(t *testing.T) {
	t.Parallel()

	caller := &languageTrackingCaller{}
	model := NewModel(caller)

	// Default should be Chinese
	if model.lang != "zh" {
		t.Fatalf("initial lang = %q, want zh", model.lang)
	}
	view := model.View().Content
	if !strings.Contains(view, "e 语言") || !strings.Contains(view, "本地控制台") {
		t.Fatalf("initial dashboard does not contain Chinese text: %s", view)
	}

	// Press 'e' on Dashboard -> switch to English
	cmd := model.handleKey(tea.KeyPressMsg{Code: 'e', Text: "e"})
	if cmd == nil {
		t.Fatal("expected command from toggleLanguage")
	}
	_ = cmd() // Execute tea.Cmd
	if model.lang != "en" {
		t.Fatalf("after pressing e, lang = %q, want en", model.lang)
	}
	if model.notice != "Switched to English." {
		t.Fatalf("notice = %q, want %q", model.notice, "Switched to English.")
	}
	if caller.lastMethod != "tui.set_language" {
		t.Fatalf("caller method = %q, want tui.set_language", caller.lastMethod)
	}
	if p, ok := caller.lastParams.(control.SetTUILanguageParams); !ok || p.Language != "en" {
		t.Fatalf("caller params = %#v, want Language: en", caller.lastParams)
	}

	view = model.View().Content
	if !strings.Contains(view, "e Lang") || !strings.Contains(view, "ssh-mcp Console") {
		t.Fatalf("after toggle to English, view does not contain English text: %s", view)
	}

	// Press 'e' again -> switch back to Chinese
	cmd = model.handleKey(tea.KeyPressMsg{Code: 'e', Text: "e"})
	if cmd == nil {
		t.Fatal("expected command from toggleLanguage")
	}
	_ = cmd() // Execute tea.Cmd
	if model.lang != "zh" {
		t.Fatalf("after pressing e second time, lang = %q, want zh", model.lang)
	}
	if model.notice != "已切换为中文。" {
		t.Fatalf("notice = %q, want %q", model.notice, "已切换为中文。")
	}
	if p, ok := caller.lastParams.(control.SetTUILanguageParams); !ok || p.Language != "zh" {
		t.Fatalf("caller params = %#v, want Language: zh", caller.lastParams)
	}
}

func TestTUIRestoresLanguageFromStatus(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.beginUnlock()

	if model.input.Prompt != "主密码：" {
		t.Fatalf("initial unlock prompt = %q, want %q", model.input.Prompt, "主密码：")
	}

	// Receive status with Language: "en"
	model.applyRPC(rpcMsg{
		action: "status",
		value:  control.Status{Initialized: true, Unlocked: false, Language: "en"},
	})

	if model.lang != "en" {
		t.Fatalf("model lang after status = %q, want en", model.lang)
	}
	if model.input.Prompt != "Master Password: " {
		t.Fatalf("unlock prompt after status = %q, want %q", model.input.Prompt, "Master Password: ")
	}
}

func TestTUIEnglishRenderingAndLayout(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.setLanguage("en")
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})

	// 1. Dashboard
	dashboardView := model.View().Content
	if !strings.Contains(dashboardView, "u Unlock") || !strings.Contains(dashboardView, "t Targets") || !strings.Contains(dashboardView, "e Lang") {
		t.Fatalf("English dashboard missing keys: %s", dashboardView)
	}
	for _, line := range strings.Split(dashboardView, "\n") {
		if w := lipgloss.Width(line); w > 80 {
			t.Fatalf("English dashboard line exceeds 80 columns (width=%d): %q", w, line)
		}
	}

	// 2. Targets list
	model.screen = screenTargets
	model.targets = control.TargetsResult{
		SSH:       []store.SSHTarget{{IP: "192.0.2.10", Mode: store.SSHDirect, Enabled: true}},
		Databases: []store.DatabaseInstance{{Host: "192.0.2.20", Port: 3306, Engine: store.EngineMySQL, Enabled: false}},
	}
	targetsView := model.View().Content
	if !strings.Contains(targetsView, "Targets") || !strings.Contains(targetsView, "n Add SSH") || !strings.Contains(targetsView, "d Add DB") {
		t.Fatalf("English targets view missing keys: %s", targetsView)
	}
	for _, line := range strings.Split(targetsView, "\n") {
		if w := lipgloss.Width(line); w > 80 {
			t.Fatalf("English targets line exceeds 80 columns (width=%d): %q", w, line)
		}
	}

	// 3. SSH Form
	model.beginSSHForm(store.SSHTarget{IP: "192.0.2.10", Mode: store.SSHDirect, Enabled: true, AllowFileOperations: true})
	sshFormView := model.View().Content
	if !strings.Contains(sshFormView, "SSH Target") || !strings.Contains(sshFormView, "SSH Port") || !strings.Contains(sshFormView, "Login Username") {
		t.Fatalf("English SSH form view missing keys: %s", sshFormView)
	}
	for _, line := range strings.Split(sshFormView, "\n") {
		if w := lipgloss.Width(line); w > 80 {
			t.Fatalf("English SSH form line exceeds 80 columns (width=%d): %q", w, line)
		}
	}

	// 4. Database Form
	model.beginDatabaseForm(store.DatabaseInstance{Host: "192.0.2.20", Port: 5432, Engine: store.EnginePostgreSQL, Enabled: true})
	dbFormView := model.View().Content
	if !strings.Contains(dbFormView, "Database Instance") || !strings.Contains(dbFormView, "Read Username") || !strings.Contains(dbFormView, "Transport Policy") {
		t.Fatalf("English DB form view missing keys: %s", dbFormView)
	}
	for _, line := range strings.Split(dbFormView, "\n") {
		if w := lipgloss.Width(line); w > 80 {
			t.Fatalf("English DB form line exceeds 80 columns (width=%d): %q", w, line)
		}
	}

	// 5. Fingerprint confirmation
	model.pending = &pendingTargetSave{fingerprint: "SHA256:test-fingerprint"}
	model.screen = screenFingerprintConfirm
	fpView := model.View().Content
	if !strings.Contains(fpView, "SSH Host Fingerprint Confirmation") || !strings.Contains(fpView, "y Confirm & Test") {
		t.Fatalf("English fingerprint view missing keys: %s", fpView)
	}

	// 6. Delete confirmation
	model.deleting = &pendingTargetDelete{label: "SSH 192.0.2.10"}
	model.screen = screenTargetDeleteConfirm
	delView := model.View().Content
	if !strings.Contains(delView, "Delete Target") || !strings.Contains(delView, "y Delete") {
		t.Fatalf("English delete view missing keys: %s", delView)
	}

	// 7. Compact layout in English
	model.Update(tea.WindowSizeMsg{Width: 36, Height: 12})
	model.screen = screenDashboard
	compactView := model.View().Content
	if !strings.Contains(compactView, "u Unlock  t Targets  e Lang  q Quit") {
		t.Fatalf("English compact dashboard view = %s", compactView)
	}
	for _, line := range strings.Split(compactView, "\n") {
		if w := lipgloss.Width(line); w > 36 {
			t.Fatalf("English compact line exceeds 36 columns (width=%d): %q", w, line)
		}
	}
}
