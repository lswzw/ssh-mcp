package tui

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"ssh-mcp/internal/control"
	"ssh-mcp/internal/ipc"
	"ssh-mcp/internal/store"
)

func TestTargetFormMasksPasswordsInRenderedView(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.beginSSHForm(store.SSHTarget{IP: "192.0.2.10", Mode: store.SSHDirect})
	model.form.fields[3].value = "local-password-must-not-render"
	view := model.View().Content
	if strings.Contains(view, "local-password-must-not-render") {
		t.Fatalf("password appeared in form view: %s", view)
	}
	if !strings.Contains(view, "密码") {
		t.Fatalf("form view does not identify password field: %s", view)
	}
}

func TestUnlockFlowMasksMasterPasswordAndReturnsToDashboard(t *testing.T) {
	t.Parallel()

	model := NewModel(&recordingCaller{})
	_, command := model.Update(tea.KeyPressMsg{Code: 'u', Text: "u"})
	if command != nil || model.screen != screenUnlock {
		t.Fatalf("after unlock key: screen = %v, command = %v", model.screen, command)
	}
	model.input.SetValue("master-password-must-not-render")
	if strings.Contains(model.View().Content, "master-password-must-not-render") {
		t.Fatalf("master password appeared in unlock view: %s", model.View().Content)
	}

	command = model.handleKey(tea.KeyPressMsg{Code: tea.KeyEnter})
	message := command()
	_, _ = model.Update(message)
	if model.screen != screenDashboard || !model.status.Unlocked {
		t.Fatalf("after unlock: screen = %v, status = %#v", model.screen, model.status)
	}
}

func TestUnlockInputRendersEveryPasswordCharacter(t *testing.T) {
	model := NewModel(nil)
	model.beginUnlock()

	for _, key := range []tea.KeyPressMsg{
		{Code: 'a', Text: "a"},
		{Code: 'b', Text: "b"},
		// Windows Console can omit Text for a printable key.
		{Code: 'c'},
		{Code: 'd', Text: "d"},
	} {
		model.handleKey(key)
	}
	if got := model.input.Value(); got != "abcd" {
		t.Fatalf("input value = %q, want all printable keys", got)
	}
	if got := strings.Count(model.input.View(), "*"); got != 4 {
		t.Fatalf("masked character count = %d, want 4; view=%q", got, model.input.View())
	}
}

func TestInputReportsCursorAtRenderedInputLine(t *testing.T) {
	model := NewModel(nil)
	model.beginUnlock()
	model.input.SetValue("abcd")

	view := model.View()
	if view.Cursor == nil {
		t.Fatal("unlock view did not report a terminal cursor")
	}
	if got, want := view.Cursor.Position.X, lipgloss.Width(model.input.Prompt)+4; got != want {
		t.Fatalf("unlock cursor x = %d, want %d", got, want)
	}
	if got, want := view.Cursor.Position.Y, 3; got != want {
		t.Fatalf("unlock cursor y = %d, want %d", got, want)
	}
	if model.input.VirtualCursor() {
		t.Fatal("unlock input should use the terminal cursor")
	}

	model.beginSSHForm(store.SSHTarget{IP: "192.0.2.10", Mode: store.SSHDirect})
	model.form.index = 3
	model.loadCurrentField()
	model.input.SetValue("secret")
	view = model.View()
	if view.Cursor == nil {
		t.Fatal("form view did not report a terminal cursor")
	}
	if got, want := view.Cursor.Position.X, lipgloss.Width(inputLinePrefix)+lipgloss.Width(model.input.Prompt)+6; got != want {
		t.Fatalf("form cursor x = %d, want %d", got, want)
	}
	if got, want := view.Cursor.Position.Y, 7; got != want {
		t.Fatalf("form cursor y = %d, want %d", got, want)
	}

	model.beginMaintenance(maintenanceChangeMasterPassword)
	model.maintenance.index = 1
	model.loadMaintenanceField()
	model.input.SetValue("new-secret")
	view = model.View()
	if view.Cursor == nil {
		t.Fatal("maintenance view did not report a terminal cursor")
	}
	if got, want := view.Cursor.Position.Y, 5; got != want {
		t.Fatalf("maintenance cursor y = %d, want %d", got, want)
	}
}

func TestDashboardDescribesUKeyAsUnlock(t *testing.T) {
	t.Parallel()

	view := NewModel(nil).View().Content
	if !strings.Contains(view, "u 解锁") {
		t.Fatalf("dashboard does not describe u as unlock: %s", view)
	}
	if strings.Contains(view, "切换会话") {
		t.Fatalf("dashboard still describes session switching: %s", view)
	}
	if strings.Contains(view, "审计") {
		t.Fatalf("dashboard still exposes audit management: %s", view)
	}
}

func TestWindowResizeConstrainsInputsAndDegradesAlternateScreen(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	updated, command := model.Update(tea.WindowSizeMsg{Width: 32, Height: 7})
	if command != nil || updated != model {
		t.Fatalf("resize update = (%T, %v)", updated, command)
	}
	if model.input.Width() != 28 {
		t.Fatalf("narrow layout input width = %d", model.input.Width())
	}
	if model.View().AltScreen {
		t.Fatal("small terminal should not require alternate screen")
	}

	_, _ = model.Update(tea.WindowSizeMsg{Width: 3, Height: 5})
	if model.input.Width() != 1 {
		t.Fatalf("very narrow layout input width = %d", model.input.Width())
	}

	_, _ = model.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if model.input.Width() != defaultInputWidth {
		t.Fatalf("wide layout input width = %d", model.input.Width())
	}
	if !model.View().AltScreen {
		t.Fatal("normal terminal should use alternate screen")
	}
}

func TestInputLayoutAccountsForPromptAndHeightBounds(t *testing.T) {
	t.Parallel()

	prompt := "主密码："
	if got := textInputWidth(32, prompt, "> "); got <= 0 || got+contentHorizontalPad+lipgloss.Width(prompt)+lipgloss.Width("> ") > 32 {
		t.Fatalf("prompt-aware input width = %d, want positive width within viewport", got)
	}
	if got := textInputWidth(32, "远端路径：", "> "); got <= 0 {
		t.Fatalf("overwide prompt input width = %d, want 1", got)
	}
}

func TestCompactViewLinesFitNarrowViewport(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	_, _ = model.Update(tea.WindowSizeMsg{Width: 8, Height: 4})
	for _, line := range strings.Split(model.View().Content, "\n") {
		if width := lipgloss.Width(line); width > 8 {
			t.Fatalf("compact view line width = %d, want <= 8: %q", width, line)
		}
	}
}

func TestViewLinesFitMediumViewport(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	for _, width := range []int{48, 80} {
		_, _ = model.Update(tea.WindowSizeMsg{Width: width, Height: 20})
		for _, line := range strings.Split(model.View().Content, "\n") {
			if got := lipgloss.Width(line); got > width {
				t.Fatalf("viewport width %d produced line width %d: %q", width, got, line)
			}
		}
	}
}

func TestCompactTextNeverExceedsTinyViewport(t *testing.T) {
	t.Parallel()

	for width := 1; width <= 3; width++ {
		if got := compactText("abcdef", width); lipgloss.Width(got) > width {
			t.Fatalf("compactText width %d = %q (%d cells), want <= %d", width, got, lipgloss.Width(got), width)
		}
	}
}

func TestSSHSaveWaitsForExplicitFingerprintConfirmation(t *testing.T) {
	t.Parallel()

	client := &recordingCaller{fingerprint: "SHA256:target"}
	model := NewModel(client)
	model.status.Unlocked = true
	model.beginSSHForm(store.SSHTarget{IP: "192.0.2.10", Mode: store.SSHDirect, Enabled: true})
	model.form.fields[2].value = "ops"
	model.form.fields[3].value = "ssh-password"
	model.form.fields[4].value = "rm /data/.*, cat /etc/passwd, passwd.*"
	model.form.fields[5].value = "production SSH host"
	model.form.fields[6].value = "production"

	message := model.submitForm()()
	_, command := model.Update(message)
	if command != nil || model.screen != screenFingerprintConfirm || client.saved {
		t.Fatalf("before confirmation screen = %v, saved = %v", model.screen, client.saved)
	}
	if !strings.Contains(model.View().Content, "SHA256:target") {
		t.Fatalf("fingerprint confirmation did not render: %s", model.View().Content)
	}

	message = model.handleKey(tea.KeyPressMsg{Code: 'y', Text: "y"})()
	_, command = model.Update(message)
	message = command()
	_, command = model.Update(message)
	message = command()
	_, _ = model.Update(message)
	if !client.saved || model.screen != screenTargets {
		t.Fatalf("after confirmation saved = %v, screen = %v", client.saved, model.screen)
	}
	if client.savedSSH.ConfirmedFingerprint != client.fingerprint {
		t.Fatalf("已保存 SSH 目标的确认指纹 = %q，期望 %q", client.savedSSH.ConfirmedFingerprint, client.fingerprint)
	}
	if want := []string{"rm /data/.*", "cat /etc/passwd", "passwd.*"}; !slices.Equal(client.savedSSH.Target.CommandBlacklistPatterns, want) {
		t.Fatalf("命令黑名单 = %#v，期望 %#v", client.savedSSH.Target.CommandBlacklistPatterns, want)
	}
	if client.savedSSH.Target.Description != "production SSH host" || client.savedSSH.Target.Environment != "production" {
		t.Fatalf("SSH 目标说明或环境保存错误：%#v", client.savedSSH.Target)
	}
}

func TestSSHFormSubmitsFileOperationsCapability(t *testing.T) {
	t.Parallel()

	client := &recordingCaller{}
	model := NewModel(client)
	model.status.Unlocked = true
	model.beginSSHForm(store.SSHTarget{IP: "192.0.2.14", Mode: store.SSHDirect, Enabled: true})
	model.form.fields[2].value = "ops"
	model.form.fields[3].value = "ssh-password"
	model.form.fields[7].value = "false"

	command := model.submitForm()
	if command == nil {
		t.Fatalf("SSH form unexpectedly rejected file capability: %q", model.notice)
	}
	message := command()
	_, command = model.Update(message)
	if command == nil {
		t.Fatal("SSH target save command was not started after the connectivity test")
	}
	message = command()
	_, _ = model.Update(message)

	if client.savedSSH.Target.AllowFileOperations {
		t.Fatalf("submitted file capability = true, want false")
	}
}

func TestSSHFormDefaultsFileOperationsToTrueForNewTarget(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.beginSSHForm(store.SSHTarget{Mode: store.SSHDirect, Enabled: true, AllowFileOperations: true})
	view := model.View().Content
	if !strings.Contains(view, "允许文件读写（true/false）：true") {
		t.Fatalf("new target does not render file capability as true: %s", view)
	}
}

func TestSSHSaveRequiresConfirmationAgainWhenFingerprintChanges(t *testing.T) {
	t.Parallel()

	client := &recordingCaller{testFingerprints: []string{"SHA256:first", "SHA256:second", "SHA256:second"}}
	model := NewModel(client)
	model.status.Unlocked = true
	model.beginSSHForm(store.SSHTarget{IP: "192.0.2.12", Mode: store.SSHDirect, Enabled: true})
	model.form.fields[2].value = "ops"
	model.form.fields[3].value = "ssh-password"

	message := model.submitForm()()
	_, command := model.Update(message)
	if command != nil || model.screen != screenFingerprintConfirm || !strings.Contains(model.View().Content, "SHA256:first") {
		t.Fatalf("首次主机身份确认界面不正确：界面 = %v，视图 = %s", model.screen, model.View().Content)
	}

	message = model.handleKey(tea.KeyPressMsg{Code: 'y', Text: "y"})()
	_, command = model.Update(message)
	if command != nil || model.screen != screenFingerprintConfirm || client.saved || !strings.Contains(model.View().Content, "SHA256:second") {
		t.Fatalf("主机身份变化后未要求再次确认：界面 = %v，已保存 = %v，视图 = %s", model.screen, client.saved, model.View().Content)
	}

	message = model.handleKey(tea.KeyPressMsg{Code: 'y', Text: "y"})()
	_, command = model.Update(message)
	message = command()
	_, command = model.Update(message)
	message = command()
	_, _ = model.Update(message)
	if !client.saved || client.savedSSH.ConfirmedFingerprint != "SHA256:second" {
		t.Fatalf("再次确认后保存的 SSH 目标不正确：已保存 = %v，指纹 = %q", client.saved, client.savedSSH.ConfirmedFingerprint)
	}
}

func TestDatabaseSaveWaitsForConnectivityTest(t *testing.T) {
	t.Parallel()

	client := &recordingCaller{databaseSecurity: store.TransportTLSVerified}
	model := NewModel(client)
	model.status.Unlocked = true
	model.beginDatabaseForm(store.DatabaseInstance{Host: "192.0.2.11", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app", TransportPolicy: store.DatabaseTLSVerified, TLSCAPath: "/etc/ssl/certs/test-ca.pem", Enabled: true})
	model.form.fields[4].value = "app_read"
	model.form.fields[5].value = "database-password"

	message := model.submitForm()()
	_, command := model.Update(message)
	if command == nil || client.databaseSaved {
		t.Fatalf("database target was saved before its connection test completed")
	}
	message = command()
	_, _ = model.Update(message)
	if !client.databaseSaved {
		t.Fatal("database target was not saved after a successful connection test")
	}
}

func TestDatabaseSaveExplainsLockedVault(t *testing.T) {
	t.Parallel()

	model := NewModel(&recordingCaller{})
	model.beginDatabaseForm(store.DatabaseInstance{Host: "192.0.2.11", Port: 3306, Engine: store.EngineMySQL, Enabled: true})
	model.form.fields[4].value = "root"
	model.form.fields[5].value = "read-password"

	if command := model.submitForm(); command != nil {
		t.Fatal("locked database form unexpectedly started a save request")
	}
	if model.notice != "本地凭据库已锁定，请先解锁后再保存。" {
		t.Fatalf("locked database notice = %q", model.notice)
	}
}

func TestLocalControlErrorNoticeExplainsCandidateSaveFailuresWithoutLeakingCause(t *testing.T) {
	t.Parallel()

	const secret = "candidate-password-must-not-render"
	cases := []struct {
		name     string
		category error
		want     []string
	}{
		{name: "locked", category: ipc.ErrLocked, want: []string{"已锁定", "解锁"}},
		{name: "invalid SSH target", category: ipc.ErrInvalidRequest, want: []string{"命令黑名单正则格式"}},
		{name: "not dispatched", category: ipc.ErrCandidateNotDispatched, want: []string{"未派发", "维护"}},
		{name: "audit write", category: ipc.ErrCandidateAuditWriteFailed, want: []string{"审计", "可写性"}},
		{name: "confirmation", category: ipc.ErrConfirmationRequired, want: []string{"指纹", "确认"}},
		{name: "connection", category: ipc.ErrCandidateConnectionFailed, want: []string{"IP、端口", "重试"}},
		{name: "authentication", category: ipc.ErrCandidateAuthenticationFailed, want: []string{"账号、密码", "权限"}},
		{name: "TLS", category: ipc.ErrCandidateTLSFailed, want: []string{"传输策略", "CA 证书"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			notice := localControlErrorNotice("target_saved", ipc.Categorize(errors.New(secret), test.category))
			for _, want := range test.want {
				if !strings.Contains(notice, want) {
					t.Fatalf("notice = %q, missing %q", notice, want)
				}
			}
			if strings.Contains(notice, secret) {
				t.Fatalf("notice leaked remote cause: %q", notice)
			}
		})
	}
}

func TestDatabaseFormAllowsSameReadAndWriteAccount(t *testing.T) {
	t.Parallel()

	client := &recordingCaller{}
	model := NewModel(client)
	model.status.Unlocked = true
	model.beginDatabaseForm(store.DatabaseInstance{Host: "192.0.2.11", Port: 3306, Engine: store.EngineMySQL, Enabled: true})
	model.form.fields[4].value = "root"
	model.form.fields[5].value = "read-password"
	model.form.fields[6].value = "root"

	command := model.submitForm()
	if command == nil {
		t.Fatalf("same read/write account was rejected: %q", model.notice)
	}
	if !strings.Contains(model.form.fields[6].label, "可与只读账号相同") {
		t.Fatalf("write account label = %q", model.form.fields[6].label)
	}
	_ = command()
	if client.databaseTested.Instance.ReadUsername != "root" || client.databaseTested.Instance.WriteUsername != "root" {
		t.Fatalf("database test configuration = %#v", client.databaseTested.Instance)
	}
	if client.databaseTested.Instance.WriteCredentialID != "" {
		t.Fatalf("same account should reuse the read credential: %#v", client.databaseTested.Instance)
	}
}

func TestNewDatabaseFormAllowsSavingWithoutWriteAccount(t *testing.T) {
	t.Parallel()

	client := &recordingCaller{}
	model := NewModel(client)
	model.status.Unlocked = true
	model.beginDatabaseForm(store.DatabaseInstance{Host: "192.0.2.12", Port: 3306, Engine: store.EngineMySQL, Enabled: true})
	model.form.fields[4].value = "app_read"
	model.form.fields[5].value = "read-password"

	command := model.submitForm()
	if command == nil {
		t.Fatalf("database form without a write account was rejected: %q", model.notice)
	}
	_ = command()
	if client.databaseTested.Instance.WriteUsername != "" || client.databaseTested.Instance.WriteCredentialID != "" {
		t.Fatalf("new database write configuration = %#v, want no write credential", client.databaseTested.Instance)
	}
}

func TestEditingDatabaseFormClearsWriteCredentialWhenWriteAccountIsRemoved(t *testing.T) {
	t.Parallel()

	client := &recordingCaller{}
	model := NewModel(client)
	model.status.Unlocked = true
	model.beginDatabaseForm(store.DatabaseInstance{
		Host: "192.0.2.13", Port: 3306, Engine: store.EngineMySQL, Enabled: true,
		ReadUsername: "app_read", ReadCredentialID: "read-credential",
		WriteUsername: "app_write", WriteCredentialID: "write-credential",
	})
	model.form.fields[6].value = ""

	testCommand := model.submitForm()
	if testCommand == nil {
		t.Fatalf("removing write account was rejected: %q", model.notice)
	}
	testMessage := testCommand()
	_, saveCommand := model.Update(testMessage)
	if saveCommand == nil {
		t.Fatalf("database target was not queued for save after removing write account")
	}
	_, _ = model.Update(saveCommand())

	if client.databaseTested.Instance.WriteUsername != "" || client.databaseTested.Instance.WriteCredentialID != "" {
		t.Fatalf("candidate database write configuration = %#v, want no write credential", client.databaseTested.Instance)
	}
	if client.savedDatabase.Instance.WriteUsername != "" || client.savedDatabase.Instance.WriteCredentialID != "" {
		t.Fatalf("saved database write configuration = %#v, want no write credential", client.savedDatabase.Instance)
	}
}

func TestActiveFormFieldRendersItsLabelOnlyOnce(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.beginDatabaseForm(store.DatabaseInstance{Host: "192.0.2.11", Port: 3306, Engine: store.EngineMySQL, Enabled: true})
	label := model.form.fields[0].label
	if count := strings.Count(model.View().Content, label); count != 1 {
		t.Fatalf("active form label %q appears %d times", label, count)
	}
}

func TestSSHCommandBlacklistFieldExplainsItsFormat(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.beginSSHForm(store.SSHTarget{IP: "192.0.2.11", Mode: store.SSHDirect, Enabled: true})
	model.form.index = 4
	model.loadCurrentField()
	view := model.View().Content
	if !strings.Contains(view, "命令黑名单（正则，逗号分隔）") {
		t.Fatalf("SSH form does not render command blacklist field: %s", view)
	}
	if !strings.Contains(view, "多个正则用英文逗号分隔；任一正则匹配命令文本即拦截。例：rm /data/.*, cat /etc/passwd, passwd.*") {
		t.Fatalf("SSH form does not render command blacklist hint: %s", view)
	}
	for _, obsolete := range []string{"数据库容器", "数据库卷", "数据库数据路径"} {
		if strings.Contains(view, obsolete) {
			t.Fatalf("SSH form still renders obsolete field %q: %s", obsolete, view)
		}
	}
}

func TestDashboardDoesNotExposePolicyModeOrReviewWorkflow(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	view := model.View().Content
	if strings.Contains(view, "执行模式") || strings.Contains(view, "审查") {
		t.Fatalf("dashboard still exposes removed workflow: %s", view)
	}
}

func TestNewDatabaseFormDefaultsToLegacyPlaintext(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.handleTargetKey("d")
	if model.form == nil || model.form.fields[8].value != string(store.DatabaseLegacyPlaintext) {
		t.Fatalf("new database policy = %#v", model.form)
	}
}

type recordingCaller struct {
	fingerprint      string
	testFingerprints []string
	testCalls        int
	saved            bool
	savedSSH         control.UpsertSSHTargetParams
	databaseSecurity store.TransportSecurity
	databaseTested   control.DatabaseTestParams
	databaseSaved    bool
	savedDatabase    control.UpsertDatabaseInstanceParams
	deletedSSH       string
	deletedDatabase  control.DeleteDatabaseInstanceParams
}

func (c *recordingCaller) Call(_ context.Context, method string, params any, output any) error {
	switch method {
	case "ssh.test_target":
		result := output.(*control.SSHTestResult)
		c.testCalls++
		fingerprint := c.fingerprint
		if index := c.testCalls - 1; index < len(c.testFingerprints) {
			fingerprint = c.testFingerprints[index]
		}
		result.Fingerprint = fingerprint
		result.RequiresFingerprintConfirmation = params.(control.SSHTestParams).ConfirmedFingerprint != fingerprint
		return nil
	case "target.upsert_ssh":
		c.saved = true
		c.savedSSH = params.(control.UpsertSSHTargetParams)
		return nil
	case "database.test_target":
		c.databaseTested = params.(control.DatabaseTestParams)
		result := output.(*control.DatabaseTestResult)
		result.TransportSecurity = c.databaseSecurity
		return nil
	case "target.upsert_database":
		c.databaseSaved = true
		c.savedDatabase = params.(control.UpsertDatabaseInstanceParams)
		return nil
	case "target.delete_ssh":
		c.deletedSSH = params.(control.DeleteSSHTargetParams).IP
		return nil
	case "target.delete_database":
		c.deletedDatabase = params.(control.DeleteDatabaseInstanceParams)
		return nil
	case "unlock":
		result := output.(*control.UnlockResult)
		result.Unlocked = true
		return nil
	default:
		return nil
	}
}

func TestTargetListShowsRegisteredTargets(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.screen = screenTargets
	model.targets = control.TargetsResult{
		SSH:       []store.SSHTarget{{IP: "192.0.2.10", Mode: store.SSHDirect, Enabled: true}},
		Databases: []store.DatabaseInstance{{Host: "192.0.2.11", Port: 3306, Engine: store.EngineMySQL, Enabled: false}},
	}
	view := model.View().Content
	if !strings.Contains(view, "192.0.2.10") || !strings.Contains(view, "192.0.2.11:3306") {
		t.Fatalf("target view = %s", view)
	}

}

func TestTargetDeleteUsesSingleConfirmationAndRefreshesList(t *testing.T) {
	t.Parallel()

	client := &recordingCaller{}
	model := NewModel(client)
	model.status.Unlocked = true
	model.screen = screenTargets
	model.targets.SSH = []store.SSHTarget{{IP: "192.0.2.10", Mode: store.SSHDirect, Enabled: true}}
	if command := model.handleTargetKey("delete"); command != nil || model.screen != screenTargetDeleteConfirm {
		t.Fatalf("after Delete screen = %v, command = %v", model.screen, command)
	}
	if !strings.Contains(model.View().Content, "192.0.2.10") || !strings.Contains(model.View().Content, "y 删除") {
		t.Fatalf("delete confirmation view = %s", model.View().Content)
	}

	message := model.handleTargetDeleteConfirmation("y")()
	_, command := model.Update(message)
	if client.deletedSSH != "192.0.2.10" || command == nil {
		t.Fatalf("deleted SSH = %q, refresh = %v", client.deletedSSH, command)
	}
	_, _ = model.Update(command())
	if model.screen != screenTargets || model.selected != 0 {
		t.Fatalf("after deletion screen = %v, selected = %d", model.screen, model.selected)
	}
}

func TestTargetDeleteSupportsDatabaseAndRequiresUnlock(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.screen = screenTargets
	model.targets = control.TargetsResult{
		SSH:       []store.SSHTarget{{IP: "192.0.2.10", Mode: store.SSHDirect, Enabled: true}},
		Databases: []store.DatabaseInstance{{Host: "192.0.2.11", Port: 5432, Engine: store.EnginePostgreSQL, Enabled: true}},
	}
	model.selected = 1
	model.handleTargetKey("delete")
	if model.screen != screenTargets || !strings.Contains(model.notice, "解锁") {
		t.Fatalf("locked delete screen = %v, notice = %q", model.screen, model.notice)
	}

	model.status.Unlocked = true
	model.handleTargetKey("delete")
	if model.screen != screenTargetDeleteConfirm || model.deleting == nil || model.deleting.method != "target.delete_database" {
		t.Fatalf("database delete state = %#v, screen = %v", model.deleting, model.screen)
	}
	model.handleTargetDeleteConfirmation("n")
	if model.screen != screenTargets || model.deleting != nil {
		t.Fatalf("cancelled database delete screen = %v, pending = %#v", model.screen, model.deleting)
	}
}

func TestMaintenanceFormMasksMasterPassword(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.beginMaintenance(maintenanceBackup)
	model.maintenance.fields[1].value = "backup-master-password"
	view := model.View().Content
	if strings.Contains(view, "backup-master-password") {
		t.Fatalf("master password appeared in maintenance view: %s", view)
	}
}

func TestChangeMasterPasswordFormMasksBothPasswords(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.beginMaintenance(maintenanceChangeMasterPassword)
	model.maintenance.fields[0].value = "old-master-password"
	model.maintenance.fields[1].value = "new-master-password"
	view := model.View().Content
	if strings.Contains(view, "old-master-password") || strings.Contains(view, "new-master-password") {
		t.Fatalf("master passwords appeared in maintenance view: %s", view)
	}
}
