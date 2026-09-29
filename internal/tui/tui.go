// Package tui implements the independent local terminal interface. It talks
// only to the authenticated local transport control channel.
package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/clipperhouse/displaywidth"

	"ssh-mcp/internal/control"
	"ssh-mcp/internal/ipc"
	"ssh-mcp/internal/store"
)

type Caller interface {
	Call(context.Context, string, any, any) error
}

func Run(ctx context.Context, socketPath, token string) error {
	options, closeConsole, err := platformProgramOptions()
	if err != nil {
		return err
	}
	defer closeConsole()
	options = append(options, tea.WithContext(ctx))
	program := tea.NewProgram(NewModel(ipc.NewClient(socketPath, token)), options...)
	_, err = program.Run()
	return err
}

type screen uint8

const (
	screenDashboard screen = iota
	screenUnlock
	screenTargets
	screenForm
	screenFingerprintConfirm
	screenTargetDeleteConfirm
	screenMaintenance
)

type formKind uint8

const (
	formSSH formKind = iota
	formDatabase
)

type maintenanceAction uint8

const (
	maintenanceBackup maintenanceAction = iota
	maintenanceRestore
	maintenanceRotate
	maintenanceChangeMasterPassword
)

type formField struct {
	label  string
	value  string
	secret bool
	hint   string
}

type targetForm struct {
	kind     formKind
	fields   []formField
	index    int
	enabled  bool
	ssh      *store.SSHTarget
	database *store.DatabaseInstance
}

type maintenanceForm struct {
	action maintenanceAction
	fields []formField
	index  int
}

type pendingTargetSave struct {
	testMethod  string
	testParams  any
	saveMethod  string
	saveParams  any
	fingerprint string
}

type pendingTargetDelete struct {
	label  string
	method string
	params any
}

type Model struct {
	client Caller

	width  int
	height int

	screen   screen
	status   control.Status
	targets  control.TargetsResult
	selected int
	notice   string

	input       textinput.Model
	form        *targetForm
	maintenance *maintenanceForm
	pending     *pendingTargetSave
	deleting    *pendingTargetDelete

	lang string
	msg  *Messages
}

type rpcMsg struct {
	action string
	value  any
	err    error
}

func NewModel(client Caller) *Model {
	input := textinput.New()
	input.SetWidth(defaultInputWidth)
	return &Model{client: client, input: input, lang: "zh", msg: messagesZH}
}

func (m *Model) setLanguage(lang string) {
	if lang != "en" {
		lang = "zh"
	}
	m.lang = lang
	m.msg = getMessages(lang)
	if m.screen == screenUnlock {
		m.input.Prompt = m.msg.UnlockPrompt
	}
}

func (m *Model) toggleLanguage() tea.Cmd {
	next := "en"
	if m.lang == "en" {
		next = "zh"
	}
	m.setLanguage(next)
	if next == "en" {
		m.notice = m.msg.LanguageSwitchedENNotice
	} else {
		m.notice = m.msg.LanguageSwitchedZHNotice
	}
	return m.call("language_set", "tui.set_language", control.SetTUILanguageParams{Language: next}, &struct{}{})
}

const (
	defaultInputWidth    = 60
	minInputWidth        = 20
	inputLinePrefix      = "> "
	contentHorizontalPad = 2

	// A paste arrives as one opaque blob, so it is validated before it reaches
	// the input: a clipboard can carry a trailing newline, an accidentally
	// copied paragraph, or nothing at all.
	maxSecretPasteRunes = 256
	maxTextPasteRunes   = 1024
)

const (
	pasteHintNotice       = "请使用终端粘贴：Shift+Ins 或 Cmd+V。"
	pasteEmptyNotice      = "粘贴内容为空。"
	pasteWhitespaceNotice = "粘贴内容包含空白字符，已忽略。"
	pasteTooLongNotice    = "粘贴内容超过长度上限，已忽略。"
	pasteSecretNotice     = "已粘贴。"
)

func (m *Model) Init() tea.Cmd {
	if m.client == nil {
		return nil
	}
	return tea.Batch(m.loadStatus(), m.loadTargets())
}

func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch value := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = value.Width, value.Height
		m.applyLayout()
		return m, nil
	case rpcMsg:
		return m, m.applyRPC(value)
	case tea.KeyMsg:
		return m, m.handleKey(value)
	case tea.PasteMsg:
		// Terminal-driven paste is the only supported paste path. It does not
		// read the host clipboard, so it also works over an SSH session.
		return m, m.handlePaste(value.Content)
	}
	return m, nil
}

func (m *Model) handleKey(message tea.KeyMsg) tea.Cmd {
	key := message.String()
	if key == "ctrl+c" || key == "q" && m.screen == screenDashboard {
		return tea.Quit
	}

	switch m.screen {
	case screenDashboard:
		switch key {
		case "u":
			m.beginUnlock()
		case "t":
			m.screen = screenTargets
			return m.loadTargets()
		case "b":
			m.beginMaintenance(maintenanceBackup)
		case "o":
			m.beginMaintenance(maintenanceRestore)
		case "k":
			m.beginMaintenance(maintenanceRotate)
		case "p":
			m.beginMaintenance(maintenanceChangeMasterPassword)
		case "l":
			return m.call("locked", "lock", nil, &struct{}{})
		case "e":
			return m.toggleLanguage()
		}
	case screenUnlock:
		if key == "esc" {
			m.screen = screenDashboard
			m.input.SetValue("")
			return nil
		}
		if key == "enter" {
			password := m.input.Value()
			m.input.SetValue("")
			return m.call("unlocked", "unlock", control.UnlockParams{MasterPassword: password}, &control.UnlockResult{})
		}
		return m.updateInput(message)
	case screenTargets:
		return m.handleTargetKey(key)
	case screenForm:
		return m.handleFormKey(message, key)
	case screenFingerprintConfirm:
		return m.handleFingerprintConfirmation(key)
	case screenTargetDeleteConfirm:
		return m.handleTargetDeleteConfirmation(key)
	case screenMaintenance:
		return m.handleMaintenanceKey(message, key)
	}
	return nil
}

func (m *Model) handleMaintenanceKey(message tea.KeyMsg, key string) tea.Cmd {
	if key == "esc" {
		m.clearMaintenance()
		m.screen = screenDashboard
		return nil
	}
	if key == "ctrl+s" {
		m.saveMaintenanceField()
		return m.submitMaintenance()
	}
	if key == "tab" || key == "enter" || key == "down" {
		m.saveMaintenanceField()
		m.maintenance.index = (m.maintenance.index + 1) % len(m.maintenance.fields)
		m.loadMaintenanceField()
		return nil
	}
	if key == "shift+tab" || key == "up" {
		m.saveMaintenanceField()
		m.maintenance.index = (m.maintenance.index - 1 + len(m.maintenance.fields)) % len(m.maintenance.fields)
		m.loadMaintenanceField()
		return nil
	}
	return m.updateInput(message)
}

func (m *Model) handleTargetKey(key string) tea.Cmd {
	switch key {
	case "esc":
		m.screen = screenDashboard
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
	case "down":
		if m.selected+1 < m.targetCount() {
			m.selected++
		}
	case "n":
		m.beginSSHForm(store.SSHTarget{Mode: store.SSHDirect, Enabled: true, AllowFileOperations: true})
	case "d":
		m.beginDatabaseForm(store.DatabaseInstance{Engine: store.EngineMySQL, Port: 3306, TransportPolicy: store.DatabaseLegacyPlaintext, Enabled: true})
	case "enter":
		m.editSelectedTarget()
	case "x":
		return m.toggleSelectedTarget()
	case "delete":
		m.beginTargetDelete()
	case "r":
		return m.loadTargets()
	}
	return nil
}

func (m *Model) handleFormKey(message tea.KeyMsg, key string) tea.Cmd {
	if key == "esc" {
		m.clearForm()
		m.screen = screenTargets
		return nil
	}
	if key == "ctrl+s" {
		m.saveCurrentField()
		return m.submitForm()
	}
	if key == "tab" || key == "enter" || key == "down" {
		m.saveCurrentField()
		m.form.index = (m.form.index + 1) % len(m.form.fields)
		m.loadCurrentField()
		return nil
	}
	if key == "shift+tab" || key == "up" {
		m.saveCurrentField()
		m.form.index = (m.form.index - 1 + len(m.form.fields)) % len(m.form.fields)
		m.loadCurrentField()
		return nil
	}
	return m.updateInput(message)
}

func (m *Model) handleFingerprintConfirmation(key string) tea.Cmd {
	if m.pending == nil {
		m.screen = screenTargets
		return nil
	}
	switch key {
	case "y":
		params, ok := confirmedFingerprintParams(m.pending.testParams, m.pending.fingerprint)
		if !ok {
			m.notice = m.msg.FingerprintInvalidRequest
			return nil
		}
		m.pending.testParams = params
		return m.call("target_tested", m.pending.testMethod, params, &control.SSHTestResult{})
	case "n", "esc":
		m.clearPendingTarget()
		m.screen = screenForm
		m.notice = m.msg.FingerprintNotConfirmedNotice
	}
	return nil
}

func (m *Model) handleTargetDeleteConfirmation(key string) tea.Cmd {
	if m.deleting == nil {
		m.screen = screenTargets
		return nil
	}
	switch key {
	case "y":
		return m.call("target_deleted", m.deleting.method, m.deleting.params, &struct{}{})
	case "n", "esc":
		m.deleting = nil
		m.screen = screenTargets
		m.notice = m.msg.DeleteCancelledNotice
	}
	return nil
}

func (m *Model) updateInput(message tea.Msg) tea.Cmd {
	// Windows Console can provide a printable key code without the associated
	// text field. Bubble's text input only inserts Text, so recover it here.
	if key, ok := message.(tea.KeyPressMsg); ok && key.Text == "" && key.Mod == 0 && unicode.IsPrint(key.Code) {
		key.Text = string(key.Code)
		message = key
	}
	// Neither shortcut is forwarded. ctrl+v would make the text input read the
	// host clipboard, whose result cannot be handled upstream, and insert only
	// reaches us when a terminal does not translate it into a paste by itself.
	// Both answer instead of failing silently.
	if key, ok := message.(tea.KeyPressMsg); ok && isPasteShortcut(key) {
		m.notice = m.msg.PasteHint
		return nil
	}
	var command tea.Cmd
	m.input, command = m.input.Update(message)
	return command
}

// isPasteShortcut reports keys whose intended result is a paste this program
// cannot perform on its own. Insert is matched without its modifiers because
// most terminals consume it, and those that forward it often drop the shift
// bit, so requiring "shift+insert" would silently fail on those terminals.
func isPasteShortcut(key tea.KeyPressMsg) bool {
	return key.Code == tea.KeyInsert || key.String() == "ctrl+v"
}

// handlePaste inserts text delivered by the terminal's bracketed-paste mode.
// Unlike typed input, a pasted payload cannot be reviewed character by
// character, so anything that is not a plausible single field value is
// rejected with a notice and leaves the input untouched.
func (m *Model) handlePaste(content string) tea.Cmd {
	switch m.screen {
	case screenUnlock, screenForm, screenMaintenance:
	default:
		return nil
	}
	// unicode.IsSpace also covers the non-breaking and ideographic spaces that
	// browsers and password managers leave behind in copied text.
	trimmed := strings.TrimSpace(content)
	switch {
	case trimmed == "":
		m.notice = m.msg.PasteEmpty
		return nil
	case strings.ContainsFunc(trimmed, unicode.IsSpace):
		m.notice = m.msg.PasteWhitespace
		return nil
	}
	limit := maxTextPasteRunes
	secret := m.activeSecretField()
	if secret {
		limit = maxSecretPasteRunes
	}
	count := utf8.RuneCountInString(trimmed)
	if count > limit {
		// The rejected length is deliberately not reported: on a secret field
		// it would disclose how long the password is.
		m.notice = m.msg.PasteTooLong
		return nil
	}
	var command tea.Cmd
	m.input, command = m.input.Update(tea.PasteMsg{Content: trimmed})
	if secret {
		m.notice = m.msg.PasteSecret
	} else {
		m.notice = m.msg.PastedRunesCount(count)
	}
	return command
}

// activeSecretField reports whether the focused input holds a secret. Secret
// fields never report a pasted length, because the length is itself a small
// disclosure about a value the interface otherwise never reveals.
func (m *Model) activeSecretField() bool {
	switch m.screen {
	case screenUnlock:
		return true
	case screenForm:
		return m.form != nil && m.form.index < len(m.form.fields) && m.form.fields[m.form.index].secret
	case screenMaintenance:
		return m.maintenance != nil && m.maintenance.index < len(m.maintenance.fields) && m.maintenance.fields[m.maintenance.index].secret
	}
	return false
}

func (m *Model) applyRPC(message rpcMsg) tea.Cmd {
	if message.err != nil {
		if message.action == "target_tested" || message.action == "database_tested" {
			m.clearPendingTarget()
		}
		m.notice = m.msg.LocalControlErrorNotice(message.action, message.err)
		return nil
	}
	m.notice = ""
	switch message.action {
	case "status":
		m.status = message.value.(control.Status)
		if m.status.Language != "" && m.status.Language != m.lang {
			m.setLanguage(m.status.Language)
		}
	case "targets":
		m.targets = message.value.(control.TargetsResult)
		m.clampSelected(m.targetCount())
	case "unlocked":
		result := message.value.(control.UnlockResult)
		m.status.Unlocked = result.Unlocked
		m.status.Initialized = true
		m.screen = screenDashboard
		if result.Created {
			m.notice = m.msg.UnlockCreatedNotice
		} else {
			m.notice = m.msg.UnlockSuccessNotice
		}
	case "locked":
		m.status.Unlocked = false
		m.notice = m.msg.LockedNotice
	case "target_saved":
		m.clearPendingTarget()
		m.clearForm()
		m.screen = screenTargets
		return m.loadTargets()
	case "target_toggled":
		return m.loadTargets()
	case "target_deleted":
		m.deleting = nil
		m.screen = screenTargets
		return m.loadTargets()
	case "target_tested":
		result := message.value.(control.SSHTestResult)
		if result.RequiresFingerprintConfirmation {
			if m.pending == nil {
				m.notice = m.msg.PendingTargetNotFound
				return nil
			}
			m.pending.fingerprint = result.Fingerprint
			m.screen = screenFingerprintConfirm
			return nil
		}
		if m.pending == nil {
			m.notice = m.msg.PendingTargetNotFound
			return nil
		}
		params, ok := m.pending.saveParams.(control.UpsertSSHTargetParams)
		if !ok {
			m.notice = m.msg.SSHTestRequestInvalid
			return nil
		}
		params.ConfirmedFingerprint = result.Fingerprint
		m.pending.saveParams = params
		return m.savePendingTarget()
	case "database_tested":
		if m.pending == nil {
			m.notice = m.msg.PendingTargetNotFound
			return nil
		}
		params, ok := m.pending.saveParams.(control.UpsertDatabaseInstanceParams)
		if !ok {
			m.notice = m.msg.DBTestRequestInvalid
			return nil
		}
		params.Instance.TransportSecurity = message.value.(control.DatabaseTestResult).TransportSecurity
		m.pending.saveParams = params
		return m.savePendingTarget()
	case "maintenance_done":
		m.clearMaintenance()
		m.screen = screenDashboard
		m.notice = m.msg.MaintenanceDoneNotice
	case "language_set":
		// language preference saved
	}
	return nil
}

func localControlErrorNotice(action string, err error) string {
	return localControlErrorNoticeZH(action, err)
}

func (m *Model) View() tea.View {
	lines := []string{m.header(), ""}
	if m.notice != "" {
		lines = append(lines, m.notice, "")
	}
	switch m.screen {
	case screenUnlock:
		lines = append(lines, m.msg.UnlockTitle, m.input.View(), "", m.msg.UnlockHelp)
	case screenTargets:
		lines = append(lines, m.renderTargets()...)
	case screenForm:
		lines = append(lines, m.renderForm()...)
	case screenFingerprintConfirm:
		lines = append(lines, m.renderFingerprintConfirmation()...)
	case screenTargetDeleteConfirm:
		lines = append(lines, m.renderTargetDeleteConfirmation()...)
	case screenMaintenance:
		lines = append(lines, m.renderMaintenance()...)
	default:
		lines = append(lines, m.renderDashboard()...)
	}
	if m.width > 0 {
		// Keep every rendered row inside the terminal, including regular layouts
		// whose fixed labels can be wider than a medium-sized viewport.
		lines = compactLines(lines, m.width)
	}
	view := tea.NewView(strings.Join(lines, "\n"))
	if cursor := m.inputCursor(); cursor != nil {
		view.Cursor = cursor
	}
	// Very small consoles, and terminals that do not report dimensions, stay
	// on the primary screen so the user can recover the prompt.
	view.AltScreen = m.width >= 48 && m.height >= 8
	return view
}

// inputCursor returns the terminal cursor position for the active input. The
// textinput component's cursor is relative to its own prompt, so account for
// the form prefix and the line where the input is rendered here.
func (m *Model) inputCursor() *tea.Cursor {
	if m == nil || m.screen != screenUnlock && m.screen != screenForm && m.screen != screenMaintenance {
		return nil
	}
	cursor := m.input.Cursor()
	if cursor == nil {
		return nil
	}
	base := 2
	if m.notice != "" {
		base += 2
	}
	line := base + 1
	prefix := ""
	switch m.screen {
	case screenForm:
		prefix = inputLinePrefix
		if m.form != nil {
			if m.isCompactLayout() {
				line = base + 3
			} else {
				line = base + 2 + m.form.index
			}
		}
	case screenMaintenance:
		prefix = inputLinePrefix
		if m.maintenance != nil {
			line = base + 2 + m.maintenance.index
		}
	}
	cursor.Position.X += lipgloss.Width(prefix)
	cursor.Position.Y += line
	if m.width > 0 {
		cursor.Position.X = min(cursor.Position.X, max(0, m.width-1))
	}
	return cursor
}

func (m *Model) applyLayout() {
	if m == nil {
		return
	}
	m.input.SetWidth(textInputWidth(m.width, m.input.Prompt, activeInputPrefix(m.screen)))
}

func inputWidth(viewport int) int {
	return textInputWidth(viewport, "", "")
}

func textInputWidth(viewport int, prompt, prefix string) int {
	if viewport <= 0 {
		return defaultInputWidth
	}
	width := viewport - contentHorizontalPad - lipgloss.Width(prompt) - lipgloss.Width(prefix)
	if width <= 0 {
		return 1
	}
	if width < minInputWidth {
		return width
	}
	if width > defaultInputWidth {
		return defaultInputWidth
	}
	return width
}

func activeInputPrefix(current screen) string {
	switch current {
	case screenForm, screenMaintenance:
		return inputLinePrefix
	default:
		return ""
	}
}

func (m *Model) contentWidth() int {
	if m == nil || m.width <= 0 {
		return defaultInputWidth
	}
	return max(1, m.width-contentHorizontalPad)
}

func (m *Model) isCompactLayout() bool {
	return m != nil && m.width > 0 && m.width < 48
}

func compactText(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	// The ellipsis itself is wider than a one- or two-cell viewport. Keep the
	// line inside the viewport even when there is no room for a marker.
	if width <= lipgloss.Width("...") {
		return displaywidth.TruncateString(value, width, "")
	}
	return displaywidth.TruncateString(value, width, "...")
}

func compactLines(lines []string, width int) []string {
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		parts := strings.Split(line, "\n")
		for _, part := range parts {
			result = append(result, compactText(part, width))
		}
	}
	return result
}

func (m *Model) header() string {
	state := m.msg.LockedState
	if m.status.Unlocked {
		state = m.msg.UnlockedState
	}
	return m.msg.ConsoleTitle + "  [" + state + "]"
}

func (m *Model) renderDashboard() []string {
	if m.isCompactLayout() {
		return []string{m.msg.DashboardCompactHelp}
	}
	return []string{
		m.msg.DashboardFullHelp,
	}
}

func (m *Model) renderTargets() []string {
	if m.isCompactLayout() {
		return m.renderCompactTargets()
	}
	lines := []string{m.msg.TargetsTitle, ""}
	index := 0
	for _, target := range m.targets.SSH {
		lines = append(lines, m.targetMarker(index)+fmt.Sprintf("%s  %s  %s  %s", m.msg.TargetKindSSH, target.IP, target.Mode, m.enabledText(target.Enabled)))
		index++
	}
	for _, instance := range m.targets.Databases {
		lines = append(lines, m.targetMarker(index)+fmt.Sprintf("%s  %s:%d  %s  %s  %s  %s  %s", m.msg.TargetKindDB, instance.Host, instance.Port, instance.Engine, m.databaseAccountText(instance), m.databaseTransportPolicyText(instance.TransportPolicy), m.databaseSecurityText(instance.TransportSecurity), m.enabledText(instance.Enabled)))
		index++
	}
	if index == 0 {
		lines = append(lines, m.msg.NoTargets)
	}
	lines = append(lines, "", m.msg.TargetsHelpFull)
	return lines
}

func (m *Model) renderCompactTargets() []string {
	lines := []string{m.msg.TargetsTitle}
	index := 0
	width := max(1, m.contentWidth()-4)
	for _, target := range m.targets.SSH {
		lines = append(lines, m.targetMarker(index)+compactText(m.msg.TargetKindSSH+" "+target.IP, width))
		index++
	}
	for _, instance := range m.targets.Databases {
		lines = append(lines, m.targetMarker(index)+compactText(fmt.Sprintf("%s %s:%d", m.msg.TargetKindDB, instance.Host, instance.Port), width))
		index++
	}
	if index == 0 {
		lines = append(lines, m.msg.NoTargets)
	}
	return append(lines, "", m.msg.TargetsCompactHelp1, m.msg.TargetsCompactHelp2)
}

func (m *Model) renderForm() []string {
	if m.form == nil {
		return []string{m.msg.FormUnavailable}
	}
	title := m.msg.SSHTargetTitle
	if m.form.kind == formDatabase {
		title = m.msg.DBTargetTitle
	}
	lines := []string{title, ""}
	if m.isCompactLayout() {
		field := m.form.fields[m.form.index]
		lines = append(lines, fmt.Sprintf("%d/%d  %s", m.form.index+1, len(m.form.fields), compactText(field.label, max(1, m.contentWidth()-6))))
		lines = append(lines, inputLinePrefix+m.input.View())
		return append(lines, "", m.msg.FormHelpCompact1, m.msg.FormHelpCompact2)
	}
	for index, field := range m.form.fields {
		value := field.value
		if field.secret && value != "" {
			value = m.msg.SecretMasked
		}
		if index == m.form.index {
			lines = append(lines, inputLinePrefix+m.input.View())
			if field.hint != "" {
				lines = append(lines, "  "+field.hint)
			}
		} else {
			lines = append(lines, "  "+field.label+m.msg.FieldSeparator+value)
		}
	}
	lines = append(lines, "", m.msg.FormHelpFull)
	return lines
}

func (m *Model) renderFingerprintConfirmation() []string {
	if m.pending == nil {
		return []string{m.msg.FingerprintConfirmUnavailable}
	}
	return []string{
		m.msg.FingerprintConfirmTitle,
		"",
		m.pending.fingerprint,
		"",
		m.msg.FingerprintConfirmHelp,
	}
}

func (m *Model) renderTargetDeleteConfirmation() []string {
	if m.deleting == nil {
		return []string{m.msg.DeleteConfirmUnavailable}
	}
	return []string{
		m.msg.DeleteConfirmTitle,
		"",
		m.deleting.label,
		"",
		m.msg.DeleteConfirmWarning,
		"",
		m.msg.DeleteConfirmHelp,
	}
}

func (m *Model) renderMaintenance() []string {
	if m.maintenance == nil {
		return []string{m.msg.MaintenanceUnavailable}
	}
	title := m.msg.MaintenanceBackupTitle
	switch m.maintenance.action {
	case maintenanceRestore:
		title = m.msg.MaintenanceRestoreTitle
	case maintenanceRotate:
		title = m.msg.MaintenanceRotateTitle
	case maintenanceChangeMasterPassword:
		title = m.msg.MaintenanceChangePasswordTitle
	}
	lines := []string{title, ""}
	for index, field := range m.maintenance.fields {
		value := field.value
		if field.secret && value != "" {
			value = m.msg.SecretMasked
		}
		if index == m.maintenance.index {
			lines = append(lines, "> "+m.input.View())
		} else {
			lines = append(lines, "  "+field.label+m.msg.FieldSeparator+value)
		}
	}
	lines = append(lines, "", m.msg.MaintenanceHelpFull)
	return lines
}

func (m *Model) beginUnlock() {
	m.screen = screenUnlock
	m.input = textinput.New()
	m.input.SetVirtualCursor(false)
	m.input.Prompt = m.msg.UnlockPrompt
	m.input.EchoMode = textinput.EchoPassword
	m.input.EchoCharacter = '*'
	m.input.SetWidth(textInputWidth(m.width, m.input.Prompt, ""))
	_ = m.input.Focus()
}

func (m *Model) beginSSHForm(target store.SSHTarget) {
	port := target.SSHPort
	if port == 0 {
		port = 22
	}
	fields := []formField{
		{label: m.msg.SSHFieldIP, value: target.IP},
		{label: m.msg.SSHFieldPort, value: strconv.Itoa(port)},
		{label: m.msg.SSHFieldUsername, value: target.LoginUsername},
		{label: m.msg.SSHFieldPassword, secret: true},
		{label: m.msg.SSHFieldBlacklist, value: strings.Join(target.CommandBlacklistPatterns, ","), hint: m.msg.SSHFieldBlacklistHint},
		{label: m.msg.SSHFieldDescription, value: target.Description},
		{label: m.msg.SSHFieldEnvironment, value: target.Environment},
		{label: m.msg.SSHFieldAllowFile, value: strconv.FormatBool(target.AllowFileOperations), hint: m.msg.SSHFieldAllowFileHint},
	}
	m.form = &targetForm{kind: formSSH, enabled: target.Enabled, ssh: &target, fields: fields}
	m.screen = screenForm
	m.loadCurrentField()
}

func (m *Model) beginDatabaseForm(instance store.DatabaseInstance) {
	port := instance.Port
	if port == 0 {
		port = 3306
	}
	if instance.TransportPolicy == "" {
		instance.TransportPolicy = store.DatabaseLegacyPlaintext
	}
	m.form = &targetForm{kind: formDatabase, enabled: instance.Enabled, database: &instance, fields: []formField{
		{label: m.msg.DBFieldHost, value: instance.Host},
		{label: m.msg.DBFieldPort, value: strconv.Itoa(port)},
		{label: m.msg.DBFieldEngine, value: string(instance.Engine)},
		{label: m.msg.DBFieldDefaultDB, value: instance.DefaultDatabase},
		{label: m.msg.DBFieldReadUsername, value: instance.ReadUsername},
		{label: m.msg.DBFieldReadPassword, secret: true},
		{label: m.msg.DBFieldWriteUsername, value: instance.WriteUsername},
		{label: m.msg.DBFieldWritePassword, secret: true},
		{label: m.msg.DBFieldPolicy, value: string(instance.TransportPolicy)},
		{label: m.msg.DBFieldTLSCAPath, value: instance.TLSCAPath},
		{label: m.msg.DBFieldDescription, value: instance.Description},
		{label: m.msg.DBFieldEnvironment, value: instance.Environment},
	}}
	m.screen = screenForm
	m.loadCurrentField()
}

func (m *Model) editSelectedTarget() {
	if m.selected < len(m.targets.SSH) {
		m.beginSSHForm(m.targets.SSH[m.selected])
		return
	}
	index := m.selected - len(m.targets.SSH)
	if index >= 0 && index < len(m.targets.Databases) {
		m.beginDatabaseForm(m.targets.Databases[index])
	}
}

func (m *Model) toggleSelectedTarget() tea.Cmd {
	if m.selected < len(m.targets.SSH) {
		target := m.targets.SSH[m.selected]
		return m.call("target_toggled", "target.set_ssh_enabled", control.SetSSHTargetEnabledParams{IP: target.IP, Enabled: !target.Enabled}, &struct{}{})
	}
	index := m.selected - len(m.targets.SSH)
	if index >= 0 && index < len(m.targets.Databases) {
		instance := m.targets.Databases[index]
		return m.call("target_toggled", "target.set_database_enabled", control.SetDatabaseInstanceEnabledParams{Host: instance.Host, Port: instance.Port, Enabled: !instance.Enabled}, &struct{}{})
	}
	return nil
}

func (m *Model) beginTargetDelete() {
	if !m.status.Unlocked {
		m.notice = m.msg.DeleteRequireUnlock
		return
	}
	if m.selected < len(m.targets.SSH) {
		target := m.targets.SSH[m.selected]
		m.deleting = &pendingTargetDelete{
			label:  m.msg.TargetKindSSH + "  " + target.IP,
			method: "target.delete_ssh",
			params: control.DeleteSSHTargetParams{IP: target.IP},
		}
		m.screen = screenTargetDeleteConfirm
		return
	}
	index := m.selected - len(m.targets.SSH)
	if index >= 0 && index < len(m.targets.Databases) {
		instance := m.targets.Databases[index]
		m.deleting = &pendingTargetDelete{
			label:  fmt.Sprintf("%s  %s:%d", m.msg.TargetKindDB, instance.Host, instance.Port),
			method: "target.delete_database",
			params: control.DeleteDatabaseInstanceParams{Host: instance.Host, Port: instance.Port},
		}
		m.screen = screenTargetDeleteConfirm
	}
}

func (m *Model) submitForm() tea.Cmd {
	if m.form == nil {
		return nil
	}
	if !m.status.Unlocked {
		m.notice = m.msg.SaveRequireUnlock
		return nil
	}
	value := func(index int) string { return m.form.fields[index].value }
	if m.form.kind == formSSH {
		port, err := strconv.Atoi(value(1))
		if err != nil {
			m.notice = m.msg.FormSSHPortInvalid
			return nil
		}
		credentialID := m.form.ssh.CredentialID
		if credentialID == "" {
			credentialID = "ssh:" + value(0)
		}
		allowFileOperations, parseErr := strconv.ParseBool(strings.TrimSpace(value(7)))
		if parseErr != nil {
			m.notice = m.msg.FormSSHAllowFileInvalid
			return nil
		}
		params := control.UpsertSSHTargetParams{Target: store.SSHTarget{
			IP: value(0), Mode: store.SSHDirect, SSHPort: port, LoginUsername: value(2),
			CredentialID: credentialID, CommandBlacklistPatterns: commaSeparated(value(4)),
			Description: value(5), Environment: value(6), AllowFileOperations: allowFileOperations, Enabled: m.form.enabled,
		}, Password: value(3)}
		m.form.fields[3].value = ""
		return m.beginTargetTest("ssh.test_target", control.SSHTestParams{Target: params.Target, Password: params.Password}, "target.upsert_ssh", params)
	}

	port, err := strconv.Atoi(value(1))
	if err != nil {
		m.notice = m.msg.FormDBPortInvalid
		return nil
	}
	readCredentialID, writeCredentialID := m.form.database.ReadCredentialID, m.form.database.WriteCredentialID
	writeUsername := strings.TrimSpace(value(6))
	if readCredentialID == "" && value(5) != "" {
		readCredentialID = fmt.Sprintf("database:%s:%d:read", value(0), port)
	}
	reuseReadCredential := writeUsername != "" && writeUsername == strings.TrimSpace(value(4)) && value(7) == ""
	if writeUsername == "" {
		writeCredentialID = ""
	} else if reuseReadCredential {
		writeCredentialID = ""
	} else if writeCredentialID == "" && value(7) != "" {
		writeCredentialID = fmt.Sprintf("database:%s:%d:write", value(0), port)
	}
	if strings.TrimSpace(value(4)) == "" || readCredentialID == "" {
		m.notice = m.msg.FormDBMissingRead
		return nil
	}
	if (writeUsername == "" && value(7) != "") || (writeUsername != "" && writeCredentialID == "" && !reuseReadCredential) {
		m.notice = m.msg.FormDBMissingWrite
		return nil
	}
	params := control.UpsertDatabaseInstanceParams{Instance: store.DatabaseInstance{
		Host: value(0), Port: port, Engine: store.DatabaseEngine(value(2)), DefaultDatabase: value(3),
		ReadUsername: value(4), WriteUsername: writeUsername,
		ReadCredentialID: readCredentialID, WriteCredentialID: writeCredentialID,
		TransportPolicy: store.DatabaseTransportPolicy(value(8)), TLSCAPath: value(9),
		Description: value(10), Environment: value(11), Enabled: m.form.enabled,
	}, ReadPassword: value(5), WritePassword: value(7)}
	m.form.fields[5].value, m.form.fields[7].value = "", ""
	return m.beginDatabaseTest(params)
}

func commaSeparated(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func (m *Model) beginTargetTest(testMethod string, testParams any, saveMethod string, saveParams any) tea.Cmd {
	m.pending = &pendingTargetSave{testMethod: testMethod, testParams: testParams, saveMethod: saveMethod, saveParams: saveParams}
	return m.call("target_tested", testMethod, testParams, &control.SSHTestResult{})
}

func (m *Model) beginDatabaseTest(params control.UpsertDatabaseInstanceParams) tea.Cmd {
	testParams := control.DatabaseTestParams{
		Instance: params.Instance, ReadPassword: params.ReadPassword, WritePassword: params.WritePassword,
	}
	m.pending = &pendingTargetSave{testMethod: "database.test_target", testParams: testParams, saveMethod: "target.upsert_database", saveParams: params}
	return m.call("database_tested", "database.test_target", testParams, &control.DatabaseTestResult{})
}

func (m *Model) savePendingTarget() tea.Cmd {
	if m.pending == nil {
		m.notice = m.msg.PendingTargetNotFound
		return nil
	}
	return m.call("target_saved", m.pending.saveMethod, m.pending.saveParams, &struct{}{})
}

func confirmedFingerprintParams(params any, fingerprint string) (any, bool) {
	switch value := params.(type) {
	case control.SSHTestParams:
		value.ConfirmedFingerprint = fingerprint
		return value, true
	default:
		return nil, false
	}
}

func (m *Model) saveCurrentField() {
	if m.form == nil {
		return
	}
	m.form.fields[m.form.index].value = m.input.Value()
}

func (m *Model) loadCurrentField() {
	field := m.form.fields[m.form.index]
	m.input = textinput.New()
	m.input.SetVirtualCursor(false)
	m.input.Prompt = field.label + m.msg.FieldSeparator
	m.input.EchoMode = textinput.EchoNormal
	if field.secret {
		m.input.EchoMode = textinput.EchoPassword
		m.input.EchoCharacter = '*'
	}
	m.input.SetWidth(textInputWidth(m.width, m.input.Prompt, inputLinePrefix))
	m.input.SetValue(field.value)
	_ = m.input.Focus()
}

func (m *Model) clearForm() {
	if m.form != nil {
		for index := range m.form.fields {
			if m.form.fields[index].secret {
				m.form.fields[index].value = ""
			}
		}
	}
	m.form = nil
	m.input.SetValue("")
}

func (m *Model) clearPendingTarget() {
	if m.pending == nil {
		return
	}
	// The password is only held while a user is deciding whether to persist it.
	switch value := m.pending.testParams.(type) {
	case control.SSHTestParams:
		value.Password = ""
		m.pending.testParams = value
	case control.DatabaseTestParams:
		value.ReadPassword = ""
		value.WritePassword = ""
		m.pending.testParams = value
	}
	switch value := m.pending.saveParams.(type) {
	case control.UpsertSSHTargetParams:
		value.Password = ""
		m.pending.saveParams = value
	case control.UpsertDatabaseInstanceParams:
		value.ReadPassword = ""
		value.WritePassword = ""
		m.pending.saveParams = value
	}
	m.pending = nil
}

func (m *Model) beginMaintenance(action maintenanceAction) {
	form := &maintenanceForm{action: action}
	switch action {
	case maintenanceBackup:
		form.fields = []formField{{label: m.msg.MaintenanceFieldBackupDest}, {label: m.msg.MaintenanceFieldMasterPassword, secret: true}}
	case maintenanceRestore:
		form.fields = []formField{{label: m.msg.MaintenanceFieldRestoreSrc}, {label: m.msg.MaintenanceFieldRestoreDest}, {label: m.msg.MaintenanceFieldMasterPassword, secret: true}}
	case maintenanceRotate:
		form.fields = []formField{{label: m.msg.MaintenanceFieldRotateConfirm}, {label: m.msg.MaintenanceFieldMasterPassword, secret: true}}
	case maintenanceChangeMasterPassword:
		form.fields = []formField{{label: m.msg.MaintenanceFieldCurrentPassword, secret: true}, {label: m.msg.MaintenanceFieldNewPassword, secret: true}}
	}
	m.maintenance = form
	m.screen = screenMaintenance
	m.loadMaintenanceField()
}

func (m *Model) submitMaintenance() tea.Cmd {
	if m.maintenance == nil {
		return nil
	}
	value := func(index int) string { return m.maintenance.fields[index].value }
	switch m.maintenance.action {
	case maintenanceBackup:
		params := control.BackupCreateParams{Destination: value(0), MasterPassword: value(1)}
		m.maintenance.fields[1].value = ""
		return m.call("maintenance_done", "backup.create", params, &struct{}{})
	case maintenanceRestore:
		params := control.BackupRestoreParams{Source: value(0), Destination: value(1), MasterPassword: value(2)}
		m.maintenance.fields[2].value = ""
		return m.call("maintenance_done", "backup.restore", params, &struct{}{})
	case maintenanceRotate:
		params := control.RotateDataKeyParams{Confirmation: value(0), MasterPassword: value(1)}
		m.maintenance.fields[1].value = ""
		return m.call("maintenance_done", "keys.rotate", params, &struct{}{})
	case maintenanceChangeMasterPassword:
		params := control.ChangeMasterPasswordParams{OldMasterPassword: value(0), NewMasterPassword: value(1)}
		m.maintenance.fields[0].value = ""
		m.maintenance.fields[1].value = ""
		return m.call("maintenance_done", "keys.change_master_password", params, &struct{}{})
	}
	return nil
}

func (m *Model) saveMaintenanceField() {
	if m.maintenance != nil {
		m.maintenance.fields[m.maintenance.index].value = m.input.Value()
	}
}

func (m *Model) loadMaintenanceField() {
	field := m.maintenance.fields[m.maintenance.index]
	m.input = textinput.New()
	m.input.SetVirtualCursor(false)
	m.input.Prompt = field.label + m.msg.FieldSeparator
	m.input.EchoMode = textinput.EchoNormal
	if field.secret {
		m.input.EchoMode = textinput.EchoPassword
		m.input.EchoCharacter = '*'
	}
	m.input.SetWidth(textInputWidth(m.width, m.input.Prompt, inputLinePrefix))
	m.input.SetValue(field.value)
	_ = m.input.Focus()
}

func (m *Model) clearMaintenance() {
	if m.maintenance != nil {
		for index := range m.maintenance.fields {
			if m.maintenance.fields[index].secret {
				m.maintenance.fields[index].value = ""
			}
		}
	}
	m.maintenance = nil
	m.input.SetValue("")
}

func (m *Model) targetCount() int {
	return len(m.targets.SSH) + len(m.targets.Databases)
}

func (m *Model) clampSelected(count int) {
	if count == 0 {
		m.selected = 0
		return
	}
	if m.selected >= count {
		m.selected = count - 1
	}
}

func (m *Model) targetMarker(index int) string {
	if index == m.selected {
		return "> "
	}
	return "  "
}

func (m *Model) loadStatus() tea.Cmd {
	return m.call("status", "status", nil, &control.Status{})
}

func (m *Model) loadTargets() tea.Cmd {
	return m.call("targets", "targets.list", nil, &control.TargetsResult{})
}

func (m *Model) call(action, method string, params any, output any) tea.Cmd {
	return func() tea.Msg {
		if m.client == nil {
			return rpcMsg{action: action, err: fmt.Errorf("local control client is unavailable")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := m.client.Call(ctx, method, params, output)
		if err != nil {
			return rpcMsg{action: action, err: err}
		}
		switch value := output.(type) {
		case *control.Status:
			return rpcMsg{action: action, value: *value}
		case *control.TargetsResult:
			return rpcMsg{action: action, value: *value}
		case *control.UnlockResult:
			return rpcMsg{action: action, value: *value}
		case *control.SSHTestResult:
			return rpcMsg{action: action, value: *value}
		case *control.DatabaseTestResult:
			return rpcMsg{action: action, value: *value}
		default:
			return rpcMsg{action: action, value: struct{}{}}
		}
	}
}

func (m *Model) enabledText(enabled bool) string {
	if enabled {
		return m.msg.Enabled
	}
	return m.msg.Disabled
}

func (m *Model) databaseAccountText(instance store.DatabaseInstance) string {
	if instance.WriteUsername == "" {
		return m.msg.DBNoWriteAccount
	}
	if instance.WriteCredentialID == "" && instance.WriteUsername == instance.ReadUsername {
		return m.msg.DBWriteAccountReuse
	}
	return m.msg.DBWriteAccountConfigured
}

func (m *Model) databaseSecurityText(security store.TransportSecurity) string {
	switch security {
	case store.TransportTLSVerified:
		return m.msg.SecurityTLSVerified
	case store.TransportTLSUnverified:
		return m.msg.SecurityTLSUnverified
	case store.TransportPlaintext:
		return m.msg.SecurityPlaintext
	default:
		return m.msg.SecurityUntested
	}
}

func (m *Model) databaseTransportPolicyText(policy store.DatabaseTransportPolicy) string {
	switch policy {
	case store.DatabaseTLSVerified:
		return m.msg.PolicyTLSVerified
	case store.DatabaseLegacyPlaintext:
		return m.msg.PolicyLegacyPlaintext
	default:
		return m.msg.PolicyLegacyPlaintext
	}
}

func enabledText(enabled bool) string {
	return (&Model{msg: messagesZH}).enabledText(enabled)
}

func databaseAccountText(instance store.DatabaseInstance) string {
	return (&Model{msg: messagesZH}).databaseAccountText(instance)
}

func databaseSecurityText(security store.TransportSecurity) string {
	return (&Model{msg: messagesZH}).databaseSecurityText(security)
}

func databaseTransportPolicyText(policy store.DatabaseTransportPolicy) string {
	return (&Model{msg: messagesZH}).databaseTransportPolicyText(policy)
}
