// Package tui implements the independent local terminal interface. It talks
// only to the authenticated local transport control channel.
package tui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

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
}

type rpcMsg struct {
	action string
	value  any
	err    error
}

func NewModel(client Caller) *Model {
	input := textinput.New()
	input.SetWidth(defaultInputWidth)
	return &Model{client: client, input: input}
}

const (
	defaultInputWidth    = 60
	minInputWidth        = 20
	inputLinePrefix      = "> "
	contentHorizontalPad = 2
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
			m.notice = "指纹确认请求无效。"
			return nil
		}
		m.pending.testParams = params
		return m.call("target_tested", m.pending.testMethod, params, &control.SSHTestResult{})
	case "n", "esc":
		m.clearPendingTarget()
		m.screen = screenForm
		m.notice = "未确认 SSH 主机指纹，目标未保存。"
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
		m.notice = "已取消删除目标。"
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
	var command tea.Cmd
	m.input, command = m.input.Update(message)
	return command
}

func (m *Model) applyRPC(message rpcMsg) tea.Cmd {
	if message.err != nil {
		if message.action == "target_tested" || message.action == "database_tested" {
			m.clearPendingTarget()
		}
		m.notice = localControlErrorNotice(message.action, message.err)
		return nil
	}
	m.notice = ""
	switch message.action {
	case "status":
		m.status = message.value.(control.Status)
	case "targets":
		m.targets = message.value.(control.TargetsResult)
		m.clampSelected(m.targetCount())
	case "unlocked":
		result := message.value.(control.UnlockResult)
		m.status.Unlocked = result.Unlocked
		m.status.Initialized = true
		m.screen = screenDashboard
		if result.Created {
			m.notice = "已创建并解锁本地凭据库。"
		} else {
			m.notice = "已解锁本地凭据库。"
		}
	case "locked":
		m.status.Unlocked = false
		m.notice = "本地凭据库已锁定。"
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
				m.notice = "找不到待保存目标。"
				return nil
			}
			m.pending.fingerprint = result.Fingerprint
			m.screen = screenFingerprintConfirm
			return nil
		}
		if m.pending == nil {
			m.notice = "找不到待保存目标。"
			return nil
		}
		params, ok := m.pending.saveParams.(control.UpsertSSHTargetParams)
		if !ok {
			m.notice = "SSH 测试请求无效。"
			return nil
		}
		params.ConfirmedFingerprint = result.Fingerprint
		m.pending.saveParams = params
		return m.savePendingTarget()
	case "database_tested":
		if m.pending == nil {
			m.notice = "找不到待保存目标。"
			return nil
		}
		params, ok := m.pending.saveParams.(control.UpsertDatabaseInstanceParams)
		if !ok {
			m.notice = "数据库测试请求无效。"
			return nil
		}
		params.Instance.TransportSecurity = message.value.(control.DatabaseTestResult).TransportSecurity
		m.pending.saveParams = params
		return m.savePendingTarget()
	case "maintenance_done":
		m.clearMaintenance()
		m.screen = screenDashboard
		m.notice = "维护操作已完成。"
	}
	return nil
}

func localControlErrorNotice(action string, err error) string {
	switch {
	case errors.Is(err, ipc.ErrUnauthorized):
		return "本地控制台授权已失效，请重新打开控制台后再操作。"
	case errors.Is(err, ipc.ErrLocked):
		return "本地凭据库已锁定，候选验证和保存均未执行。请先返回主页按 u 解锁后重试。"
	case errors.Is(err, ipc.ErrCandidateNotDispatched):
		return "候选验证未派发：本地服务正处于锁定、维护或停止派发状态，配置未保存。请完成当前维护或解锁后重试。"
	case errors.Is(err, ipc.ErrCandidateAuditWriteFailed):
		return "候选配置未保存：本地审计记录写入失败。请检查本机状态库的可写性和磁盘空间后重试。"
	case errors.Is(err, ipc.ErrConfirmationRequired):
		if action == "target_saved" || action == "target_tested" {
			return "SSH 主机身份尚未确认，配置未保存。请在指纹确认界面核对指纹后再确认。"
		}
		return "本地确认尚未完成，操作未保存。请核对显示内容后完成确认。"
	case errors.Is(err, ipc.ErrCandidateConnectionFailed):
		return "候选连接验证失败，配置未保存。请检查 IP、端口、网络连通性和目标服务状态后重试。"
	case errors.Is(err, ipc.ErrCandidateAuthenticationFailed):
		return "候选身份验证失败，配置未保存。请核对账号、密码及该账号的连接权限后重试。"
	case errors.Is(err, ipc.ErrCandidateTLSFailed):
		return "候选 TLS 验证失败，配置未保存。请核对传输策略、CA 证书文件和服务端证书后重试。"
	case errors.Is(err, ipc.ErrInvalidRequest):
		switch action {
		case "target_tested", "target_saved":
			return "SSH 目标保存失败：请检查 IP、端口、登录账号、密码和命令黑名单正则格式。"
		case "database_tested", "database_saved":
			return "数据库目标保存失败：请检查 IP、端口、引擎、只读账号密码，以及可写账号和密码是否同时填写。"
		default:
			return "操作输入无效，请检查当前字段后重试。"
		}
	case errors.Is(err, ipc.ErrMethodNotFound):
		return "本地控制服务版本不匹配，请重启 ssh-mcp 后重试。"
	case errors.Is(err, context.DeadlineExceeded):
		return "操作超时，未完成保存或验证。请检查目标连接状态后重试。"
	}

	switch action {
	case "target_tested":
		return "SSH 目标验证未完成，配置未保存。请检查输入、网络、端口、账号密码和主机指纹后重试。"
	case "database_tested":
		return "数据库目标验证未完成，配置未保存。请检查输入、网络、账号密码、传输策略、CA 证书和可写账号配置后重试。"
	case "target_saved":
		return "SSH 目标未保存：候选验证或本地配置写入未完成。请重新执行验证；若仍失败，请检查本机状态库和连接状态。"
	case "database_saved":
		return "数据库目标未保存：候选验证或本地配置写入未完成。请重新执行验证；若仍失败，请检查本机状态库和连接状态。"
	default:
		return "操作未完成，且本地服务未提供可安全展示的具体原因。请检查解锁状态、输入和连接状态后重试。"
	}
}

func (m *Model) View() tea.View {
	lines := []string{m.header(), ""}
	if m.notice != "" {
		lines = append(lines, m.notice, "")
	}
	switch m.screen {
	case screenUnlock:
		lines = append(lines, "输入主密码", m.input.View(), "", "Enter 解锁  Esc 返回")
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
	state := "已锁定"
	if m.status.Unlocked {
		state = "已解锁"
	}
	return "ssh-mcp 本地控制台  [" + state + "]"
}

func (m *Model) renderDashboard() []string {
	if m.isCompactLayout() {
		return []string{"u 解锁  t 目标  q 退出"}
	}
	return []string{
		"u 解锁    t 目标    b 备份    o 恢复    k 轮换密钥    p 修改主密码    l 锁定    q 退出",
	}
}

func (m *Model) renderTargets() []string {
	if m.isCompactLayout() {
		return m.renderCompactTargets()
	}
	lines := []string{"目标", ""}
	index := 0
	for _, target := range m.targets.SSH {
		lines = append(lines, m.targetMarker(index)+fmt.Sprintf("SSH  %s  %s  %s", target.IP, target.Mode, enabledText(target.Enabled)))
		index++
	}
	for _, instance := range m.targets.Databases {
		lines = append(lines, m.targetMarker(index)+fmt.Sprintf("数据库  %s:%d  %s  %s  %s  %s  %s", instance.Host, instance.Port, instance.Engine, databaseAccountText(instance), databaseTransportPolicyText(instance.TransportPolicy), databaseSecurityText(instance.TransportSecurity), enabledText(instance.Enabled)))
		index++
	}
	if index == 0 {
		lines = append(lines, "暂无目标")
	}
	lines = append(lines, "", "n 新增 SSH    d 新增数据库    Enter 编辑    x 启用/停用    Delete 删除    r 刷新    Esc 返回")
	return lines
}

func (m *Model) renderCompactTargets() []string {
	lines := []string{"目标"}
	index := 0
	width := max(1, m.contentWidth()-4)
	for _, target := range m.targets.SSH {
		lines = append(lines, m.targetMarker(index)+compactText("SSH "+target.IP, width))
		index++
	}
	for _, instance := range m.targets.Databases {
		lines = append(lines, m.targetMarker(index)+compactText(fmt.Sprintf("DB %s:%d", instance.Host, instance.Port), width))
		index++
	}
	if index == 0 {
		lines = append(lines, "暂无目标")
	}
	return append(lines, "", "n 新增  Enter 编辑", "x 启停  Esc 返回")
}

func (m *Model) renderForm() []string {
	if m.form == nil {
		return []string{"表单不可用"}
	}
	title := "SSH 目标"
	if m.form.kind == formDatabase {
		title = "数据库实例"
	}
	lines := []string{title, ""}
	if m.isCompactLayout() {
		field := m.form.fields[m.form.index]
		lines = append(lines, fmt.Sprintf("%d/%d  %s", m.form.index+1, len(m.form.fields), compactText(field.label, max(1, m.contentWidth()-6))))
		lines = append(lines, inputLinePrefix+m.input.View())
		return append(lines, "", "Tab 字段  Ctrl+S 保存", "Esc 取消")
	}
	for index, field := range m.form.fields {
		value := field.value
		if field.secret && value != "" {
			value = "已设置"
		}
		if index == m.form.index {
			lines = append(lines, inputLinePrefix+m.input.View())
			if field.hint != "" {
				lines = append(lines, "  "+field.hint)
			}
		} else {
			lines = append(lines, "  "+field.label+"："+value)
		}
	}
	lines = append(lines, "", "Tab/Enter 切换字段    Ctrl+S 保存    Esc 取消")
	return lines
}

func (m *Model) renderFingerprintConfirmation() []string {
	if m.pending == nil {
		return []string{"SSH 主机指纹确认不可用"}
	}
	return []string{
		"SSH 主机指纹确认",
		"",
		m.pending.fingerprint,
		"",
		"y 确认并测试    n 拒绝并返回编辑    Esc 返回编辑",
	}
}

func (m *Model) renderTargetDeleteConfirmation() []string {
	if m.deleting == nil {
		return []string{"删除目标不可用"}
	}
	return []string{
		"删除目标",
		"",
		m.deleting.label,
		"",
		"删除会撤销未执行的授权，并清理未引用的凭据。",
		"",
		"y 删除    n 取消    Esc 取消",
	}
}

func (m *Model) renderMaintenance() []string {
	if m.maintenance == nil {
		return []string{"维护表单不可用"}
	}
	title := "创建加密备份"
	switch m.maintenance.action {
	case maintenanceRestore:
		title = "恢复备份到独立本地文件"
	case maintenanceRotate:
		title = "显式轮换数据密钥"
	case maintenanceChangeMasterPassword:
		title = "修改主密码"
	}
	lines := []string{title, ""}
	for index, field := range m.maintenance.fields {
		value := field.value
		if field.secret && value != "" {
			value = "已设置"
		}
		if index == m.maintenance.index {
			lines = append(lines, "> "+m.input.View())
		} else {
			lines = append(lines, "  "+field.label+"："+value)
		}
	}
	lines = append(lines, "", "Tab/Enter 切换字段    Ctrl+S 确认    Esc 取消")
	return lines
}

func (m *Model) beginUnlock() {
	m.screen = screenUnlock
	m.input = textinput.New()
	m.input.SetVirtualCursor(false)
	m.input.Prompt = "主密码："
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
		{label: "IP", value: target.IP},
		{label: "SSH 端口", value: strconv.Itoa(port)},
		{label: "登录账号", value: target.LoginUsername},
		{label: "密码（留空不修改）", secret: true},
		{label: "命令黑名单（正则，逗号分隔）", value: strings.Join(target.CommandBlacklistPatterns, ","), hint: "多个正则用英文逗号分隔；任一正则匹配命令文本即拦截。例：rm /data/.*, cat /etc/passwd, passwd.*"},
		{label: "说明", value: target.Description},
		{label: "环境", value: target.Environment},
		{label: "允许文件读写（true/false）", value: strconv.FormatBool(target.AllowFileOperations), hint: "开启后允许 read_ssh_file 和 deploy_ssh_binary；新建目标默认 true。"},
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
		{label: "IP", value: instance.Host},
		{label: "端口", value: strconv.Itoa(port)},
		{label: "引擎（mysql/postgresql）", value: string(instance.Engine)},
		{label: "默认数据库", value: instance.DefaultDatabase},
		{label: "只读账号", value: instance.ReadUsername},
		{label: "只读密码（留空不修改）", secret: true},
		{label: "可写账号（可选；填写后用于变更 SQL，可与只读账号相同）", value: instance.WriteUsername},
		{label: "可写密码（同账号可留空复用只读密码；不同账号必填）", secret: true},
		{label: "传输策略（tls_verified/legacy_plaintext）", value: string(instance.TransportPolicy)},
		{label: "CA 证书文件（tls_verified 必填）", value: instance.TLSCAPath},
		{label: "说明", value: instance.Description},
		{label: "环境", value: instance.Environment},
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
		m.notice = "请先解锁本地凭据库后再删除目标。"
		return
	}
	if m.selected < len(m.targets.SSH) {
		target := m.targets.SSH[m.selected]
		m.deleting = &pendingTargetDelete{
			label:  "SSH  " + target.IP,
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
			label:  fmt.Sprintf("数据库  %s:%d", instance.Host, instance.Port),
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
		m.notice = "本地凭据库已锁定，请先解锁后再保存。"
		return nil
	}
	value := func(index int) string { return m.form.fields[index].value }
	if m.form.kind == formSSH {
		port, err := strconv.Atoi(value(1))
		if err != nil {
			m.notice = "SSH 端口必须是整数。"
			return nil
		}
		credentialID := m.form.ssh.CredentialID
		if credentialID == "" {
			credentialID = "ssh:" + value(0)
		}
		allowFileOperations, parseErr := strconv.ParseBool(strings.TrimSpace(value(7)))
		if parseErr != nil {
			m.notice = "允许文件读写必须填写 true 或 false。"
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
		m.notice = "数据库端口必须是整数。"
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
		m.notice = "必须填写只读账号和密码。"
		return nil
	}
	if (writeUsername == "" && value(7) != "") || (writeUsername != "" && writeCredentialID == "" && !reuseReadCredential) {
		m.notice = "不同于只读账号的可写账号必须同时填写密码。"
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
		m.notice = "找不到待保存目标。"
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
	m.input.Prompt = field.label + "："
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
		form.fields = []formField{{label: "备份文件路径"}, {label: "主密码", secret: true}}
	case maintenanceRestore:
		form.fields = []formField{{label: "备份文件路径"}, {label: "恢复目标路径"}, {label: "主密码", secret: true}}
	case maintenanceRotate:
		form.fields = []formField{{label: "确认文本（输入 ROTATE）"}, {label: "主密码", secret: true}}
	case maintenanceChangeMasterPassword:
		form.fields = []formField{{label: "当前主密码", secret: true}, {label: "新主密码", secret: true}}
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
	m.input.Prompt = field.label + "："
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

func enabledText(enabled bool) string {
	if enabled {
		return "启用"
	}
	return "停用"
}

func databaseAccountText(instance store.DatabaseInstance) string {
	if instance.WriteUsername == "" {
		return "未配置写账号"
	}
	if instance.WriteCredentialID == "" && instance.WriteUsername == instance.ReadUsername {
		return "写账号复用只读凭据"
	}
	return "写账号已配置"
}

func databaseSecurityText(security store.TransportSecurity) string {
	switch security {
	case store.TransportTLSVerified:
		return "TLS 已验证"
	case store.TransportTLSUnverified:
		return "TLS 未验证"
	case store.TransportPlaintext:
		return "明文"
	default:
		return "未测试"
	}
}

func databaseTransportPolicyText(policy store.DatabaseTransportPolicy) string {
	switch policy {
	case store.DatabaseTLSVerified:
		return "要求 TLS"
	case store.DatabaseLegacyPlaintext:
		return "旧式明文"
	default:
		return "旧式明文"
	}
}
