package tui

import (
	"context"
	"errors"
	"fmt"

	"ssh-mcp/internal/ipc"
)

type Messages struct {
	// Header
	ConsoleTitle  string
	LockedState   string
	UnlockedState string

	// Dashboard
	DashboardFullHelp    string
	DashboardCompactHelp string

	// Unlock screen
	UnlockTitle string
	UnlockPrompt string
	UnlockHelp  string

	// Targets screen
	TargetsTitle            string
	NoTargets               string
	TargetsHelpFull         string
	TargetsCompactHelp1     string
	TargetsCompactHelp2     string
	TargetKindSSH           string
	TargetKindDB            string
	Enabled                 string
	Disabled                string
	DBNoWriteAccount        string
	DBWriteAccountReuse     string
	DBWriteAccountConfigured string
	SecurityTLSVerified     string
	SecurityTLSUnverified   string
	SecurityPlaintext       string
	SecurityUntested        string
	PolicyTLSVerified       string
	PolicyLegacyPlaintext   string

	// Forms general
	FormUnavailable     string
	SSHTargetTitle      string
	DBTargetTitle       string
	SecretMasked        string
	FieldSeparator      string
	FormHelpFull        string
	FormHelpCompact1    string
	FormHelpCompact2    string

	// SSH Form fields
	SSHFieldIP            string
	SSHFieldPort          string
	SSHFieldUsername      string
	SSHFieldPassword      string
	SSHFieldBlacklist     string
	SSHFieldBlacklistHint string
	SSHFieldDescription   string
	SSHFieldEnvironment   string
	SSHFieldAllowFile     string
	SSHFieldAllowFileHint string

	// Database Form fields
	DBFieldHost          string
	DBFieldPort          string
	DBFieldEngine        string
	DBFieldDefaultDB     string
	DBFieldReadUsername  string
	DBFieldReadPassword  string
	DBFieldWriteUsername string
	DBFieldWritePassword string
	DBFieldPolicy        string
	DBFieldTLSCAPath     string
	DBFieldDescription   string
	DBFieldEnvironment   string

	// Maintenance
	MaintenanceUnavailable          string
	MaintenanceBackupTitle          string
	MaintenanceRestoreTitle         string
	MaintenanceRotateTitle          string
	MaintenanceChangePasswordTitle  string
	MaintenanceHelpFull             string
	MaintenanceFieldBackupDest      string
	MaintenanceFieldRestoreSrc      string
	MaintenanceFieldRestoreDest     string
	MaintenanceFieldMasterPassword  string
	MaintenanceFieldRotateConfirm   string
	MaintenanceFieldCurrentPassword string
	MaintenanceFieldNewPassword     string

	// Confirmations
	FingerprintConfirmUnavailable string
	FingerprintConfirmTitle       string
	FingerprintConfirmHelp        string
	FingerprintInvalidRequest     string
	FingerprintNotConfirmedNotice string
	DeleteConfirmUnavailable      string
	DeleteConfirmTitle            string
	DeleteConfirmWarning          string
	DeleteConfirmHelp             string
	DeleteCancelledNotice         string

	// Notices
	PasteHint                 string
	PasteEmpty                string
	PasteWhitespace           string
	PasteTooLong              string
	PasteSecret               string
	PastedRunesCount          func(int) string
	UnlockCreatedNotice       string
	UnlockSuccessNotice       string
	LockedNotice              string
	MaintenanceDoneNotice     string
	LanguageSwitchedZHNotice  string
	LanguageSwitchedENNotice  string
	FormSSHPortInvalid        string
	FormSSHAllowFileInvalid   string
	FormDBPortInvalid         string
	FormDBMissingRead         string
	FormDBMissingWrite        string
	DeleteRequireUnlock       string
	SaveRequireUnlock         string
	PendingTargetNotFound     string
	SSHTestRequestInvalid     string
	DBTestRequestInvalid      string

	// Local control error notice function
	LocalControlErrorNotice func(action string, err error) string
}

var messagesZH = &Messages{
	ConsoleTitle:  "ssh-mcp 本地控制台",
	LockedState:   "已锁定",
	UnlockedState: "已解锁",

	DashboardFullHelp:    "u 解锁    t 目标    b 备份    o 恢复    k 轮换密钥    p 修改主密码    l 锁定    e 语言    q 退出",
	DashboardCompactHelp: "u 解锁  t 目标  e 语言  q 退出",

	UnlockTitle:  "输入主密码",
	UnlockPrompt: "主密码：",
	UnlockHelp:   "Enter 解锁  Esc 返回  Shift+Ins 粘贴",

	TargetsTitle:            "目标",
	NoTargets:               "暂无目标",
	TargetsHelpFull:         "n 新增 SSH    d 新增数据库    Enter 编辑    x 启用/停用    Delete 删除    r 刷新    Esc 返回",
	TargetsCompactHelp1:     "n 新增  Enter 编辑",
	TargetsCompactHelp2:     "x 启停  Esc 返回",
	TargetKindSSH:           "SSH",
	TargetKindDB:            "数据库",
	Enabled:                 "启用",
	Disabled:                "停用",
	DBNoWriteAccount:        "未配置写账号",
	DBWriteAccountReuse:     "写账号复用只读凭据",
	DBWriteAccountConfigured: "写账号已配置",
	SecurityTLSVerified:     "TLS 已验证",
	SecurityTLSUnverified:   "TLS 未验证",
	SecurityPlaintext:       "明文",
	SecurityUntested:        "未测试",
	PolicyTLSVerified:       "要求 TLS",
	PolicyLegacyPlaintext:   "旧式明文",

	FormUnavailable:  "表单不可用",
	SSHTargetTitle:   "SSH 目标",
	DBTargetTitle:    "数据库实例",
	SecretMasked:     "已设置",
	FieldSeparator:   "：",
	FormHelpFull:     "Tab/Enter 切换字段    Ctrl+S 保存    Esc 取消    Shift+Ins 粘贴",
	FormHelpCompact1: "Tab 字段  Ctrl+S 保存",
	FormHelpCompact2: "Esc 取消  Shift+Ins 粘贴",

	SSHFieldIP:            "IP",
	SSHFieldPort:          "SSH 端口",
	SSHFieldUsername:      "登录账号",
	SSHFieldPassword:      "密码（留空不修改）",
	SSHFieldBlacklist:     "命令黑名单（正则，逗号分隔）",
	SSHFieldBlacklistHint: "多个正则用英文逗号分隔；任一正则匹配命令文本即拦截。例：rm /data/.*, cat /etc/passwd, passwd.*",
	SSHFieldDescription:   "说明",
	SSHFieldEnvironment:   "环境",
	SSHFieldAllowFile:     "允许文件读写（true/false）",
	SSHFieldAllowFileHint: "开启后允许 read_ssh_file 和 deploy_ssh_binary；新建目标默认 true。",

	DBFieldHost:          "IP",
	DBFieldPort:          "端口",
	DBFieldEngine:        "引擎（mysql/postgresql）",
	DBFieldDefaultDB:     "默认数据库",
	DBFieldReadUsername:  "只读账号",
	DBFieldReadPassword:  "只读密码（留空不修改）",
	DBFieldWriteUsername: "可写账号（可选；填写后用于变更 SQL，可与只读账号相同）",
	DBFieldWritePassword: "可写密码（同账号可留空复用只读密码；不同账号必填）",
	DBFieldPolicy:        "传输策略（tls_verified/legacy_plaintext）",
	DBFieldTLSCAPath:     "CA 证书文件（tls_verified 必填）",
	DBFieldDescription:   "说明",
	DBFieldEnvironment:   "环境",

	MaintenanceUnavailable:          "维护表单不可用",
	MaintenanceBackupTitle:          "创建加密备份",
	MaintenanceRestoreTitle:         "恢复备份到独立本地文件",
	MaintenanceRotateTitle:          "显式轮换数据密钥",
	MaintenanceChangePasswordTitle:  "修改主密码",
	MaintenanceHelpFull:             "Tab/Enter 切换字段    Ctrl+S 确认    Esc 取消    Shift+Ins 粘贴",
	MaintenanceFieldBackupDest:      "备份文件路径",
	MaintenanceFieldRestoreSrc:      "备份文件路径",
	MaintenanceFieldRestoreDest:     "恢复目标路径",
	MaintenanceFieldMasterPassword:  "主密码",
	MaintenanceFieldRotateConfirm:   "确认文本（输入 ROTATE）",
	MaintenanceFieldCurrentPassword: "当前主密码",
	MaintenanceFieldNewPassword:     "新主密码",

	FingerprintConfirmUnavailable: "SSH 主机指纹确认不可用",
	FingerprintConfirmTitle:       "SSH 主机指纹确认",
	FingerprintConfirmHelp:        "y 确认并测试    n 拒绝并返回编辑    Esc 返回编辑",
	FingerprintInvalidRequest:     "指纹确认请求无效。",
	FingerprintNotConfirmedNotice: "未确认 SSH 主机指纹，目标未保存。",
	DeleteConfirmUnavailable:      "删除目标不可用",
	DeleteConfirmTitle:            "删除目标",
	DeleteConfirmWarning:          "删除会撤销未执行的授权，并清理未引用的凭据。",
	DeleteConfirmHelp:             "y 删除    n 取消    Esc 取消",
	DeleteCancelledNotice:         "已取消删除目标。",

	PasteHint:                 "请使用终端粘贴：Shift+Ins 或 Cmd+V。",
	PasteEmpty:                "粘贴内容为空。",
	PasteWhitespace:           "粘贴内容包含空白字符，已忽略。",
	PasteTooLong:              "粘贴内容超过长度上限，已忽略。",
	PasteSecret:               "已粘贴。",
	PastedRunesCount:          func(n int) string { return fmt.Sprintf("已粘贴 %d 个字符。", n) },
	UnlockCreatedNotice:       "已创建并解锁本地凭据库。",
	UnlockSuccessNotice:       "已解锁本地凭据库。",
	LockedNotice:              "本地凭据库已锁定。",
	MaintenanceDoneNotice:     "维护操作已完成。",
	LanguageSwitchedZHNotice:  "已切换为中文。",
	LanguageSwitchedENNotice:  "已切换为英文。",
	FormSSHPortInvalid:        "SSH 端口必须是整数。",
	FormSSHAllowFileInvalid:   "允许文件读写必须填写 true 或 false。",
	FormDBPortInvalid:         "数据库端口必须是整数。",
	FormDBMissingRead:         "必须填写只读账号和密码。",
	FormDBMissingWrite:        "不同于只读账号的可写账号必须同时填写密码。",
	DeleteRequireUnlock:       "请先解锁本地凭据库后再删除目标。",
	SaveRequireUnlock:         "本地凭据库已锁定，请先解锁后再保存。",
	PendingTargetNotFound:     "找不到待保存目标。",
	SSHTestRequestInvalid:     "SSH 测试请求无效。",
	DBTestRequestInvalid:      "数据库测试请求无效。",

	LocalControlErrorNotice: localControlErrorNoticeZH,
}

var messagesEN = &Messages{
	ConsoleTitle:  "ssh-mcp Console",
	LockedState:   "Locked",
	UnlockedState: "Unlocked",

	DashboardFullHelp:    "u Unlock  t Targets  b Backup  o Restore  k Rotate  p ChgPass  l Lock  e Lang  q Quit",
	DashboardCompactHelp: "u Unlock  t Targets  e Lang  q Quit",

	UnlockTitle:  "Enter Master Password",
	UnlockPrompt: "Master Password: ",
	UnlockHelp:   "Enter Unlock  Esc Back  Shift+Ins Paste",

	TargetsTitle:            "Targets",
	NoTargets:               "No targets registered",
	TargetsHelpFull:         "n Add SSH  d Add DB  Enter Edit  x Toggle  Delete Remove  r Refresh  Esc Back",
	TargetsCompactHelp1:     "n Add  Enter Edit",
	TargetsCompactHelp2:     "x Toggle  Esc Back",
	TargetKindSSH:           "SSH",
	TargetKindDB:            "DB",
	Enabled:                 "Enabled",
	Disabled:                "Disabled",
	DBNoWriteAccount:        "No write user",
	DBWriteAccountReuse:     "Write user reuses read credential",
	DBWriteAccountConfigured: "Write user configured",
	SecurityTLSVerified:     "TLS verified",
	SecurityTLSUnverified:   "TLS unverified",
	SecurityPlaintext:       "Plaintext",
	SecurityUntested:        "Untested",
	PolicyTLSVerified:       "Require TLS",
	PolicyLegacyPlaintext:   "Legacy plaintext",

	FormUnavailable:  "Form unavailable",
	SSHTargetTitle:   "SSH Target",
	DBTargetTitle:    "Database Instance",
	SecretMasked:     "Configured",
	FieldSeparator:   ": ",
	FormHelpFull:     "Tab/Enter Field  Ctrl+S Save  Esc Cancel  Shift+Ins Paste",
	FormHelpCompact1: "Tab Field  Ctrl+S Save",
	FormHelpCompact2: "Esc Cancel  Shift+Ins Paste",

	SSHFieldIP:            "IP",
	SSHFieldPort:          "SSH Port",
	SSHFieldUsername:      "Login Username",
	SSHFieldPassword:      "Password (leave empty to keep)",
	SSHFieldBlacklist:     "Command Blacklist (regex, comma-separated)",
	SSHFieldBlacklistHint: "Comma-separated regex patterns; blocks matching commands. E.g. rm /data/.*, cat /etc/passwd, passwd.*",
	SSHFieldDescription:   "Description",
	SSHFieldEnvironment:   "Environment",
	SSHFieldAllowFile:     "Allow File Operations (true/false)",
	SSHFieldAllowFileHint: "Enables read_ssh_file and deploy_ssh_binary; defaults to true.",

	DBFieldHost:          "Host/IP",
	DBFieldPort:          "Port",
	DBFieldEngine:        "Engine (mysql/postgresql)",
	DBFieldDefaultDB:     "Default Database",
	DBFieldReadUsername:  "Read Username",
	DBFieldReadPassword:  "Read Password (leave empty to keep)",
	DBFieldWriteUsername: "Write Username (optional, can be same as read user)",
	DBFieldWritePassword: "Write Password (leave empty if reusing read password)",
	DBFieldPolicy:        "Transport Policy (tls_verified/legacy_plaintext)",
	DBFieldTLSCAPath:     "CA Cert Path (required for tls_verified)",
	DBFieldDescription:   "Description",
	DBFieldEnvironment:   "Environment",

	MaintenanceUnavailable:          "Maintenance form unavailable",
	MaintenanceBackupTitle:          "Create Encrypted Backup",
	MaintenanceRestoreTitle:         "Restore Backup to Local File",
	MaintenanceRotateTitle:          "Explicitly Rotate Data Key",
	MaintenanceChangePasswordTitle:  "Change Master Password",
	MaintenanceHelpFull:             "Tab/Enter Field  Ctrl+S Confirm  Esc Cancel  Shift+Ins Paste",
	MaintenanceFieldBackupDest:      "Backup Destination Path",
	MaintenanceFieldRestoreSrc:      "Backup Source Path",
	MaintenanceFieldRestoreDest:     "Restore Destination Path",
	MaintenanceFieldMasterPassword:  "Master Password",
	MaintenanceFieldRotateConfirm:   "Confirmation Text (type ROTATE)",
	MaintenanceFieldCurrentPassword: "Current Master Password",
	MaintenanceFieldNewPassword:     "New Master Password",

	FingerprintConfirmUnavailable: "SSH host fingerprint confirmation unavailable",
	FingerprintConfirmTitle:       "SSH Host Fingerprint Confirmation",
	FingerprintConfirmHelp:        "y Confirm & Test  n Reject & Edit  Esc Back to Edit",
	FingerprintInvalidRequest:     "Invalid fingerprint confirmation request.",
	FingerprintNotConfirmedNotice: "SSH host fingerprint not confirmed; target was not saved.",
	DeleteConfirmUnavailable:      "Target deletion unavailable",
	DeleteConfirmTitle:            "Delete Target",
	DeleteConfirmWarning:          "Deletion revokes unexecuted authorizations and removes unreferenced credentials.",
	DeleteConfirmHelp:             "y Delete  n Cancel  Esc Cancel",
	DeleteCancelledNotice:         "Target deletion cancelled.",

	PasteHint:                 "Use terminal paste: Shift+Ins or Cmd+V.",
	PasteEmpty:                "Pasted content is empty.",
	PasteWhitespace:           "Pasted content contains whitespace; ignored.",
	PasteTooLong:              "Pasted content exceeds maximum length; ignored.",
	PasteSecret:               "Pasted.",
	PastedRunesCount:          func(n int) string { return fmt.Sprintf("Pasted %d characters.", n) },
	UnlockCreatedNotice:       "Local credential vault created and unlocked.",
	UnlockSuccessNotice:       "Local credential vault unlocked.",
	LockedNotice:              "Local credential vault is locked.",
	MaintenanceDoneNotice:     "Maintenance operation completed.",
	LanguageSwitchedZHNotice:  "已切换为中文。",
	LanguageSwitchedENNotice:  "Switched to English.",
	FormSSHPortInvalid:        "SSH port must be an integer.",
	FormSSHAllowFileInvalid:   "Allow file operations must be true or false.",
	FormDBPortInvalid:         "Database port must be an integer.",
	FormDBMissingRead:         "Read username and password are required.",
	FormDBMissingWrite:        "Write account different from read account requires a password.",
	DeleteRequireUnlock:       "Please unlock local credential vault before deleting targets.",
	SaveRequireUnlock:         "Local credential vault is locked; please unlock before saving.",
	PendingTargetNotFound:     "Pending target not found.",
	SSHTestRequestInvalid:     "Invalid SSH test request.",
	DBTestRequestInvalid:      "Invalid database test request.",

	LocalControlErrorNotice: localControlErrorNoticeEN,
}

func getMessages(lang string) *Messages {
	if lang == "en" {
		return messagesEN
	}
	return messagesZH
}

func localControlErrorNoticeZH(action string, err error) string {
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

func localControlErrorNoticeEN(action string, err error) string {
	switch {
	case errors.Is(err, ipc.ErrUnauthorized):
		return "Local console authorization expired; please reopen the console and retry."
	case errors.Is(err, ipc.ErrLocked):
		return "Local vault is locked; candidate test and save were not executed. Press u on Dashboard to unlock."
	case errors.Is(err, ipc.ErrCandidateNotDispatched):
		return "Candidate validation not dispatched: service is locked or in maintenance. Finish maintenance or unlock and retry."
	case errors.Is(err, ipc.ErrCandidateAuditWriteFailed):
		return "Candidate target not saved: failed to write audit record. Check disk space and database permissions."
	case errors.Is(err, ipc.ErrConfirmationRequired):
		if action == "target_saved" || action == "target_tested" {
			return "SSH host identity not confirmed; configuration not saved. Verify fingerprint on confirmation screen."
		}
		return "Local confirmation not completed; operation not saved. Verify details and confirm."
	case errors.Is(err, ipc.ErrCandidateConnectionFailed):
		return "Candidate connection test failed; configuration not saved. Check IP, port, network, and target status."
	case errors.Is(err, ipc.ErrCandidateAuthenticationFailed):
		return "Candidate authentication failed; configuration not saved. Verify username, password, and permissions."
	case errors.Is(err, ipc.ErrCandidateTLSFailed):
		return "Candidate TLS validation failed; configuration not saved. Check transport policy, CA cert, and server cert."
	case errors.Is(err, ipc.ErrInvalidRequest):
		switch action {
		case "target_tested", "target_saved":
			return "SSH target save failed: check IP, port, username, password, and command blacklist regex syntax."
		case "database_tested", "database_saved":
			return "Database target save failed: check IP, port, engine, read credentials, and write credentials."
		default:
			return "Invalid input; check current field and retry."
		}
	case errors.Is(err, ipc.ErrMethodNotFound):
		return "Local control service version mismatch; please restart ssh-mcp and retry."
	case errors.Is(err, context.DeadlineExceeded):
		return "Operation timed out without completing save or validation. Check target connectivity and retry."
	}

	switch action {
	case "target_tested":
		return "SSH target validation incomplete; not saved. Check input, network, credentials, and host fingerprint."
	case "database_tested":
		return "Database target validation incomplete; not saved. Check input, network, credentials, TLS CA, and settings."
	case "target_saved":
		return "SSH target not saved: candidate validation or write failed. Retry validation or check database and connection."
	case "database_saved":
		return "Database target not saved: candidate validation or write failed. Retry validation or check database and connection."
	default:
		return "Operation not completed. Check unlock state, input, and connectivity, then retry."
	}
}
