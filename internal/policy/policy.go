// Package policy classifies SSH and SQL requests before a transport is allowed
// to execute them. The rules are built in and versioned so callers cannot
// weaken the local security boundary.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"
	"mvdan.cc/sh/v3/syntax"
	"vitess.io/vitess/go/vt/sqlparser"

	"ssh-mcp/internal/store"
)

const (
	Version           = "2026-08-07.5"
	DefaultSSHTimeout = 60 * time.Second
	DefaultSQLTimeout = 30 * time.Second
	DefaultMaxRows    = 1000
	DefaultMaxBytes   = 16 << 10
)

type Decision string

const (
	DecisionAllowed  Decision = "direct"
	DecisionRejected Decision = "rejected"
	// DecisionPermanentlyRejected identifies a recognized match in the fixed,
	// daemon-local hard-stop registry. The stable wire value does not claim a
	// semantic or MCP-external universal prohibition.
	DecisionPermanentlyRejected Decision = "absolute_prohibited"
)

// SQLExecutionClass selects the database credential and transport path. The
// zero value is deliberately conservative and must be treated as may-write.
// This is routing metadata, not an approval state.
type SQLExecutionClass string

const (
	SQLExecutionMayWrite SQLExecutionClass = "may_write"
	SQLExecutionRead     SQLExecutionClass = "read_query"
)

type Reason string

const (
	ReasonDiagnostic             Reason = "bounded_diagnostic"
	ReasonStaticShell            Reason = "literal_static_shell"
	ReasonInvalidRequest         Reason = "invalid_request"
	ReasonTargetUnavailable      Reason = "target_unavailable"
	ReasonUnlockRequired         Reason = "unlock_required"
	ReasonTargetCommandBlacklist Reason = "target_command_blacklist"

	// Hard-stop reasons are stable identifiers for the fixed rule registry.
	ReasonFormatOrPartition         Reason = "format_or_partition"
	ReasonRawBlockDeviceWrite       Reason = "raw_block_device_write"
	ReasonBaseSystemTreeDestruction Reason = "base_system_tree_destruction"
	ReasonUnboundedResource         Reason = "unbounded_resource_exhaustion"
	ReasonOpaqueShellEffect         Reason = "opaque_shell_effect"
	ReasonOpaqueSQLEffect           Reason = "opaque_sql_effect"
	ReasonDropDatabaseSchemaTable   Reason = "drop_database_schema_table"
	ReasonTruncateTable             Reason = "truncate_table"
	ReasonAlterDrop                 Reason = "alter_drop"
	ReasonUnconditionalWrite        Reason = "unconditional_update_or_delete"
	ReasonUnregisteredRemoteHop     Reason = "unregistered_remote_hop"
)

type SSHRequest struct {
	Command                       string
	AsRoot                        bool
	WorkingDirectory              string
	Timeout                       time.Duration
	MaxBytes                      int
	CommandBlacklistPatterns      []string
	RegisteredRemoteTargets       []RegisteredRemoteTarget
	RemoteTargetRegistryAvailable bool
}

// RegisteredRemoteTarget is a non-secret SSH destination identity supplied by
// the runner from its local target registry. Nested remote clients can only
// connect to one of these exact IP and port pairs.
type RegisteredRemoteTarget struct {
	Host string
	Port int
}

type Risk string

const (
	RiskNone   Risk = ""
	RiskNormal Risk = "normal"
	RiskHigh   Risk = "high"
)

type SQLRequest struct {
	Engine    store.DatabaseEngine
	Statement string
	Timeout   time.Duration
	MaxRows   int
	MaxBytes  int
}

type Result struct {
	Decision                 Decision
	Reason                   Reason
	RuleID                   string
	MatchedFragment          string
	InteractiveInputRequired bool
	UseNonInteractiveSudo    bool
	Risk                     Risk
	ExecutionClass           SQLExecutionClass
	Normalized               string
	Payload                  string
	PayloadHash              string
	Timeout                  time.Duration
	MaxRows                  int
	MaxBytes                 int
}

var ErrNotExecutable = errors.New("permanently rejected requests cannot execute")

// Limiter bounds dispatch concurrency. It does not impose another policy
// classification layer: every non-hard-stopped request uses this lane.
type Limiter struct {
	lane chan struct{}
}

func NewLimiter(concurrency int) *Limiter {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &Limiter{lane: make(chan struct{}, concurrency)}
}

func (l *Limiter) Acquire(ctx context.Context, decision Decision) (func(), error) {
	if l == nil || decision != DecisionAllowed {
		return nil, ErrNotExecutable
	}
	select {
	case l.lane <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.lane }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func EvaluateSSH(request SSHRequest) Result {
	timeout, maxBytes := sshLimits(request)
	command := strings.TrimSpace(request.Command)
	workingDirectory, validWorkingDirectory := normalizedSSHWorkingDirectory(request.WorkingDirectory)
	result := sshResult(command, request.AsRoot, workingDirectory, timeout, maxBytes)
	if command == "" || timeout <= 0 || maxBytes <= 0 || !validWorkingDirectory {
		return withDecision(result, DecisionRejected, ReasonInvalidRequest)
	}
	blacklistPattern, err := matchTargetCommandBlacklist(command, request.CommandBlacklistPatterns)
	if err != nil {
		return withDecision(result, DecisionRejected, ReasonInvalidRequest)
	}

	analysis, err := analyzeShellProgram(command)
	if err != nil || len(analysis.commands) == 0 {
		// Syntax diagnostics belong to the remote shell. A local parser must
		// never become a second, stricter command language.
		if blacklistPattern != "" {
			return withTargetCommandBlacklist(result, blacklistPattern)
		}
		return withDecision(result, DecisionAllowed, ReasonStaticShell)
	}
	analysis.knownPathCommands = collectKnownPathCommands(command, workingDirectory)
	if match, found := matchSSHHardStop(command, analysis, request.RegisteredRemoteTargets, request.RemoteTargetRegistryAvailable); found {
		return withHardStop(result, match)
	}
	if blacklistPattern != "" {
		return withTargetCommandBlacklist(result, blacklistPattern)
	}
	result.InteractiveInputRequired = requiresInteractiveInput(analysis.commands)
	result.UseNonInteractiveSudo = hasLiteralSudoWrapper(analysis.commands)
	return withDecision(result, DecisionAllowed, ReasonStaticShell)
}

func EvaluateSQL(request SQLRequest) Result {
	timeout, maxRows, maxBytes := sqlLimits(request)
	statement := strings.TrimSpace(request.Statement)
	result := sqlResult(request.Engine, statement, timeout, maxRows, maxBytes)
	if statement == "" || timeout <= 0 || maxRows <= 0 || maxBytes <= 0 || !validEngine(request.Engine) {
		return withDecision(result, DecisionRejected, ReasonInvalidRequest)
	}
	switch request.Engine {
	case store.EngineMySQL:
		return evaluateMySQLDefaultAllow(result, request.Engine, statement, timeout, maxRows, maxBytes)
	case store.EnginePostgreSQL:
		return evaluatePostgreSQL(result, request.Engine, statement, timeout, maxRows, maxBytes)
	default:
		return withDecision(result, DecisionRejected, ReasonInvalidRequest)
	}
}

// SplitStatements parses and re-formats statements with the selected dialect
// parser. Parse failure is a routing concern for callers; it is not a policy
// rejection and must not be used to block direct execution.
func SplitStatements(engine store.DatabaseEngine, statement string) (result []string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("SQL parser failed: %v", recovered)
		}
	}()
	switch engine {
	case store.EngineMySQL:
		parsed, err := parseMySQLStatements(statement)
		if err != nil {
			return nil, err
		}
		result = make([]string, 0, len(parsed))
		for _, item := range parsed {
			result = append(result, sqlparser.String(item))
		}
		if len(result) == 0 {
			return nil, fmt.Errorf("no MySQL statements")
		}
		return result, nil
	case store.EnginePostgreSQL:
		return splitPostgreSQLStatements(statement)
	default:
		return nil, fmt.Errorf("unsupported SQL engine %q", engine)
	}
}

func sshLimits(request SSHRequest) (time.Duration, int) {
	timeout, maxBytes := request.Timeout, request.MaxBytes
	if timeout == 0 {
		timeout = DefaultSSHTimeout
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	// Caller-supplied finite limits are transport parameters, not policy
	// thresholds. The constants above are defaults only.
	return timeout, maxBytes
}

func sqlLimits(request SQLRequest) (time.Duration, int, int) {
	timeout, maxRows, maxBytes := request.Timeout, request.MaxRows, request.MaxBytes
	if timeout == 0 {
		timeout = DefaultSQLTimeout
	}
	if maxRows == 0 {
		maxRows = DefaultMaxRows
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	return timeout, maxRows, maxBytes
}

func sshResult(command string, asRoot bool, workingDirectory string, timeout time.Duration, maxBytes int) Result {
	payload := fmt.Sprintf("kind=ssh\ncommand=%s\nas_root=%t\nworking_directory=%s\ntimeout=%s\nmax_bytes=%d", command, asRoot, workingDirectory, timeout, maxBytes)
	return Result{Normalized: command, Payload: payload, PayloadHash: hash(payload), Timeout: timeout, MaxBytes: maxBytes}
}

func sqlResult(engine store.DatabaseEngine, statement string, timeout time.Duration, maxRows, maxBytes int) Result {
	payload := fmt.Sprintf("kind=sql\nengine=%s\nstatement=%s\ntimeout=%s\nmax_rows=%d\nmax_bytes=%d", engine, statement, timeout, maxRows, maxBytes)
	return Result{Normalized: statement, Payload: payload, PayloadHash: hash(payload), Timeout: timeout, MaxRows: maxRows, MaxBytes: maxBytes}
}

func withDecision(result Result, decision Decision, reason Reason) Result {
	result.Decision = decision
	result.Reason = reason
	return result
}

type hardStopRule struct {
	id            Reason
	matchSSH      func(string, shellAnalysis, []RegisteredRemoteTarget, bool) string
	matchMySQL    func(sqlparser.Statement, string) string
	matchPostgres func(*pg_query.Node, string) string
}

type hardStopMatch struct {
	id       Reason
	fragment string
}

// hardStopRules is the complete fixed execution boundary. It stays small,
// ordered, and local; per-target command blacklists are evaluated separately.
var hardStopRules = []hardStopRule{
	{id: ReasonFormatOrPartition, matchSSH: matchFormatOrPartition},
	{id: ReasonRawBlockDeviceWrite, matchSSH: matchRawBlockDeviceWrite},
	{id: ReasonBaseSystemTreeDestruction, matchSSH: matchBaseSystemTreeDestruction},
	{id: ReasonUnboundedResource, matchSSH: matchUnboundedResourceExhaustion},
	{id: ReasonOpaqueShellEffect, matchSSH: matchOpaqueShellEffect},
	{id: ReasonOpaqueSQLEffect, matchMySQL: matchOpaqueMySQLEffect, matchPostgres: matchOpaquePostgreSQLEffect},
	{id: ReasonDropDatabaseSchemaTable, matchMySQL: matchDropMySQLDatabaseSchemaTable, matchPostgres: matchDropPostgreSQLDatabaseSchemaTable},
	{id: ReasonTruncateTable, matchMySQL: matchTruncateMySQLTable, matchPostgres: matchTruncatePostgreSQLTable},
	{id: ReasonAlterDrop, matchMySQL: matchAlterMySQLDrop, matchPostgres: matchAlterPostgreSQLDrop},
	{id: ReasonUnconditionalWrite, matchMySQL: matchUnconditionalMySQLWrite, matchPostgres: matchUnconditionalPostgreSQLWrite},
	{id: ReasonUnregisteredRemoteHop, matchSSH: matchUnregisteredRemoteHop},
}

// HardStopRuleIDs returns a copy so callers can describe the fixed boundary
// without being able to alter it.
func HardStopRuleIDs() []string {
	ids := make([]string, 0, len(hardStopRules))
	for _, rule := range hardStopRules {
		ids = append(ids, string(rule.id))
	}
	return ids
}

func withHardStop(result Result, match hardStopMatch) Result {
	result.Decision = DecisionPermanentlyRejected
	result.Reason = match.id
	result.RuleID = string(match.id)
	result.MatchedFragment = match.fragment
	result.Risk = RiskHigh
	return result
}

func withTargetCommandBlacklist(result Result, pattern string) Result {
	result.Decision = DecisionRejected
	result.Reason = ReasonTargetCommandBlacklist
	result.RuleID = string(ReasonTargetCommandBlacklist)
	result.MatchedFragment = pattern
	result.Risk = RiskHigh
	return result
}

func matchTargetCommandBlacklist(command string, patterns []string) (string, error) {
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			return "", fmt.Errorf("empty target command blacklist pattern")
		}
		expression, err := regexp.Compile(pattern)
		if err != nil {
			return "", fmt.Errorf("compile target command blacklist pattern: %w", err)
		}
		if expression.MatchString(command) {
			return pattern, nil
		}
	}
	return "", nil
}

func matchSSHHardStop(command string, analysis shellAnalysis, remoteTargets []RegisteredRemoteTarget, remoteTargetRegistryAvailable bool) (hardStopMatch, bool) {
	for _, rule := range hardStopRules {
		if rule.matchSSH == nil {
			continue
		}
		if fragment := rule.matchSSH(command, analysis, remoteTargets, remoteTargetRegistryAvailable); fragment != "" {
			return hardStopMatch{id: rule.id, fragment: fragment}, true
		}
	}
	return hardStopMatch{}, false
}

func matchMySQLHardStop(statement sqlparser.Statement, normalized string) (hardStopMatch, bool) {
	for _, rule := range hardStopRules {
		if rule.matchMySQL == nil {
			continue
		}
		if fragment := rule.matchMySQL(statement, normalized); fragment != "" {
			return hardStopMatch{id: rule.id, fragment: fragment}, true
		}
	}
	return hardStopMatch{}, false
}

func matchPostgreSQLHardStop(node *pg_query.Node, normalized string) (hardStopMatch, bool) {
	for _, rule := range hardStopRules {
		if rule.matchPostgres == nil {
			continue
		}
		if fragment := rule.matchPostgres(node, normalized); fragment != "" {
			return hardStopMatch{id: rule.id, fragment: fragment}, true
		}
	}
	return hardStopMatch{}, false
}

func evaluateMySQLDefaultAllow(result Result, engine store.DatabaseEngine, statement string, timeout time.Duration, maxRows, maxBytes int) Result {
	parsed, err := parseMySQLStatements(statement)
	if err != nil || len(parsed) == 0 {
		result.ExecutionClass = SQLExecutionMayWrite
		return withDecision(result, DecisionAllowed, ReasonDiagnostic)
	}
	result = sqlResult(engine, formatMySQLStatements(parsed), timeout, maxRows, maxBytes)
	result.ExecutionClass = SQLExecutionRead
	for _, item := range parsed {
		if match, found := matchMySQLHardStop(item, sqlparser.String(item)); found {
			return withHardStop(result, match)
		}
		if !mysqlReadOnlyStatement(item) {
			result.ExecutionClass = SQLExecutionMayWrite
		}
	}
	return withDecision(result, DecisionAllowed, ReasonDiagnostic)
}

func evaluatePostgreSQLDefaultAllow(result Result, engine store.DatabaseEngine, statement string, timeout time.Duration, maxRows, maxBytes int) Result {
	tree, err := parsePostgreSQLStatements(statement)
	if err != nil || len(tree.GetStmts()) == 0 {
		result.ExecutionClass = SQLExecutionMayWrite
		return withDecision(result, DecisionAllowed, ReasonDiagnostic)
	}
	normalized, err := deparsePostgreSQL(tree)
	if err != nil {
		normalized = statement
	}
	result = sqlResult(engine, strings.TrimSpace(normalized), timeout, maxRows, maxBytes)
	result.ExecutionClass = SQLExecutionRead
	for _, raw := range tree.GetStmts() {
		single := &pg_query.ParseResult{Version: tree.GetVersion(), Stmts: []*pg_query.RawStmt{raw}}
		singleNormalized, deparseErr := deparsePostgreSQL(single)
		if deparseErr != nil {
			singleNormalized = normalized
		}
		if match, found := matchPostgreSQLHardStop(raw.GetStmt(), strings.TrimSpace(singleNormalized)); found {
			return withHardStop(result, match)
		}
		if !postgresReadOnlyStatement(raw.GetStmt()) {
			result.ExecutionClass = SQLExecutionMayWrite
		}
	}
	return withDecision(result, DecisionAllowed, ReasonDiagnostic)
}

func mysqlReadOnlyStatement(statement sqlparser.Statement) bool {
	switch node := statement.(type) {
	case *sqlparser.Select:
		return node.Into == nil && node.Lock == sqlparser.NoLock
	case *sqlparser.Union:
		return node.Into == nil && node.Lock == sqlparser.NoLock
	case *sqlparser.Show:
		return true
	case *sqlparser.ExplainStmt:
		return node.Type != sqlparser.AnalyzeType && mysqlReadOnlyStatement(node.Statement)
	default:
		return false
	}
}

func postgresReadOnlyStatement(node *pg_query.Node) bool {
	if node == nil {
		return false
	}
	if selectStatement := node.GetSelectStmt(); selectStatement != nil {
		return selectStatement.GetIntoClause() == nil && len(selectStatement.GetLockingClause()) == 0 && !postgresContainsWrite(node)
	}
	if explain := node.GetExplainStmt(); explain != nil {
		query := explain.GetQuery()
		return !postgresExplainExecutesQuery(explain) && query != nil && query.GetSelectStmt() != nil && !postgresContainsWrite(query)
	}
	return false
}

func hash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func validEngine(engine store.DatabaseEngine) bool {
	return engine == store.EngineMySQL || engine == store.EnginePostgreSQL
}

func matchFormatOrPartition(_ string, analysis shellAnalysis, _ []RegisteredRemoteTarget, _ bool) string {
	if hasFormattingOrPartitioning(analysis.commands) {
		return "格式化或分区工具"
	}
	return ""
}

func matchRawBlockDeviceWrite(_ string, analysis shellAnalysis, _ []RegisteredRemoteTarget, _ bool) string {
	if hasBlockDeviceWrite(analysis.writesBlockDevice, analysis.commands) || hasKnownBlockDeviceWrite(analysis.knownPathCommands) {
		return "原始块设备目标"
	}
	return ""
}

func matchBaseSystemTreeDestruction(_ string, analysis shellAnalysis, _ []RegisteredRemoteTarget, _ bool) string {
	if hasBaseSystemTreeDestruction(analysis.commands) || hasKnownBaseSystemTreeDestruction(analysis.knownPathCommands) {
		return "基础系统目录"
	}
	return ""
}

func matchUnboundedResourceExhaustion(command string, analysis shellAnalysis, _ []RegisteredRemoteTarget, _ bool) string {
	if analysis.unbounded || hasUnboundedResourceCommand(command, analysis.commands) {
		return "无界资源生成"
	}
	return ""
}

func matchOpaqueShellEffect(_ string, analysis shellAnalysis, _ []RegisteredRemoteTarget, _ bool) string {
	if analysis.dynamic {
		return "动态 Shell 表达式"
	}
	for _, tokens := range analysis.commands {
		index := executableIndex(tokens)
		if index < 0 {
			continue
		}
		program := strings.ToLower(path.Base(tokens[index]))
		switch program {
		case "eval", "source", ".":
			return program
		case "bash", "zsh", "dash", "fish", "python", "python3", "perl", "ruby", "node", "php", "lua", "awk":
			return program
		case "sed":
			if !isLiteralSedLinePrintInvocation(tokens) {
				return program
			}
		case "sh":
			if _, embedded := staticEmbeddedShellSource(tokens); embedded {
				continue
			}
			if analysis.hasPipeline || analysis.hasInputRedirect {
				return "从标准输入读取 Shell 程序"
			}
		case "xargs", "parallel", "pxargs":
			return program
		case "find":
			if containsAnyShellToken(tokens[index+1:], "-exec", "-execdir", "-ok", "-okdir") {
				return "find -exec"
			}
		case "docker", "podman", "nerdctl", "ctr", "crictl", "kubectl", "lxc", "incus":
			if containsAnyShellToken(tokens[index+1:], "exec") {
				return program + " exec"
			}
		}
	}
	return ""
}

func matchUnregisteredRemoteHop(_ string, analysis shellAnalysis, targets []RegisteredRemoteTarget, registryAvailable bool) string {
	registered := registeredRemoteTargetSet(targets)
	for _, tokens := range analysis.commands {
		endpoints, remoteClient, staticallyResolved := nestedRemoteEndpoints(tokens)
		if !remoteClient {
			continue
		}
		if !registryAvailable {
			return "无法读取已登记 SSH 目标清单"
		}
		if !staticallyResolved {
			return "无法静态解析的嵌套远端地址"
		}
		for _, endpoint := range endpoints {
			if _, ok := registered[endpoint.key()]; !ok {
				return "未登记嵌套远端地址 " + endpoint.display()
			}
		}
	}
	return ""
}

type remoteEndpoint struct {
	host string
	port int
}

func (endpoint remoteEndpoint) key() string {
	return endpoint.host + ":" + strconv.Itoa(endpoint.port)
}

func (endpoint remoteEndpoint) display() string {
	if endpoint.port == 22 {
		return endpoint.host
	}
	return endpoint.key()
}

func registeredRemoteTargetSet(targets []RegisteredRemoteTarget) map[string]struct{} {
	registered := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		host, ok := canonicalRemoteHost(target.Host)
		if !ok {
			continue
		}
		port := target.Port
		if port == 0 {
			port = 22
		}
		if port < 1 || port > 65535 {
			continue
		}
		registered[remoteEndpoint{host: host, port: port}.key()] = struct{}{}
	}
	return registered
}

// nestedRemoteEndpoints accepts only a deliberately small, static grammar.
// A command that uses an unsupported option, a hostname alias, a shell value,
// or a protocol form that cannot identify its actual destination is a remote
// hop with an unknown destination and therefore remains hard-blocked.
func nestedRemoteEndpoints(tokens []string) ([]remoteEndpoint, bool, bool) {
	index := executableIndex(tokens)
	if index < 0 {
		return nil, false, true
	}
	program := strings.ToLower(path.Base(tokens[index]))
	arguments := tokens[index+1:]
	switch program {
	case "ssh":
		endpoints, resolved := parseSSHRemoteEndpoints(arguments)
		return endpoints, true, resolved
	case "scp":
		endpoints, resolved := parseSCPRemoteEndpoints(arguments)
		return endpoints, true, resolved
	case "sftp":
		endpoints, resolved := parseSFTPRemoteEndpoints(arguments)
		return endpoints, true, resolved
	case "rsync":
		endpoints, resolved := parseRsyncRemoteEndpoints(arguments)
		return endpoints, true, resolved
	case "mosh":
		endpoints, resolved := parseSimpleRemoteEndpoint(arguments, 22)
		return endpoints, true, resolved
	case "rsh", "slogin":
		endpoints, resolved := parseSimpleRemoteEndpoint(arguments, 22)
		return endpoints, true, resolved
	case "telnet":
		endpoints, resolved := parseSimpleRemoteEndpoint(arguments, 23)
		return endpoints, true, resolved
	default:
		return nil, false, true
	}
}

func parseSSHRemoteEndpoints(arguments []string) ([]remoteEndpoint, bool) {
	port := 22
	var hostOverride string
	var endpoints []remoteEndpoint
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			index++
			if index >= len(arguments) {
				return nil, false
			}
			return appendSSHDestination(endpoints, hostOverride, arguments[index], port)
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			return appendSSHDestination(endpoints, hostOverride, argument, port)
		}
		switch {
		case argument == "-p":
			if index+1 >= len(arguments) {
				return nil, false
			}
			parsed, ok := parseRemotePort(arguments[index+1])
			if !ok {
				return nil, false
			}
			port = parsed
			index++
		case strings.HasPrefix(argument, "-p") && len(argument) > len("-p"):
			parsed, ok := parseRemotePort(strings.TrimPrefix(argument, "-p"))
			if !ok {
				return nil, false
			}
			port = parsed
		case argument == "-o":
			if index+1 >= len(arguments) {
				return nil, false
			}
			updatedPort, updatedHost, extra, ok := parseSSHOption(arguments[index+1], port, hostOverride)
			if !ok {
				return nil, false
			}
			port, hostOverride = updatedPort, updatedHost
			endpoints = append(endpoints, extra...)
			index++
		case strings.HasPrefix(argument, "-o") && len(argument) > len("-o"):
			updatedPort, updatedHost, extra, ok := parseSSHOption(strings.TrimPrefix(argument, "-o"), port, hostOverride)
			if !ok {
				return nil, false
			}
			port, hostOverride = updatedPort, updatedHost
			endpoints = append(endpoints, extra...)
		case argument == "-J" || argument == "--proxyjump":
			if index+1 >= len(arguments) {
				return nil, false
			}
			jumpEndpoints, ok := parseProxyJumpEndpoints(arguments[index+1], port)
			if !ok {
				return nil, false
			}
			endpoints = append(endpoints, jumpEndpoints...)
			index++
		case strings.HasPrefix(argument, "-J") && len(argument) > len("-J"):
			jumpEndpoints, ok := parseProxyJumpEndpoints(strings.TrimPrefix(argument, "-J"), port)
			if !ok {
				return nil, false
			}
			endpoints = append(endpoints, jumpEndpoints...)
		case strings.HasPrefix(argument, "--proxyjump="):
			jumpEndpoints, ok := parseProxyJumpEndpoints(strings.TrimPrefix(argument, "--proxyjump="), port)
			if !ok {
				return nil, false
			}
			endpoints = append(endpoints, jumpEndpoints...)
		case argument == "-L" || argument == "-R" || argument == "-W":
			if index+1 >= len(arguments) {
				return nil, false
			}
			forward, ok := parseSSHForwardEndpoint(argument, arguments[index+1])
			if !ok {
				return nil, false
			}
			endpoints = append(endpoints, forward)
			index++
		case (strings.HasPrefix(argument, "-L") || strings.HasPrefix(argument, "-R") || strings.HasPrefix(argument, "-W")) && len(argument) > len("-L"):
			forward, ok := parseSSHForwardEndpoint(argument[:2], argument[2:])
			if !ok {
				return nil, false
			}
			endpoints = append(endpoints, forward)
		case argument == "-D" || strings.HasPrefix(argument, "-D"):
			// A SOCKS forward intentionally accepts arbitrary destinations.
			return nil, false
		case sshOptionWithoutDestination(argument):
			continue
		case sshOptionWithValue(argument):
			if index+1 >= len(arguments) {
				return nil, false
			}
			index++
		default:
			return nil, false
		}
	}
	return nil, false
}

func appendSSHDestination(endpoints []remoteEndpoint, hostOverride, destination string, port int) ([]remoteEndpoint, bool) {
	if hostOverride != "" {
		destination = hostOverride
	}
	endpoint, ok := parseRemoteHost(destination, port)
	if !ok {
		return nil, false
	}
	return append(endpoints, endpoint), true
}

func parseSSHOption(value string, port int, hostOverride string) (int, string, []remoteEndpoint, bool) {
	name, optionValue, found := strings.Cut(value, "=")
	if !found {
		return 0, "", nil, false
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "port":
		parsed, ok := parseRemotePort(optionValue)
		return parsed, hostOverride, nil, ok
	case "hostname":
		if _, ok := canonicalRemoteHost(optionValue); !ok {
			return 0, "", nil, false
		}
		return port, optionValue, nil, true
	case "proxyjump":
		endpoints, ok := parseProxyJumpEndpoints(optionValue, port)
		return port, hostOverride, endpoints, ok
	case "localforward", "remoteforward":
		endpoint, ok := parseForwardDestination(optionValue)
		if !ok {
			return 0, "", nil, false
		}
		return port, hostOverride, []remoteEndpoint{endpoint}, true
	case "dynamicforward", "proxycommand", "localcommand", "include", "match":
		return 0, "", nil, false
	default:
		// Other explicit SSH configuration keys do not name a destination.
		return port, hostOverride, nil, true
	}
}

func sshOptionWithoutDestination(argument string) bool {
	if len(argument) != 2 || !strings.HasPrefix(argument, "-") {
		return false
	}
	switch argument {
	case "-4", "-6", "-A", "-a", "-C", "-f", "-G", "-g", "-K", "-k", "-M", "-N", "-n", "-q", "-T", "-t", "-V", "-v", "-X", "-x", "-Y", "-y":
		return true
	default:
		return false
	}
}

func sshOptionWithValue(argument string) bool {
	switch argument {
	case "-b", "-c", "-E", "-I", "-i", "-l", "-m", "-Q", "-w":
		return true
	default:
		return false
	}
}

func parseSSHForwardEndpoint(kind, value string) (remoteEndpoint, bool) {
	if kind == "-W" {
		return parseHostPortEndpoint(value)
	}
	return parseForwardDestination(value)
}

func parseForwardDestination(value string) (remoteEndpoint, bool) {
	// SSH forward forms end in `host:port`; use the last two fields for the
	// common static IPv4 form and net.SplitHostPort for bracketed IPv6.
	if endpoint, ok := parseHostPortEndpoint(value); ok {
		return endpoint, true
	}
	last := strings.LastIndex(value, ":")
	if last <= 0 || last+1 == len(value) {
		return remoteEndpoint{}, false
	}
	port, ok := parseRemotePort(value[last+1:])
	if !ok {
		return remoteEndpoint{}, false
	}
	remaining := value[:last]
	previous := strings.LastIndex(remaining, ":")
	if previous < 0 || previous+1 == len(remaining) {
		return remoteEndpoint{}, false
	}
	return parseRemoteHost(remaining[previous+1:], port)
}

func parseProxyJumpEndpoints(value string, defaultPort int) ([]remoteEndpoint, bool) {
	if value == "" {
		return nil, false
	}
	parts := strings.Split(value, ",")
	endpoints := make([]remoteEndpoint, 0, len(parts))
	for _, part := range parts {
		endpoint, ok := parseJumpEndpoint(part, defaultPort)
		if !ok {
			return nil, false
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, true
}

func parseJumpEndpoint(value string, defaultPort int) (remoteEndpoint, bool) {
	value = stripRemoteUser(value)
	if strings.HasPrefix(value, "[") {
		return parseHostPortEndpoint(value)
	}
	if strings.Count(value, ":") == 1 {
		return parseHostPortEndpoint(value)
	}
	return parseRemoteHost(value, defaultPort)
}

func parseSCPRemoteEndpoints(arguments []string) ([]remoteEndpoint, bool) {
	port := 22
	var endpoints []remoteEndpoint
	options := true
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if options && argument == "--" {
			options = false
			continue
		}
		if !options {
			endpoint, remote, ok := parseSCPPathEndpoint(argument, port)
			if !ok {
				return nil, false
			}
			if remote {
				endpoints = append(endpoints, endpoint)
			}
			continue
		}
		switch {
		case argument == "-P":
			if index+1 >= len(arguments) {
				return nil, false
			}
			parsed, ok := parseRemotePort(arguments[index+1])
			if !ok {
				return nil, false
			}
			port = parsed
			index++
		case strings.HasPrefix(argument, "-P") && len(argument) > len("-P"):
			parsed, ok := parseRemotePort(strings.TrimPrefix(argument, "-P"))
			if !ok {
				return nil, false
			}
			port = parsed
		case argument == "-o":
			if index+1 >= len(arguments) {
				return nil, false
			}
			updatedPort, _, extra, ok := parseSSHOption(arguments[index+1], port, "")
			if !ok || len(extra) != 0 {
				return nil, false
			}
			port = updatedPort
			index++
		case strings.HasPrefix(argument, "-o") && len(argument) > len("-o"):
			updatedPort, _, extra, ok := parseSSHOption(strings.TrimPrefix(argument, "-o"), port, "")
			if !ok || len(extra) != 0 {
				return nil, false
			}
			port = updatedPort
		case strings.HasPrefix(argument, "-"):
			if !scpOptionWithoutValue(argument) {
				return nil, false
			}
		default:
			endpoint, remote, ok := parseSCPPathEndpoint(argument, port)
			if !ok {
				return nil, false
			}
			if remote {
				endpoints = append(endpoints, endpoint)
			}
		}
	}
	return endpoints, len(endpoints) > 0
}

func scpOptionWithoutValue(argument string) bool {
	if strings.HasPrefix(argument, "--") {
		return argument == "--verbose"
	}
	for _, flag := range strings.TrimPrefix(argument, "-") {
		switch flag {
		case '3', 'A', 'B', 'C', 'O', 'p', 'q', 'R', 'r', 'T', 'v':
		default:
			return false
		}
	}
	return len(strings.TrimPrefix(argument, "-")) > 0
}

func parseSCPPathEndpoint(value string, defaultPort int) (remoteEndpoint, bool, bool) {
	if strings.HasPrefix(strings.ToLower(value), "scp://") {
		return remoteEndpoint{}, true, false
	}
	separator := strings.Index(value, ":")
	if separator < 0 {
		return remoteEndpoint{}, false, true
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return remoteEndpoint{}, false, true
	}
	endpoint, ok := parseRemoteHost(value[:separator], defaultPort)
	return endpoint, true, ok
}

func parseSFTPRemoteEndpoints(arguments []string) ([]remoteEndpoint, bool) {
	port := 22
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "-P":
			if index+1 >= len(arguments) {
				return nil, false
			}
			parsed, ok := parseRemotePort(arguments[index+1])
			if !ok {
				return nil, false
			}
			port = parsed
			index++
		case strings.HasPrefix(argument, "-P") && len(argument) > len("-P"):
			parsed, ok := parseRemotePort(strings.TrimPrefix(argument, "-P"))
			if !ok {
				return nil, false
			}
			port = parsed
		case argument == "-o":
			if index+1 >= len(arguments) {
				return nil, false
			}
			updatedPort, _, extra, ok := parseSSHOption(arguments[index+1], port, "")
			if !ok || len(extra) != 0 {
				return nil, false
			}
			port = updatedPort
			index++
		case strings.HasPrefix(argument, "-"):
			if !sftpOptionWithoutValue(argument) {
				return nil, false
			}
		default:
			endpoint, ok := parseRemoteHost(argument, port)
			return []remoteEndpoint{endpoint}, ok
		}
	}
	return nil, false
}

func sftpOptionWithoutValue(argument string) bool {
	for _, flag := range strings.TrimPrefix(argument, "-") {
		switch flag {
		case '4', '6', 'A', 'a', 'C', 'f', 'q', 'R', 'v':
		default:
			return false
		}
	}
	return len(strings.TrimPrefix(argument, "-")) > 0
}

func parseRsyncRemoteEndpoints(arguments []string) ([]remoteEndpoint, bool) {
	port := 22
	var endpoints []remoteEndpoint
	options := true
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if options && argument == "--" {
			options = false
			continue
		}
		if !options {
			endpoint, remote, ok := parseRsyncPathEndpoint(argument, port)
			if !ok {
				return nil, false
			}
			if remote {
				endpoints = append(endpoints, endpoint)
			}
			continue
		}
		switch {
		case argument == "--port":
			if index+1 >= len(arguments) {
				return nil, false
			}
			parsed, ok := parseRemotePort(arguments[index+1])
			if !ok {
				return nil, false
			}
			port = parsed
			index++
		case strings.HasPrefix(argument, "--port="):
			parsed, ok := parseRemotePort(strings.TrimPrefix(argument, "--port="))
			if !ok {
				return nil, false
			}
			port = parsed
		case strings.HasPrefix(argument, "-"):
			if !rsyncOptionWithoutValue(argument) {
				return nil, false
			}
		default:
			endpoint, remote, ok := parseRsyncPathEndpoint(argument, port)
			if !ok {
				return nil, false
			}
			if remote {
				endpoints = append(endpoints, endpoint)
			}
		}
	}
	return endpoints, len(endpoints) > 0
}

func rsyncOptionWithoutValue(argument string) bool {
	if strings.HasPrefix(argument, "--") {
		switch argument {
		case "--archive", "--verbose", "--compress", "--delete", "--progress", "--partial", "--dry-run":
			return true
		default:
			return false
		}
	}
	for _, flag := range strings.TrimPrefix(argument, "-") {
		switch flag {
		case 'a', 'v', 'z', 'r', 'l', 'p', 't', 'g', 'o', 'D', 'h', 'n', 'P', 'q':
		default:
			return false
		}
	}
	return len(strings.TrimPrefix(argument, "-")) > 0
}

func parseRsyncPathEndpoint(value string, defaultPort int) (remoteEndpoint, bool, bool) {
	if strings.HasPrefix(strings.ToLower(value), "rsync://") {
		return parseRsyncURL(value)
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return remoteEndpoint{}, false, true
	}
	separator := strings.Index(value, ":")
	if separator < 0 {
		return remoteEndpoint{}, false, true
	}
	endpoint, ok := parseRemoteHost(value[:separator], defaultPort)
	return endpoint, true, ok
}

func parseRsyncURL(value string) (remoteEndpoint, bool, bool) {
	withoutScheme := strings.TrimPrefix(strings.TrimPrefix(value, "rsync://"), "RSYNC://")
	hostPort, _, found := strings.Cut(withoutScheme, "/")
	if !found || hostPort == "" {
		return remoteEndpoint{}, true, false
	}
	endpoint, ok := parseHostPortEndpoint(hostPort)
	if ok {
		return endpoint, true, true
	}
	endpoint, ok = parseRemoteHost(hostPort, 873)
	return endpoint, true, ok
}

func parseSimpleRemoteEndpoint(arguments []string, defaultPort int) ([]remoteEndpoint, bool) {
	if len(arguments) != 1 {
		return nil, false
	}
	endpoint, ok := parseRemoteHost(arguments[0], defaultPort)
	return []remoteEndpoint{endpoint}, ok
}

func parseHostPortEndpoint(value string) (remoteEndpoint, bool) {
	host, portText, err := netipParseHostPort(value)
	if err != nil {
		return remoteEndpoint{}, false
	}
	port, ok := parseRemotePort(portText)
	if !ok {
		return remoteEndpoint{}, false
	}
	canonicalHost, ok := canonicalRemoteHost(host)
	if !ok {
		return remoteEndpoint{}, false
	}
	return remoteEndpoint{host: canonicalHost, port: port}, true
}

func netipParseHostPort(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end <= 1 || end+2 >= len(value) {
			return "", "", fmt.Errorf("invalid bracketed endpoint")
		}
		return value[1:end], value[end+2:], nil
	}
	if strings.Count(value, ":") != 1 {
		return "", "", fmt.Errorf("ambiguous endpoint")
	}
	host, port, found := strings.Cut(value, ":")
	if !found || host == "" || port == "" {
		return "", "", fmt.Errorf("invalid endpoint")
	}
	return host, port, nil
}

func parseRemoteHost(value string, port int) (remoteEndpoint, bool) {
	if port < 1 || port > 65535 {
		return remoteEndpoint{}, false
	}
	host, ok := canonicalRemoteHost(value)
	if !ok {
		return remoteEndpoint{}, false
	}
	return remoteEndpoint{host: host, port: port}, true
}

func canonicalRemoteHost(value string) (string, bool) {
	value = strings.TrimSpace(stripRemoteUser(value))
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", false
	}
	return address.String(), true
}

func stripRemoteUser(value string) string {
	if at := strings.LastIndex(value, "@"); at >= 0 {
		return value[at+1:]
	}
	return value
}

func parseRemotePort(value string) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	return port, err == nil && port >= 1 && port <= 65535
}

func matchOpaqueMySQLEffect(_ sqlparser.Statement, normalized string) string {
	return opaqueMySQLFragment(normalized)
}

func matchOpaquePostgreSQLEffect(node *pg_query.Node, normalized string) string {
	if fragment := opaquePostgreSQLFragment(normalized); fragment != "" {
		return fragment
	}
	if postgresHasOpaqueEffectNode(node) {
		return "不透明 PostgreSQL 语句"
	}
	return ""
}

func matchDropMySQLDatabaseSchemaTable(_ sqlparser.Statement, normalized string) string {
	if sqlStartsWithAny(normalized, "DROP DATABASE", "DROP SCHEMA", "DROP TABLE", "DROP TEMPORARY TABLE") {
		return "DROP DATABASE/SCHEMA/TABLE"
	}
	return ""
}

func matchDropPostgreSQLDatabaseSchemaTable(node *pg_query.Node, normalized string) string {
	if node != nil && node.GetDropdbStmt() != nil {
		return "DROP DATABASE"
	}
	if drop := node.GetDropStmt(); drop != nil {
		switch drop.GetRemoveType() {
		case pg_query.ObjectType_OBJECT_DATABASE, pg_query.ObjectType_OBJECT_SCHEMA, pg_query.ObjectType_OBJECT_TABLE:
			return "DROP DATABASE/SCHEMA/TABLE"
		}
	}
	if sqlStartsWithAny(normalized, "DROP DATABASE", "DROP SCHEMA", "DROP TABLE", "DROP FOREIGN TABLE") {
		return "DROP DATABASE/SCHEMA/TABLE"
	}
	return ""
}

func matchTruncateMySQLTable(_ sqlparser.Statement, normalized string) string {
	if sqlStartsWithAny(normalized, "TRUNCATE", "TRUNCATE TABLE") {
		return "TRUNCATE TABLE"
	}
	return ""
}

func matchTruncatePostgreSQLTable(node *pg_query.Node, normalized string) string {
	if node != nil && node.GetTruncateStmt() != nil || sqlStartsWithAny(normalized, "TRUNCATE", "TRUNCATE TABLE") {
		return "TRUNCATE TABLE"
	}
	return ""
}

func matchAlterMySQLDrop(_ sqlparser.Statement, normalized string) string {
	if sqlAlterDropsData(normalized) {
		return "ALTER ... DROP"
	}
	return ""
}

func matchAlterPostgreSQLDrop(node *pg_query.Node, normalized string) string {
	if postgresAlterDropsData(node) || sqlAlterDropsData(normalized) {
		return "ALTER ... DROP"
	}
	return ""
}

func matchUnconditionalMySQLWrite(statement sqlparser.Statement, _ string) string {
	switch node := statement.(type) {
	case *sqlparser.Update:
		if node.Where == nil || mysqlContainsObviousTautology(node.Where.Expr) {
			return "UPDATE 缺少限制条件"
		}
	case *sqlparser.Delete:
		if node.Where == nil || mysqlContainsObviousTautology(node.Where.Expr) {
			return "DELETE 缺少限制条件"
		}
	}
	return ""
}

func matchUnconditionalPostgreSQLWrite(node *pg_query.Node, _ string) string {
	if node == nil {
		return ""
	}
	if update := node.GetUpdateStmt(); update != nil && (update.GetWhereClause() == nil || postgresContainsObviousTautology(update.GetWhereClause())) {
		return "UPDATE 缺少限制条件"
	}
	if deleteStatement := node.GetDeleteStmt(); deleteStatement != nil && (deleteStatement.GetWhereClause() == nil || postgresContainsObviousTautology(deleteStatement.GetWhereClause())) {
		return "DELETE 缺少限制条件"
	}
	return ""
}

func sqlStartsWithAny(statement string, prefixes ...string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(statement))
	for _, prefix := range prefixes {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

func sqlAlterDropsData(statement string) bool {
	fields := strings.Fields(strings.ToUpper(strings.TrimSpace(statement)))
	if len(fields) == 0 || fields[0] != "ALTER" {
		return false
	}
	for _, field := range fields[1:] {
		if field == "DROP" {
			return true
		}
	}
	return false
}

func postgresAlterDropsData(node *pg_query.Node) bool {
	if node == nil || node.GetAlterTableStmt() == nil {
		return false
	}
	for _, rawCommand := range node.GetAlterTableStmt().GetCmds() {
		command := rawCommand.GetAlterTableCmd()
		if command != nil && strings.Contains(strings.ToUpper(command.GetSubtype().String()), "DROP") {
			return true
		}
	}
	return false
}

func opaqueMySQLFragment(statement string) string {
	normalized := strings.ToUpper(strings.TrimSpace(statement))
	for _, prefix := range []string{
		"CALL ", "DO ", "PREPARE ", "EXECUTE ", "DEALLOCATE ", "HANDLER ",
		"LOAD DATA", "LOAD XML", "CREATE FUNCTION", "ALTER FUNCTION", "DROP FUNCTION",
		"CREATE PROCEDURE", "ALTER PROCEDURE", "DROP PROCEDURE", "CREATE TRIGGER", "ALTER TRIGGER", "DROP TRIGGER",
	} {
		if strings.HasPrefix(normalized, prefix) {
			return strings.TrimSpace(prefix)
		}
	}
	for _, marker := range []string{" INTO OUTFILE", " INTO DUMPFILE", "LOAD_FILE(", " DATA DIRECTORY", " INDEX DIRECTORY", " IMPORT TABLESPACE", " DISCARD TABLESPACE"} {
		if strings.Contains(normalized, marker) {
			return strings.TrimSpace(marker)
		}
	}
	return ""
}

func opaquePostgreSQLFragment(statement string) string {
	normalized := strings.ToUpper(strings.TrimSpace(statement))
	for _, prefix := range []string{
		"CALL ", "DO ", "PREPARE ", "EXECUTE ", "DEALLOCATE ", "COPY ", "LOAD ",
		"CREATE FUNCTION", "ALTER FUNCTION", "DROP FUNCTION", "CREATE PROCEDURE", "ALTER PROCEDURE", "DROP PROCEDURE",
		"CREATE TRIGGER", "ALTER TRIGGER", "DROP TRIGGER", "CREATE EXTENSION", "ALTER EXTENSION", "DROP EXTENSION",
		"CREATE FOREIGN DATA WRAPPER", "ALTER FOREIGN DATA WRAPPER", "CREATE SERVER", "ALTER SERVER",
		"CREATE FOREIGN TABLE", "IMPORT FOREIGN SCHEMA", "CREATE USER MAPPING", "ALTER USER MAPPING", "DROP USER MAPPING",
		"CREATE SUBSCRIPTION", "ALTER SUBSCRIPTION", "DROP SUBSCRIPTION",
	} {
		if strings.HasPrefix(normalized, prefix) {
			return strings.TrimSpace(prefix)
		}
	}
	return ""
}

func postgresHasOpaqueEffectNode(root *pg_query.Node) bool {
	if root == nil {
		return false
	}
	found := false
	walkPostgres(root.ProtoReflect(), func(message protoreflect.Message) bool {
		node, ok := message.Interface().(*pg_query.Node)
		if !ok {
			return false
		}
		if node.GetCallStmt() != nil || node.GetDoStmt() != nil || node.GetCopyStmt() != nil || node.GetLoadStmt() != nil ||
			node.GetPrepareStmt() != nil || node.GetExecuteStmt() != nil || node.GetDeallocateStmt() != nil ||
			node.GetCreateFunctionStmt() != nil || node.GetAlterFunctionStmt() != nil || node.GetCreateTrigStmt() != nil ||
			node.GetCreateExtensionStmt() != nil || node.GetAlterExtensionStmt() != nil || node.GetCreateFdwStmt() != nil ||
			node.GetAlterFdwStmt() != nil || node.GetCreateForeignServerStmt() != nil || node.GetAlterForeignServerStmt() != nil ||
			node.GetCreateForeignTableStmt() != nil || node.GetCreateUserMappingStmt() != nil || node.GetAlterUserMappingStmt() != nil ||
			node.GetDropUserMappingStmt() != nil || node.GetImportForeignSchemaStmt() != nil || node.GetCreateSubscriptionStmt() != nil ||
			node.GetAlterSubscriptionStmt() != nil || node.GetDropSubscriptionStmt() != nil {
			found = true
		}
		return found
	})
	return found
}

type shellAnalysis struct {
	commands          [][]string
	knownPathCommands []knownPathCommand
	writesBlockDevice bool
	unbounded         bool
	dynamic           bool
	hasInputRedirect  bool
	hasPipeline       bool
}

// analyzeShellProgram uses a POSIX shell AST for the fixed hard-stop rules.
// It deliberately leaves ordinary unsupported syntax to the remote shell.
func analyzeShellProgram(command string) (shellAnalysis, error) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(command), "")
	if err != nil {
		return shellAnalysis{}, err
	}

	var analysis shellAnalysis
	var embeddedSourceErr error
	syntax.Walk(file, func(node syntax.Node) bool {
		if embeddedSourceErr != nil {
			return false
		}
		switch value := node.(type) {
		case *syntax.Stmt:
			for _, redirect := range value.Redirs {
				if isInputRedirection(redirect.Op) {
					analysis.hasInputRedirect = true
				}
			}
		case *syntax.CallExpr:
			tokens := literalShellWords(value.Args)
			if !literalShellWordsStatic(value.Args) {
				analysis.dynamic = true
			}
			if len(tokens) == 0 {
				return true
			}
			analysis.commands = append(analysis.commands, tokens)
			if isDynamicShellInvocation(tokens) {
				analysis.dynamic = true
			}
			if source, embedded := staticEmbeddedShellSource(tokens); embedded {
				nested, err := analyzeShellProgram(source)
				if err != nil {
					embeddedSourceErr = fmt.Errorf("embedded sh -c source: %w", err)
					return false
				}
				analysis.merge(nested)
			}
		case *syntax.Redirect:
			if isInputRedirection(value.Op) {
				analysis.hasInputRedirect = true
			}
			if isOutputRedirection(value.Op) && value.Word != nil {
				if destination, ok := literalShellWord(value.Word); ok && isRawBlockDevicePath(destination) {
					analysis.writesBlockDevice = true
				}
			}
		case *syntax.BinaryCmd:
			if value.Op == syntax.Pipe || value.Op == syntax.PipeAll {
				analysis.hasPipeline = true
			}
		case *syntax.WhileClause:
			if !value.Until && isAlwaysTrueCondition(value.Cond) {
				analysis.unbounded = true
			}
		case *syntax.CStyleLoop:
			if value.Cond == nil {
				analysis.unbounded = true
			}
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
			analysis.dynamic = true
		}
		return true
	})
	if embeddedSourceErr != nil {
		return shellAnalysis{}, embeddedSourceErr
	}
	return analysis, nil
}

func (analysis *shellAnalysis) merge(other shellAnalysis) {
	analysis.commands = append(analysis.commands, other.commands...)
	analysis.writesBlockDevice = analysis.writesBlockDevice || other.writesBlockDevice
	analysis.unbounded = analysis.unbounded || other.unbounded
	analysis.dynamic = analysis.dynamic || other.dynamic
	analysis.hasInputRedirect = analysis.hasInputRedirect || other.hasInputRedirect
	analysis.hasPipeline = analysis.hasPipeline || other.hasPipeline
}

func literalShellWords(words []*syntax.Word) []string {
	tokens := make([]string, 0, len(words))
	for _, word := range words {
		value, ok := literalShellWord(word)
		if !ok {
			value = ""
		}
		tokens = append(tokens, value)
	}
	return tokens
}

func literalShellWordsStatic(words []*syntax.Word) bool {
	for _, word := range words {
		if _, ok := literalShellWord(word); !ok {
			return false
		}
	}
	return true
}

func literalShellWord(word *syntax.Word) (string, bool) {
	var builder strings.Builder
	for _, part := range word.Parts {
		switch value := part.(type) {
		case *syntax.Lit:
			builder.WriteString(unescapeUnquotedLiteral(value.Value))
		case *syntax.SglQuoted:
			builder.WriteString(value.Value)
		case *syntax.DblQuoted:
			literal, ok := literalDoubleQuotedParts(value.Parts)
			if !ok {
				return "", false
			}
			builder.WriteString(literal)
		default:
			return "", false
		}
	}
	return builder.String(), true
}

func literalDoubleQuotedParts(parts []syntax.WordPart) (string, bool) {
	var builder strings.Builder
	for _, part := range parts {
		value, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		builder.WriteString(unescapeDoubleQuotedLiteral(value.Value))
	}
	return builder.String(), true
}

func unescapeUnquotedLiteral(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index+1 == len(value) {
			builder.WriteByte(value[index])
			continue
		}
		index++
		if value[index] != '\n' {
			builder.WriteByte(value[index])
		}
	}
	return builder.String()
}

func unescapeDoubleQuotedLiteral(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index+1 == len(value) {
			builder.WriteByte(value[index])
			continue
		}
		next := value[index+1]
		if next == '$' || next == '`' || next == '"' || next == '\\' || next == '\n' {
			index++
			if next != '\n' {
				builder.WriteByte(next)
			}
			continue
		}
		builder.WriteByte(value[index])
	}
	return builder.String()
}

func isDynamicShellInvocation(tokens []string) bool {
	program := invokedShellProgram(tokens)
	if program == "" || isShellInterpreter(program) {
		return false
	}
	if program == "sed" && isLiteralSedLinePrintInvocation(tokens) {
		return false
	}
	return program == "eval" || program == "source" || program == "." || isEmbeddedInterpreter(program)
}

func invokedShellProgram(tokens []string) string {
	index := executableIndex(tokens)
	if index < 0 {
		return ""
	}
	return strings.ToLower(path.Base(tokens[index]))
}

func staticEmbeddedShellSource(tokens []string) (string, bool) {
	index := executableIndex(tokens)
	if index < 0 || !isShellInterpreter(strings.ToLower(path.Base(tokens[index]))) {
		return "", false
	}
	arguments := tokens[index+1:]
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			return "", false
		}
		if shellOptionContainsCommandString(argument) && index+1 < len(arguments) {
			return arguments[index+1], true
		}
		if argument == "-o" && index+1 < len(arguments) {
			index++
			continue
		}
		if !strings.HasPrefix(argument, "-") {
			return "", false
		}
	}
	return "", false
}

func shellOptionContainsCommandString(argument string) bool {
	if argument == "-c" {
		return true
	}
	if !strings.HasPrefix(argument, "-") || strings.HasPrefix(argument, "--") {
		return false
	}
	return strings.Contains(argument[1:], "c")
}

func isShellInterpreter(program string) bool {
	return program == "sh"
}

// isEmbeddedInterpreter lists programs whose arguments can carry an
// independent program that the shell parser cannot inspect.
func isEmbeddedInterpreter(program string) bool {
	switch program {
	case "bash", "zsh", "dash", "fish", "python", "python3", "perl", "ruby", "node", "php", "lua", "awk", "sed":
		return true
	default:
		return false
	}
}

// isLiteralSedLinePrintInvocation recognizes the small read-only sed form
// needed for bounded line inspection. Other sed programs can execute commands
// or write files, so they remain opaque shell effects.
func isLiteralSedLinePrintInvocation(tokens []string) bool {
	index := executableIndex(tokens)
	if index < 0 || strings.ToLower(path.Base(tokens[index])) != "sed" {
		return false
	}

	arguments := tokens[index+1:]
	quiet := false
	optionsEnded := false
	programSeen := false
	program := ""
	files := 0
	for _, argument := range arguments {
		if !programSeen {
			if optionsEnded {
				program = argument
				programSeen = true
				continue
			}
			switch argument {
			case "-n", "--quiet", "--silent":
				quiet = true
				continue
			case "--":
				optionsEnded = true
				continue
			}
			if strings.HasPrefix(argument, "-") {
				return false
			}
			program = argument
			programSeen = true
			continue
		}

		if !isLiteralSedInputFile(argument) {
			return false
		}
		files++
	}

	return quiet && programSeen && files > 0 && isLiteralSedLinePrintProgram(program)
}

func isLiteralSedInputFile(value string) bool {
	if value == "" || value == "-" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "~") {
		return false
	}
	// The shell parser intentionally keeps ordinary glob expansion out of the
	// opaque-effect check. This narrow sed exception requires an explicit file
	// name so a later option-looking glob result cannot change sed's behavior.
	return !strings.ContainsAny(value, "*?[{")
}

func isLiteralSedLinePrintProgram(program string) bool {
	if !strings.HasSuffix(program, "p") {
		return false
	}
	addresses := strings.TrimSuffix(program, "p")
	parts := strings.Split(addresses, ",")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	for _, address := range parts {
		if address == "" {
			return false
		}
		if _, err := strconv.ParseUint(address, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func isOutputRedirection(operator syntax.RedirOperator) bool {
	switch operator {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrInOut, syntax.DplOut, syntax.RdrClob, syntax.AppClob, syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
		return true
	default:
		return false
	}
}

func isInputRedirection(operator syntax.RedirOperator) bool {
	switch operator {
	case syntax.RdrIn, syntax.RdrInOut, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		return true
	default:
		return false
	}
}

func executableIndex(tokens []string) int {
	for index := 0; index < len(tokens); {
		program := strings.ToLower(path.Base(tokens[index]))
		switch program {
		case "sudo":
			index = skipSudoArguments(tokens, index+1)
			continue
		case "env":
			index = skipEnvArguments(tokens, index+1)
			continue
		case "command", "nohup":
			index++
			continue
		case "exec":
			index = skipExecArguments(tokens, index+1)
			continue
		}
		if strings.Contains(tokens[index], "=") && !strings.HasPrefix(tokens[index], "/") {
			index++
			continue
		}
		return index
	}
	return -1
}

func skipExecArguments(tokens []string, index int) int {
	for index < len(tokens) {
		argument := tokens[index]
		if argument == "--" {
			return index + 1
		}
		if argument == "-a" && index+1 < len(tokens) {
			index += 2
			continue
		}
		if strings.HasPrefix(argument, "-") {
			index++
			continue
		}
		return index
	}
	return index
}

// requiresInteractiveInput is a capability signal, not a policy rejection.
func requiresInteractiveInput(commands [][]string) bool {
	for _, tokens := range commands {
		if len(tokens) == 0 {
			continue
		}
		index := executableIndex(tokens)
		if index < 0 {
			if strings.EqualFold(path.Base(tokens[0]), "sudo") {
				return true
			}
			continue
		}
		program := strings.ToLower(path.Base(tokens[index]))
		switch program {
		case "read", "vi", "vim", "nvim", "nano", "emacs", "less", "more", "man", "su", "doas", "login", "passwd":
			return true
		case "top", "htop":
			if !containsAnyShellToken(tokens[index+1:], "-b", "--batch") {
				return true
			}
		case "sh":
			if _, embedded := staticEmbeddedShellSource(tokens); !embedded {
				return true
			}
		case "mysql", "mariadb", "psql":
			if !containsAnyShellToken(tokens[index+1:], "-e", "--execute", "-c", "--command", "-f", "--file") {
				return true
			}
		}
	}
	return false
}

// hasLiteralSudoWrapper reports only command-position sudo, including
// transparent wrapper prefixes such as `env sudo`.
func hasLiteralSudoWrapper(commands [][]string) bool {
	for _, tokens := range commands {
		if commandStartsWithSudo(tokens) {
			return true
		}
	}
	return false
}

func commandStartsWithSudo(tokens []string) bool {
	for index := 0; index < len(tokens); {
		program := strings.ToLower(path.Base(tokens[index]))
		switch program {
		case "env":
			index = skipEnvArguments(tokens, index+1)
			continue
		case "command", "nohup":
			index++
			continue
		}
		if strings.Contains(tokens[index], "=") && !strings.HasPrefix(tokens[index], "/") {
			index++
			continue
		}
		return program == "sudo"
	}
	return false
}

func skipSudoArguments(tokens []string, index int) int {
	for index < len(tokens) {
		argument := tokens[index]
		if argument == "--" {
			return index + 1
		}
		if !strings.HasPrefix(argument, "-") {
			return index
		}
		if sudoOptionTakesValue(argument) && !strings.Contains(argument, "=") && index+1 < len(tokens) {
			index += 2
			continue
		}
		index++
	}
	return index
}

func sudoOptionTakesValue(argument string) bool {
	switch argument {
	case "-C", "-g", "-h", "-p", "-r", "-t", "-u", "--chdir", "--close-from", "--group", "--host", "--prompt", "--role", "--type", "--user":
		return true
	default:
		return false
	}
}

func skipEnvArguments(tokens []string, index int) int {
	for index < len(tokens) {
		argument := tokens[index]
		if argument == "--" {
			return index + 1
		}
		if argument == "-u" || argument == "--unset" {
			if index+1 < len(tokens) {
				index += 2
				continue
			}
			return len(tokens)
		}
		if strings.HasPrefix(argument, "-") || strings.Contains(argument, "=") && !strings.HasPrefix(argument, "/") {
			index++
			continue
		}
		return index
	}
	return index
}

func containsAnyShellToken(arguments []string, values ...string) bool {
	for _, argument := range arguments {
		for _, value := range values {
			if strings.EqualFold(argument, value) {
				return true
			}
		}
	}
	return false
}

func hasUnboundedResourceCommand(command string, commands [][]string) bool {
	trimmed := strings.TrimSpace(command)
	if strings.HasPrefix(trimmed, ":(){") || strings.HasPrefix(trimmed, "while true") || strings.HasPrefix(trimmed, "for (;;") {
		return true
	}
	for _, tokens := range commands {
		index := executableIndex(tokens)
		if index < 0 {
			continue
		}
		switch strings.ToLower(path.Base(tokens[index])) {
		case "yes", "stress", "stress-ng":
			return true
		case "dd":
			if hasUnboundedDDInput(tokens[index+1:]) {
				return true
			}
		case "cat":
			if hasUnboundedCharacterDeviceInput(tokens[index+1:]) {
				return true
			}
		}
	}
	return false
}

func hasUnboundedDDInput(arguments []string) bool {
	fromUnboundedDevice, hasCount := false, false
	for index, argument := range arguments {
		lower := strings.ToLower(argument)
		if strings.HasPrefix(lower, "if=") && isUnboundedCharacterDevice(strings.TrimPrefix(lower, "if=")) {
			fromUnboundedDevice = true
		}
		if strings.HasPrefix(lower, "count=") {
			hasCount = true
		}
		if lower == "count" && index+1 < len(arguments) {
			hasCount = true
		}
	}
	return fromUnboundedDevice && !hasCount
}

func hasUnboundedCharacterDeviceInput(arguments []string) bool {
	for _, argument := range arguments {
		if isUnboundedCharacterDevice(strings.ToLower(argument)) {
			return true
		}
	}
	return false
}

func isUnboundedCharacterDevice(value string) bool {
	switch value {
	case "/dev/zero", "/dev/random", "/dev/urandom":
		return true
	default:
		return false
	}
}

type pathMatcher func(string) bool

func hasBaseSystemTreeDestruction(commands [][]string) bool {
	for _, tokens := range commands {
		if destroysBaseSystemTree(tokens, isBaseSystemPath) {
			return true
		}
	}
	return false
}

func destroysBaseSystemTree(tokens []string, matchesPath pathMatcher) bool {
	index := executableIndex(tokens)
	if index < 0 {
		return false
	}
	arguments := tokens[index+1:]
	switch strings.ToLower(path.Base(tokens[index])) {
	case "rm":
		return hasRecursiveRemove(tokens[index:]) && containsBaseSystemPath(arguments, matchesPath)
	case "rmdir", "unlink", "shred":
		return containsBaseSystemPath(arguments, matchesPath)
	case "find":
		return findDeletesBaseSystemTree(arguments, matchesPath)
	default:
		return false
	}
}

func hasRecursiveRemove(tokens []string) bool {
	for index, token := range tokens {
		if strings.ToLower(path.Base(token)) != "rm" {
			continue
		}
		for _, argument := range tokens[index+1:] {
			value := strings.ToLower(argument)
			if value == "--recursive" || strings.HasPrefix(value, "-") && strings.Contains(strings.TrimLeft(value, "-"), "r") {
				return true
			}
		}
	}
	return false
}

func findDeletesBaseSystemTree(arguments []string, matchesPath pathMatcher) bool {
	hasSystemPath, deletes := false, false
	for _, argument := range arguments {
		if !strings.HasPrefix(argument, "-") && matchesPath(argument) {
			hasSystemPath = true
		}
		if argument == "-delete" {
			deletes = true
		}
	}
	return hasSystemPath && deletes
}

func containsBaseSystemPath(arguments []string, matchesPath pathMatcher) bool {
	for _, argument := range arguments {
		if !strings.HasPrefix(argument, "-") && matchesPath(argument) {
			return true
		}
	}
	return false
}

func isBaseSystemPath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/") {
		return false
	}
	clean := path.Clean(value)
	if clean == "/" || strings.HasPrefix(clean, "/*") {
		return true
	}
	if clean == "/usr/local" || strings.HasPrefix(clean, "/usr/local/") {
		return false
	}
	for _, root := range []string{"/bin", "/sbin", "/lib", "/lib64", "/boot", "/etc", "/usr", "/dev", "/proc", "/sys", "/run"} {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}

func hasFormattingOrPartitioning(commands [][]string) bool {
	for _, tokens := range commands {
		index := executableIndex(tokens)
		if index < 0 {
			continue
		}
		program := strings.ToLower(path.Base(tokens[index]))
		switch {
		case program == "mkfs" || strings.HasPrefix(program, "mkfs."):
			return true
		case program == "fdisk", program == "cfdisk", program == "sfdisk", program == "gdisk", program == "sgdisk", program == "parted", program == "wipefs":
			return true
		}
	}
	return false
}

func hasBlockDeviceWrite(writesBlockDevice bool, commands [][]string) bool {
	if writesBlockDevice {
		return true
	}
	for _, tokens := range commands {
		if writesBlockDeviceWithPath(tokens, isRawBlockDevicePath) {
			return true
		}
	}
	return false
}

func writesBlockDeviceWithPath(tokens []string, matchesPath pathMatcher) bool {
	index := executableIndex(tokens)
	if index < 0 {
		return false
	}
	arguments := tokens[index+1:]
	switch strings.ToLower(path.Base(tokens[index])) {
	case "dd":
		return hasDDBlockDeviceDestination(arguments, matchesPath) || blockDeviceDestination(arguments, matchesPath)
	case "shred", "tee":
		return containsBlockDeviceArgument(arguments, matchesPath)
	case "cp", "mv", "install":
		return blockDeviceDestination(arguments, matchesPath)
	default:
		return false
	}
}

func hasDDBlockDeviceDestination(arguments []string, matchesPath pathMatcher) bool {
	for _, argument := range arguments {
		if strings.HasPrefix(strings.ToLower(argument), "of=") && matchesPath(argument[len("of="):]) {
			return true
		}
	}
	return false
}

func blockDeviceDestination(arguments []string, matchesPath pathMatcher) bool {
	for index := len(arguments) - 1; index >= 0; index-- {
		argument := arguments[index]
		if strings.HasPrefix(argument, "-") {
			continue
		}
		return matchesPath(argument)
	}
	return false
}

func containsBlockDeviceArgument(arguments []string, matchesPath pathMatcher) bool {
	for _, argument := range arguments {
		if matchesPath(argument) {
			return true
		}
	}
	return false
}

func isRawBlockDevicePath(value string) bool {
	clean := strings.ToLower(path.Clean(strings.TrimSpace(value)))
	if !strings.HasPrefix(clean, "/dev/") {
		return false
	}
	name := strings.TrimPrefix(clean, "/dev/")
	if strings.HasPrefix(name, "mapper/") || strings.HasPrefix(name, "disk/by-") {
		return true
	}
	for _, prefix := range []string{"sd", "vd", "xvd", "nvme", "mmcblk", "loop", "md", "dm-", "ram"} {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			return true
		}
	}
	return false
}

func isAlwaysTrueCondition(statements []*syntax.Stmt) bool {
	if len(statements) != 1 {
		return false
	}
	call, ok := statements[0].Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	tokens := literalShellWords(call.Args)
	return len(tokens) == 1 && strings.EqualFold(tokens[0], "true")
}

func formatMySQLStatements(statements []sqlparser.Statement) string {
	formatted := make([]string, 0, len(statements))
	for _, statement := range statements {
		formatted = append(formatted, sqlparser.String(statement))
	}
	return strings.Join(formatted, ";\n")
}

func mysqlContainsObviousTautology(expression sqlparser.Expr) bool {
	switch value := expression.(type) {
	case sqlparser.BoolVal:
		return bool(value)
	case *sqlparser.AndExpr:
		return mysqlContainsObviousTautology(value.Left) || mysqlContainsObviousTautology(value.Right)
	case *sqlparser.OrExpr:
		return mysqlContainsObviousTautology(value.Left) || mysqlContainsObviousTautology(value.Right)
	case *sqlparser.ComparisonExpr:
		return mysqlConstantComparisonAlwaysTrue(value)
	default:
		return false
	}
}

func mysqlConstantComparisonAlwaysTrue(expression *sqlparser.ComparisonExpr) bool {
	left, leftOK := mysqlLiteralValue(expression.Left)
	right, rightOK := mysqlLiteralValue(expression.Right)
	if !leftOK || !rightOK {
		return false
	}
	if expression.Operator == sqlparser.EqualOp || expression.Operator == sqlparser.NullSafeEqualOp {
		return left == right || mysqlNumericComparison(left, right, func(left, right float64) bool { return left == right })
	}
	if expression.Operator == sqlparser.NotEqualOp {
		return left != right && !mysqlNumericComparison(left, right, func(left, right float64) bool { return left == right })
	}
	switch expression.Operator {
	case sqlparser.LessThanOp:
		return mysqlNumericComparison(left, right, func(left, right float64) bool { return left < right })
	case sqlparser.GreaterThanOp:
		return mysqlNumericComparison(left, right, func(left, right float64) bool { return left > right })
	case sqlparser.LessEqualOp:
		return mysqlNumericComparison(left, right, func(left, right float64) bool { return left <= right })
	case sqlparser.GreaterEqualOp:
		return mysqlNumericComparison(left, right, func(left, right float64) bool { return left >= right })
	default:
		return false
	}
}

func mysqlLiteralValue(expression sqlparser.Expr) (string, bool) {
	literal, ok := expression.(*sqlparser.Literal)
	if !ok {
		return "", false
	}
	return literal.Val, true
}

func mysqlNumericComparison(left, right string, comparison func(float64, float64) bool) bool {
	leftValue, leftErr := strconv.ParseFloat(left, 64)
	rightValue, rightErr := strconv.ParseFloat(right, 64)
	return leftErr == nil && rightErr == nil && comparison(leftValue, rightValue)
}

func postgresContainsObviousTautology(node *pg_query.Node) bool {
	if node == nil {
		return false
	}
	if constant := node.GetAConst(); constant != nil {
		return constant.GetBoolval() != nil && constant.GetBoolval().GetBoolval()
	}
	if value := node.GetBoolean(); value != nil && value.GetBoolval() {
		return true
	}
	if expression := node.GetBoolExpr(); expression != nil {
		switch expression.GetBoolop() {
		case pg_query.BoolExprType_AND_EXPR, pg_query.BoolExprType_OR_EXPR:
			for _, argument := range expression.GetArgs() {
				if postgresContainsObviousTautology(argument) {
					return true
				}
			}
		}
		return false
	}
	if expression := node.GetAExpr(); expression != nil {
		return postgresConstantComparisonAlwaysTrue(expression)
	}
	return false
}

func postgresAExprOperator(expression *pg_query.A_Expr) string {
	for _, node := range expression.GetName() {
		if value := node.GetString_(); value != nil {
			return value.GetSval()
		}
	}
	return ""
}

func postgresConstantComparisonAlwaysTrue(expression *pg_query.A_Expr) bool {
	if expression.GetKind() != pg_query.A_Expr_Kind_AEXPR_OP {
		return false
	}
	left, leftOK := postgresLiteralValue(expression.GetLexpr())
	right, rightOK := postgresLiteralValue(expression.GetRexpr())
	if !leftOK || !rightOK {
		return false
	}
	switch postgresAExprOperator(expression) {
	case "=":
		return left == right || postgresNumericComparison(left, right, func(left, right float64) bool { return left == right })
	case "<>", "!=":
		return left != right && !postgresNumericComparison(left, right, func(left, right float64) bool { return left == right })
	case "<":
		return postgresNumericComparison(left, right, func(left, right float64) bool { return left < right })
	case ">":
		return postgresNumericComparison(left, right, func(left, right float64) bool { return left > right })
	case "<=":
		return postgresNumericComparison(left, right, func(left, right float64) bool { return left <= right })
	case ">=":
		return postgresNumericComparison(left, right, func(left, right float64) bool { return left >= right })
	default:
		return false
	}
}

func postgresLiteralValue(node *pg_query.Node) (string, bool) {
	constant := node.GetAConst()
	if constant == nil {
		return "", false
	}
	if value := constant.GetIval(); value != nil {
		return "i:" + strconv.FormatInt(int64(value.GetIval()), 10), true
	}
	if value := constant.GetFval(); value != nil {
		return "n:" + value.GetFval(), true
	}
	if value := constant.GetSval(); value != nil {
		return "s:" + value.GetSval(), true
	}
	if value := constant.GetBoolval(); value != nil {
		return "b:" + strconv.FormatBool(value.GetBoolval()), true
	}
	return "", false
}

func postgresNumericComparison(left, right string, comparison func(float64, float64) bool) bool {
	left = strings.TrimPrefix(strings.TrimPrefix(left, "i:"), "n:")
	right = strings.TrimPrefix(strings.TrimPrefix(right, "i:"), "n:")
	leftValue, leftErr := strconv.ParseFloat(left, 64)
	rightValue, rightErr := strconv.ParseFloat(right, 64)
	return leftErr == nil && rightErr == nil && comparison(leftValue, rightValue)
}

func postgresExplainExecutesQuery(statement *pg_query.ExplainStmt) bool {
	if statement == nil {
		return true
	}
	for _, option := range statement.GetOptions() {
		definition := option.GetDefElem()
		if definition == nil || !strings.EqualFold(definition.GetDefname(), "analyze") {
			continue
		}
		argument := definition.GetArg()
		if argument == nil {
			return true
		}
		if boolean := argument.GetBoolean(); boolean != nil {
			return boolean.GetBoolval()
		}
		if constant := argument.GetAConst(); constant != nil && constant.GetBoolval() != nil {
			return constant.GetBoolval().GetBoolval()
		}
		return true
	}
	return false
}

func postgresContainsWrite(root *pg_query.Node) bool {
	if root == nil {
		return false
	}
	found := false
	walkPostgres(root.ProtoReflect(), func(message protoreflect.Message) bool {
		node, ok := message.Interface().(*pg_query.Node)
		if !ok {
			return false
		}
		if node.GetInsertStmt() != nil || node.GetUpdateStmt() != nil || node.GetDeleteStmt() != nil || node.GetMergeStmt() != nil ||
			node.GetCopyStmt() != nil || node.GetTruncateStmt() != nil || node.GetDropdbStmt() != nil || node.GetTransactionStmt() != nil {
			found = true
		}
		return found
	})
	return found
}

func parseMySQLStatements(statement string) (parsed []sqlparser.Statement, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			parsed = nil
			err = fmt.Errorf("parse MySQL: %v", recovered)
		}
	}()
	return sqlparser.NewTestParser().ParseMultipleIgnoreEmpty(statement)
}

func parsePostgreSQLStatements(statement string) (tree *pg_query.ParseResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			tree = nil
			err = fmt.Errorf("parse PostgreSQL: %v", recovered)
		}
	}()
	return parsePostgreSQL(statement)
}

func walkPostgres(message protoreflect.Message, visit func(protoreflect.Message) bool) bool {
	if !message.IsValid() || visit(message) {
		return true
	}
	stop := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsList() {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if field.Kind() == protoreflect.MessageKind && walkPostgres(list.Get(index).Message(), visit) {
					stop = true
					return false
				}
			}
			return true
		}
		if field.Kind() == protoreflect.MessageKind && walkPostgres(value.Message(), visit) {
			stop = true
			return false
		}
		return true
	})
	return stop
}
