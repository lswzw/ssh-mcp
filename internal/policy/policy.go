// Package policy normalizes SSH and SQL requests before a transport executes
// them. This fork keeps only request-shape validation, per-target command
// blacklists and bounded transport budgets; there is no fixed semantic
// hard-stop registry. See README fork notice.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
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
	Version = "2026-10-22.1"

	// Default budgets. Callers may pass any finite value; these are defaults
	// only and are reported through describe_target_capability.
	DefaultSSHTimeout = 300 * time.Second
	DefaultSQLTimeout = 30 * time.Second
	DefaultMaxRows    = 1000
	DefaultMaxBytes   = 64 << 10
)

type Decision string

const (
	DecisionAllowed  Decision = "direct"
	DecisionRejected Decision = "rejected"
	// DecisionPermanentlyRejected is retained for wire and audit compatibility.
	// This fork never produces it: no request is permanently prohibited.
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

	// The former hard-stop identifiers are retained as reserved values so old
	// audit rows keep decoding. Nothing in this fork emits them.
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
	Command                  string
	AsRoot                   bool
	WorkingDirectory         string
	Timeout                  time.Duration
	MaxBytes                 int
	CommandBlacklistPatterns []string
}

// RegisteredRemoteTarget is retained for source compatibility with callers
// that still describe the registry. It no longer affects evaluation.
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

// Limiter bounds dispatch concurrency.
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
	if blacklistPattern != "" {
		return withTargetCommandBlacklist(result, blacklistPattern)
	}

	// The shell AST is used only to detect capability facts (interactive
	// programs, literal sudo). Syntax the local parser does not understand is
	// left to the remote shell; it is never a rejection reason.
	analysis, err := analyzeShellProgram(command)
	if err != nil || len(analysis.commands) == 0 {
		return withDecision(result, DecisionAllowed, ReasonStaticShell)
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

// HardStopRuleIDs is retained for protocol compatibility. This fork has no
// fixed rules, so it always returns an empty slice.
func HardStopRuleIDs() []string { return []string{} }

// SafetyNotice is the single source of truth for the risk facts reported by
// describe_target_capability. The MCP instructions embed the same lines so the
// two surfaces cannot drift apart.
func SafetyNotice() []string {
	return []string{
		"本分支没有固定硬拦截规则：任何命令与 SQL 都会真实派发并真实执行。",
		"派发删除或覆盖文件、DROP/TRUNCATE/ALTER DROP、无 WHERE 的 UPDATE/DELETE、格式化与改分区、停止或重启服务、改权限属主、写系统目录、批量变更之前，必须先向当前用户复述具体命令或 SQL 与影响范围，并取得一次显式确认。",
		"无法判断是否可逆时，一律按不可逆处理；用户对某一次任务的授权不等于对更大范围的授权。",
		"远端已派发但超时、断连或协议错误时结果为 outcome_unknown，不得自动重试，应先做受限核验。",
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

// evaluateMySQLDefaultAllow classifies statements for credential routing. A
// statement the local parser does not understand is sent to the server as-is
// and treated as may-write.
func evaluateMySQLDefaultAllow(result Result, engine store.DatabaseEngine, statement string, timeout time.Duration, maxRows, maxBytes int) Result {
	parsed, err := parseMySQLStatements(statement)
	if err != nil || len(parsed) == 0 {
		result.ExecutionClass = SQLExecutionMayWrite
		return withDecision(result, DecisionAllowed, ReasonDiagnostic)
	}
	result = sqlResult(engine, formatMySQLStatements(parsed), timeout, maxRows, maxBytes)
	result.ExecutionClass = SQLExecutionRead
	for _, item := range parsed {
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

func normalizedSSHWorkingDirectory(directory string) (string, bool) {
	if directory == "" {
		return "", true
	}
	if len(directory) > 4096 || strings.ContainsAny(directory, "\x00\r\n") || !path.IsAbs(directory) || path.Clean(directory) != directory {
		return "", false
	}
	return directory, true
}

func formatMySQLStatements(statements []sqlparser.Statement) string {
	formatted := make([]string, 0, len(statements))
	for _, statement := range statements {
		formatted = append(formatted, sqlparser.String(statement))
	}
	return strings.Join(formatted, ";\n")
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

// shellAnalysis collects the literal command words of a POSIX shell program so
// capability facts can be derived. It never rejects a program.
type shellAnalysis struct {
	commands [][]string
}

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
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		tokens := literalShellWords(call.Args)
		if len(tokens) == 0 {
			return true
		}
		analysis.commands = append(analysis.commands, tokens)
		if source, embedded := staticEmbeddedShellSource(tokens); embedded {
			nested, err := analyzeShellProgram(source)
			if err != nil {
				embeddedSourceErr = fmt.Errorf("embedded sh -c source: %w", err)
				return false
			}
			analysis.commands = append(analysis.commands, nested.commands...)
		}
		return true
	})
	if embeddedSourceErr != nil {
		return shellAnalysis{}, embeddedSourceErr
	}
	return analysis, nil
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
