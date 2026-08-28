package policy

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// knownPathCommand records a literal command whose relative paths can be
// resolved from a directory known to the daemon. It intentionally models only
// the small, static context needed by the fixed path rules.
type knownPathCommand struct {
	tokens           []string
	workingDirectory string
	outputRedirects  []string
}

// staticPathContext is valid only in a direct command or a statically known
// literal cd && success chain. An empty directory can still derive an
// absolute literal cd; an unknown context cannot derive any path context.
type staticPathContext struct {
	workingDirectory string
	allowsLiteralCD  bool
}

func initialStaticPathContext(directory string) staticPathContext {
	return staticPathContext{workingDirectory: directory, allowsLiteralCD: true}
}

func unknownStaticPathContext() staticPathContext { return staticPathContext{} }

func normalizedSSHWorkingDirectory(directory string) (string, bool) {
	if directory == "" {
		return "", true
	}
	if len(directory) > 4096 || strings.ContainsAny(directory, "\x00\r\n") || !path.IsAbs(directory) || path.Clean(directory) != directory {
		return "", false
	}
	return directory, true
}

// collectKnownPathCommands derives directory context only from a declared
// session directory and literal `cd ... &&` success chains. Lists, branches,
// pipelines, negation, and other compound flows deliberately become unknown.
func collectKnownPathCommands(command, initialDirectory string) []knownPathCommand {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	commands := make([]knownPathCommand, 0)
	context := initialStaticPathContext(initialDirectory)
	if declaresCDFunction(file) {
		context.allowsLiteralCD = false
	}
	collectKnownPathStatements(file.Stmts, context, &commands)
	return commands
}

func declaresCDFunction(file *syntax.File) bool {
	if file == nil {
		return false
	}
	declared := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if declared {
			return false
		}
		function, ok := node.(*syntax.FuncDecl)
		if !ok || function.Name == nil || function.Name.Value != "cd" {
			return true
		}
		declared = true
		return false
	})
	return declared
}

func collectKnownPathStatements(statements []*syntax.Stmt, context staticPathContext, commands *[]knownPathCommand) {
	for _, statement := range statements {
		collectKnownPathStatement(statement, context, commands)
		// A shell list separator does not prove whether a preceding command
		// changed cwd, so the next item receives no inferred context.
		context = unknownStaticPathContext()
	}
}

func collectKnownPathStatement(statement *syntax.Stmt, context staticPathContext, commands *[]knownPathCommand) staticPathContext {
	if statement == nil || statement.Cmd == nil {
		return context
	}
	next := collectKnownPathExpression(statement.Cmd, statement.Redirs, context, commands)
	if statement.Negated || statement.Background || statement.Coprocess || statement.Disown {
		return unknownStaticPathContext()
	}
	return next
}

func collectKnownPathExpression(expression syntax.Command, redirects []*syntax.Redirect, context staticPathContext, commands *[]knownPathCommand) staticPathContext {
	switch value := expression.(type) {
	case *syntax.CallExpr:
		return collectKnownPathCall(value, redirects, context, commands)
	case *syntax.BinaryCmd:
		recordKnownOutputRedirects(redirects, context, commands)
		left := collectKnownPathStatement(value.X, context, commands)
		if value.Op != syntax.AndStmt {
			collectKnownPathStatement(value.Y, unknownStaticPathContext(), commands)
			return unknownStaticPathContext()
		}
		return collectKnownPathStatement(value.Y, left, commands)
	case *syntax.Subshell:
		recordKnownOutputRedirects(redirects, context, commands)
		collectKnownPathStatements(value.Stmts, context, commands)
		// A subshell cannot change its caller's cwd.
		return context
	case *syntax.Block:
		recordKnownOutputRedirects(redirects, context, commands)
		collectKnownPathStatements(value.Stmts, context, commands)
		// A block can change its caller's cwd through unsupported list forms.
		return unknownStaticPathContext()
	default:
		return unknownStaticPathContext()
	}
}

func collectKnownPathCall(call *syntax.CallExpr, redirects []*syntax.Redirect, context staticPathContext, commands *[]knownPathCommand) staticPathContext {
	tokens, callContext, ok := recordKnownLiteralPathCall(call, context, literalOutputRedirects(redirects), commands)
	if !ok {
		return unknownStaticPathContext()
	}
	return literalCDContext(tokens, callContext)
}

func recordKnownLiteralPathCall(call *syntax.CallExpr, context staticPathContext, redirects []string, commands *[]knownPathCommand) ([]string, staticPathContext, bool) {
	if !literalShellWordsStatic(call.Args) {
		return nil, unknownStaticPathContext(), false
	}
	tokens := literalShellWords(call.Args)
	callContext := context
	if hasWorkingDirectoryWrapper(tokens) {
		callContext = unknownStaticPathContext()
	}
	appendKnownPathCommand(tokens, callContext.workingDirectory, nil, commands)
	// Shell output redirects are opened by the parent shell before a wrapper
	// such as env --chdir or sudo --chdir starts its child process.
	appendKnownPathCommand(nil, context.workingDirectory, redirects, commands)
	if source, embedded := staticEmbeddedShellSource(tokens); embedded {
		collectKnownPathCommandsFromSource(source, callContext, commands)
	}
	return tokens, callContext, true
}

func collectKnownPathCommandsFromSource(source string, context staticPathContext, commands *[]knownPathCommand) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(source), "")
	if err != nil {
		return
	}
	if declaresCDFunction(file) {
		context.allowsLiteralCD = false
	}
	collectKnownPathStatements(file.Stmts, context, commands)
}

func literalCDContext(tokens []string, context staticPathContext) staticPathContext {
	if len(tokens) == 0 {
		return context
	}
	if tokens[0] != "cd" || !context.allowsLiteralCD {
		if invokesCD(tokens) {
			return unknownStaticPathContext()
		}
		return context
	}
	arguments := tokens[1:]
	if len(arguments) == 2 && arguments[0] == "--" {
		arguments = arguments[1:]
	}
	if len(arguments) != 1 || strings.HasPrefix(arguments[0], "-") {
		return unknownStaticPathContext()
	}
	if !isStaticCDTarget(arguments[0]) {
		return unknownStaticPathContext()
	}
	resolved, ok := resolveKnownPath(context.workingDirectory, arguments[0])
	if !ok {
		return unknownStaticPathContext()
	}
	return staticPathContext{workingDirectory: resolved, allowsLiteralCD: true}
}

// isStaticCDTarget permits only operands whose resolution does not depend on
// CDPATH or pathname expansion. Quoted glob characters are conservatively
// treated as unknown because literal token extraction does not retain quoting.
func isStaticCDTarget(value string) bool {
	if strings.ContainsAny(value, "*?[{}") {
		return false
	}
	return path.IsAbs(value) || value == "." || value == ".." || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../")
}

func invokesCD(tokens []string) bool {
	if len(tokens) > 0 {
		switch strings.ToLower(path.Base(tokens[0])) {
		case "command", "builtin":
			// These wrappers can invoke cd with options that are not part of
			// the direct literal cd grammar, so their cwd effect is unknown.
			return true
		}
	}
	index := executableIndex(tokens)
	if index < 0 {
		return false
	}
	program := strings.ToLower(path.Base(tokens[index]))
	switch program {
	case "cd", "builtin", "pushd", "popd", "trap":
		return true
	default:
		return false
	}
}

// hasWorkingDirectoryWrapper detects literal wrappers that run their child in
// another directory. Their path effects are intentionally left unknown.
func hasWorkingDirectoryWrapper(tokens []string) bool {
	for index := 0; index < len(tokens); {
		program := strings.ToLower(path.Base(tokens[index]))
		switch program {
		case "env":
			if envChangesWorkingDirectory(tokens, index+1) {
				return true
			}
			index = skipEnvArguments(tokens, index+1)
			continue
		case "sudo":
			if sudoChangesWorkingDirectory(tokens, index+1) {
				return true
			}
			index = skipSudoArguments(tokens, index+1)
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
		return false
	}
	return false
}

func envChangesWorkingDirectory(tokens []string, index int) bool {
	for index < len(tokens) {
		argument := tokens[index]
		switch {
		case argument == "--":
			return false
		case argument == "-C", argument == "--chdir", strings.HasPrefix(argument, "--chdir="), strings.HasPrefix(argument, "-C"):
			return true
		case argument == "-u", argument == "--unset":
			index += 2
			continue
		case strings.HasPrefix(argument, "-") || strings.Contains(argument, "=") && !strings.HasPrefix(argument, "/"):
			index++
			continue
		default:
			return false
		}
	}
	return false
}

func sudoChangesWorkingDirectory(tokens []string, index int) bool {
	for index < len(tokens) {
		argument := tokens[index]
		switch {
		case argument == "--":
			return false
		case argument == "--chdir", argument == "-D", strings.HasPrefix(argument, "--chdir="), strings.HasPrefix(argument, "-D"):
			return true
		case !strings.HasPrefix(argument, "-"):
			return false
		case sudoOptionTakesValue(argument) && !strings.Contains(argument, "="):
			index += 2
			continue
		default:
			index++
			continue
		}
	}
	return false
}

func recordKnownOutputRedirects(redirects []*syntax.Redirect, context staticPathContext, commands *[]knownPathCommand) {
	appendKnownPathCommand(nil, context.workingDirectory, literalOutputRedirects(redirects), commands)
}

func appendKnownPathCommand(tokens []string, directory string, redirects []string, commands *[]knownPathCommand) {
	if directory == "" || (len(tokens) == 0 && len(redirects) == 0) {
		return
	}
	*commands = append(*commands, knownPathCommand{
		tokens:           append([]string(nil), tokens...),
		workingDirectory: directory,
		outputRedirects:  append([]string(nil), redirects...),
	})
}

func literalOutputRedirects(redirects []*syntax.Redirect) []string {
	result := make([]string, 0, len(redirects))
	for _, redirect := range redirects {
		if redirect == nil || !isOutputRedirection(redirect.Op) || redirect.Word == nil {
			continue
		}
		if destination, ok := literalShellWord(redirect.Word); ok {
			result = append(result, destination)
		}
	}
	return result
}

func resolveKnownPath(directory, value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsRune(value, '\x00') || strings.HasPrefix(value, "~") {
		return "", false
	}
	if path.IsAbs(value) {
		return path.Clean(value), true
	}
	if directory == "" {
		return "", false
	}
	return path.Clean(path.Join(directory, value)), true
}

func knownPathMatcher(directory string, matchesPath pathMatcher) pathMatcher {
	return func(value string) bool {
		resolved, ok := resolveKnownPath(directory, value)
		return ok && matchesPath(resolved)
	}
}

func hasKnownBaseSystemTreeDestruction(commands []knownPathCommand) bool {
	for _, command := range commands {
		if destroysBaseSystemTree(command.tokens, knownPathMatcher(command.workingDirectory, isBaseSystemPath)) {
			return true
		}
	}
	return false
}

func hasKnownBlockDeviceWrite(commands []knownPathCommand) bool {
	for _, command := range commands {
		matchesPath := knownPathMatcher(command.workingDirectory, isRawBlockDevicePath)
		for _, destination := range command.outputRedirects {
			if matchesPath(destination) {
				return true
			}
		}
		if writesBlockDeviceWithPath(command.tokens, matchesPath) {
			return true
		}
	}
	return false
}
