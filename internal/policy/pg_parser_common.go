package policy

import (
	"errors"
	"strings"
)

var ErrNoStatements = errors.New("no PostgreSQL statements")

func trimPostgreSQLStatement(value string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), ";"))
}

type portablePostgreSQLToken struct {
	value string
	depth int
}

// splitPortablePostgreSQL is deliberately lexical rather than semantic. It is
// used only when the CGO PostgreSQL parser is unavailable, where preserving
// statement boundaries is preferable to treating a semicolon in a literal or
// comment as a new operation.
func splitPortablePostgreSQL(input string) []string {
	var result []string
	start := 0
	inSingle, inDouble := false, false
	escapeString := false
	dollarQuote := ""
	lineComment := false
	blockCommentDepth := 0
	for index := 0; index < len(input); index++ {
		if lineComment {
			if input[index] == '\n' {
				lineComment = false
			}
			continue
		}
		if blockCommentDepth > 0 {
			if strings.HasPrefix(input[index:], "/*") {
				blockCommentDepth++
				index++
				continue
			}
			if strings.HasPrefix(input[index:], "*/") {
				blockCommentDepth--
				index++
			}
			continue
		}
		if dollarQuote != "" {
			if strings.HasPrefix(input[index:], dollarQuote) {
				index += len(dollarQuote) - 1
				dollarQuote = ""
			}
			continue
		}
		character := input[index]
		if inSingle {
			if escapeString && character == '\\' && index+1 < len(input) {
				index++
				continue
			}
			if character == '\'' {
				if index+1 < len(input) && input[index+1] == '\'' {
					index++
					continue
				}
				inSingle = false
				escapeString = false
			}
			continue
		}
		if inDouble {
			if character == '"' {
				if index+1 < len(input) && input[index+1] == '"' {
					index++
					continue
				}
				inDouble = false
			}
			continue
		}
		switch character {
		case '-':
			if strings.HasPrefix(input[index:], "--") {
				lineComment = true
				index++
			}
		case '/':
			if strings.HasPrefix(input[index:], "/*") {
				blockCommentDepth = 1
				index++
			}
		case '\'':
			inSingle = true
			escapeString = postgresEscapeStringStart(input, index)
		case '"':
			inDouble = true
		case '$':
			if delimiter, ok := postgresDollarQuote(input[index:]); ok {
				dollarQuote = delimiter
				index += len(delimiter) - 1
			}
		case ';':
			if value := trimPostgreSQLStatement(input[start:index]); value != "" {
				result = append(result, value)
			}
			start = index + 1
		}
	}
	if value := trimPostgreSQLStatement(input[start:]); value != "" {
		result = append(result, value)
	}
	return result
}

func postgresDollarQuote(value string) (string, bool) {
	if len(value) < 2 || value[0] != '$' {
		return "", false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character == '$' {
			return value[:index+1], true
		}
		if !(character == '_' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return "", false
		}
	}
	return "", false
}

func portablePostgreSQLHardStop(statement string) (hardStopMatch, bool) {
	tokens := portablePostgreSQLTokens(statement)
	topLevel := portablePostgreSQLTopLevel(tokens)
	if len(topLevel) == 0 {
		return hardStopMatch{}, false
	}
	if fragment := portablePostgreSQLOpaqueFragment(topLevel); fragment != "" {
		return hardStopMatch{id: ReasonOpaqueSQLEffect, fragment: fragment}, true
	}
	if portablePostgreSQLHasPrefix(topLevel, "DROP", "DATABASE") ||
		portablePostgreSQLHasPrefix(topLevel, "DROP", "SCHEMA") ||
		portablePostgreSQLHasPrefix(topLevel, "DROP", "TABLE") ||
		portablePostgreSQLHasPrefix(topLevel, "DROP", "FOREIGN", "TABLE") ||
		portablePostgreSQLHasPrefix(topLevel, "DROP", "TEMPORARY", "TABLE") {
		return hardStopMatch{id: ReasonDropDatabaseSchemaTable, fragment: "DROP DATABASE/SCHEMA/TABLE"}, true
	}
	if portablePostgreSQLHasPrefix(topLevel, "TRUNCATE") {
		return hardStopMatch{id: ReasonTruncateTable, fragment: "TRUNCATE TABLE"}, true
	}
	if portablePostgreSQLHasPrefix(topLevel, "ALTER") && portablePostgreSQLContains(topLevel[1:], "DROP") {
		return hardStopMatch{id: ReasonAlterDrop, fragment: "ALTER ... DROP"}, true
	}
	if fragment := portablePostgreSQLUnconditionalWrite(tokens, topLevel); fragment != "" {
		return hardStopMatch{id: ReasonUnconditionalWrite, fragment: fragment}, true
	}
	return hardStopMatch{}, false
}

func portablePostgreSQLReadOnly(statement string) bool {
	topLevel := portablePostgreSQLTopLevel(portablePostgreSQLTokens(statement))
	if len(topLevel) == 0 {
		return false
	}
	switch topLevel[0] {
	case "SELECT", "SHOW", "VALUES":
		return !portablePostgreSQLHasSequence(topLevel, "FOR", "UPDATE")
	case "EXPLAIN":
		return !portablePostgreSQLContains(topLevel, "ANALYZE") && !portablePostgreSQLContains(topLevel, "ANALYSE")
	default:
		return false
	}
}

func portablePostgreSQLTokens(input string) []portablePostgreSQLToken {
	var tokens []portablePostgreSQLToken
	depth := 0
	for index := 0; index < len(input); {
		character := input[index]
		if isPortableSQLSpace(character) {
			index++
			continue
		}
		if strings.HasPrefix(input[index:], "--") {
			index += 2
			for index < len(input) && input[index] != '\n' {
				index++
			}
			continue
		}
		if strings.HasPrefix(input[index:], "/*") {
			index = skipPortableSQLBlockComment(input, index)
			continue
		}
		switch character {
		case '\'':
			index = skipPortableSQLQuoted(input, index, '\'', postgresEscapeStringStart(input, index))
			continue
		case '"':
			index = skipPortableSQLQuoted(input, index, '"', false)
			continue
		case '$':
			if delimiter, ok := postgresDollarQuote(input[index:]); ok {
				index += len(delimiter)
				if end := strings.Index(input[index:], delimiter); end >= 0 {
					index += end + len(delimiter)
				} else {
					index = len(input)
				}
				continue
			}
		case '(':
			depth++
			index++
			continue
		case ')':
			if depth > 0 {
				depth--
			}
			index++
			continue
		}
		if isPortableSQLIdentifierStart(character) {
			start := index
			for index < len(input) && isPortableSQLIdentifierPart(input[index]) {
				index++
			}
			tokens = append(tokens, portablePostgreSQLToken{value: strings.ToUpper(input[start:index]), depth: depth})
			continue
		}
		if character >= '0' && character <= '9' {
			start := index
			for index < len(input) && input[index] >= '0' && input[index] <= '9' {
				index++
			}
			tokens = append(tokens, portablePostgreSQLToken{value: input[start:index], depth: depth})
			continue
		}
		if (character == '!' || character == '<' || character == '>') && index+1 < len(input) && input[index+1] == '=' || character == '<' && index+1 < len(input) && input[index+1] == '>' {
			tokens = append(tokens, portablePostgreSQLToken{value: input[index : index+2], depth: depth})
			index += 2
			continue
		}
		if character == '=' {
			tokens = append(tokens, portablePostgreSQLToken{value: "=", depth: depth})
		}
		index++
	}
	return tokens
}

func skipPortableSQLBlockComment(input string, index int) int {
	depth := 1
	index += 2
	for index < len(input) && depth > 0 {
		if strings.HasPrefix(input[index:], "/*") {
			depth++
			index += 2
			continue
		}
		if strings.HasPrefix(input[index:], "*/") {
			depth--
			index += 2
			continue
		}
		index++
	}
	return index
}

func skipPortableSQLQuoted(input string, index int, quote byte, escapeBackslash bool) int {
	index++
	for index < len(input) {
		if escapeBackslash && input[index] == '\\' && index+1 < len(input) {
			index += 2
			continue
		}
		if input[index] == quote {
			if index+1 < len(input) && input[index+1] == quote {
				index += 2
				continue
			}
			return index + 1
		}
		index++
	}
	return index
}

// postgresEscapeStringStart reports whether quote begins PostgreSQL's E'...'
// escape-string syntax. In ordinary strings, a backslash is not an escape when
// standard_conforming_strings is enabled (the server default), so treating it
// as one could hide a later statement from the portable policy backend.
func postgresEscapeStringStart(input string, quoteIndex int) bool {
	if quoteIndex < 1 || quoteIndex >= len(input) || input[quoteIndex] != '\'' {
		return false
	}
	prefix := input[quoteIndex-1]
	if prefix != 'E' && prefix != 'e' {
		return false
	}
	return quoteIndex < 2 || !isPortableSQLIdentifierPart(input[quoteIndex-2])
}

func portablePostgreSQLTopLevel(tokens []portablePostgreSQLToken) []string {
	result := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if token.depth == 0 {
			result = append(result, token.value)
		}
	}
	return result
}

func portablePostgreSQLOpaqueFragment(tokens []string) string {
	prefixes := [][]string{
		{"CALL"}, {"DO"}, {"PREPARE"}, {"EXECUTE"}, {"DEALLOCATE"}, {"COPY"}, {"LOAD"},
		{"CREATE", "FUNCTION"}, {"ALTER", "FUNCTION"}, {"DROP", "FUNCTION"},
		{"CREATE", "PROCEDURE"}, {"ALTER", "PROCEDURE"}, {"DROP", "PROCEDURE"},
		{"CREATE", "TRIGGER"}, {"ALTER", "TRIGGER"}, {"DROP", "TRIGGER"},
		{"CREATE", "EXTENSION"}, {"ALTER", "EXTENSION"}, {"DROP", "EXTENSION"},
		{"CREATE", "FOREIGN", "DATA", "WRAPPER"}, {"ALTER", "FOREIGN", "DATA", "WRAPPER"},
		{"CREATE", "SERVER"}, {"ALTER", "SERVER"}, {"CREATE", "FOREIGN", "TABLE"},
		{"IMPORT", "FOREIGN", "SCHEMA"}, {"CREATE", "USER", "MAPPING"}, {"ALTER", "USER", "MAPPING"}, {"DROP", "USER", "MAPPING"},
		{"CREATE", "SUBSCRIPTION"}, {"ALTER", "SUBSCRIPTION"}, {"DROP", "SUBSCRIPTION"},
	}
	for _, prefix := range prefixes {
		if portablePostgreSQLHasPrefix(tokens, prefix...) {
			return strings.Join(prefix, " ")
		}
	}
	return ""
}

func portablePostgreSQLUnconditionalWrite(tokens []portablePostgreSQLToken, topLevel []string) string {
	operation := ""
	operationIndex := -1
	topLevelIndex := 0
	for index, token := range tokens {
		if token.depth != 0 {
			continue
		}
		if topLevelIndex == 0 && (token.value == "UPDATE" || token.value == "DELETE") {
			operation = token.value
			operationIndex = index
			break
		}
		topLevelIndex++
	}
	if operation == "" && len(topLevel) > 1 && topLevel[0] == "WITH" {
		// A data-modifying CTE ends in a top-level UPDATE/DELETE. Ignore the
		// UPDATE token in SELECT ... FOR UPDATE locking clauses.
		for index, token := range tokens {
			if index == 0 || token.depth != 0 || (token.value != "UPDATE" && token.value != "DELETE") {
				continue
			}
			previous := ""
			for previousIndex := index - 1; previousIndex >= 0; previousIndex-- {
				if tokens[previousIndex].depth == 0 {
					previous = tokens[previousIndex].value
					break
				}
			}
			if previous != "FOR" {
				operation = token.value
				operationIndex = index
				break
			}
		}
	}
	if operation == "" || operationIndex < 0 {
		return ""
	}
	whereIndex := -1
	for index := operationIndex + 1; index < len(tokens); index++ {
		if tokens[index].depth == 0 && tokens[index].value == "WHERE" {
			whereIndex = index
			break
		}
	}
	if whereIndex < 0 || portablePostgreSQLContainsObviousTautology(tokens[whereIndex+1:]) {
		return operation + " 缺少限制条件"
	}
	return ""
}

func portablePostgreSQLContainsObviousTautology(tokens []portablePostgreSQLToken) bool {
	// Only inspect the WHERE expression. A returned boolean or a boolean
	// comparison such as "enabled = TRUE" is not an unconditional write.
	end := len(tokens)
	for index, token := range tokens {
		if token.depth == 0 && (token.value == "RETURNING" || token.value == "ORDER" || token.value == "LIMIT" || token.value == "OFFSET") {
			end = index
			break
		}
	}
	tokens = tokens[:end]
	if len(tokens) == 0 {
		return false
	}

	minimumDepth := tokens[0].depth
	for _, token := range tokens[1:] {
		if token.depth < minimumDepth {
			minimumDepth = token.depth
		}
	}
	values := make([]string, 0, len(tokens))
	depths := make([]int, 0, len(tokens))
	for _, token := range tokens {
		values = append(values, token.value)
		depths = append(depths, token.depth)
	}
	if portablePostgreSQLSimpleTautology(values) {
		return true
	}

	// A top-level `... OR TRUE` or `... OR 1 = 1` is unconditionally true.
	// Do not infer across an AND or nested group: that would reject valid
	// selective predicates such as `id = 1 AND (enabled = TRUE)`.
	for index := range values {
		if depths[index] != minimumDepth || !portablePostgreSQLTautologyAt(values, index) {
			continue
		}
		if index > 0 && depths[index-1] == minimumDepth && values[index-1] == "OR" {
			return true
		}
		end := portablePostgreSQLTautologyEnd(values, index)
		if end < len(values) && depths[end] == minimumDepth && values[end] == "OR" {
			return true
		}
	}
	return false
}

func portablePostgreSQLSimpleTautology(values []string) bool {
	return len(values) == 1 && values[0] == "TRUE" ||
		len(values) == 3 && portablePostgreSQLTautologyAt(values, 0)
}

func portablePostgreSQLTautologyAt(values []string, index int) bool {
	if index < 0 || index >= len(values) {
		return false
	}
	if values[index] == "TRUE" {
		if index > 0 && (values[index-1] == "=" || values[index-1] == "IS" || values[index-1] == "NOT") {
			return false
		}
		return index+1 == len(values) || values[index+1] != "="
	}
	if index+2 >= len(values) {
		return false
	}
	return values[index] == "1" && values[index+1] == "=" && values[index+2] == "1" ||
		values[index] == "0" && (values[index+1] == "!=" || values[index+1] == "<>") && values[index+2] == "1" ||
		values[index] == "1" && (values[index+1] == "!=" || values[index+1] == "<>") && values[index+2] == "0"
}

func portablePostgreSQLTautologyEnd(values []string, index int) int {
	if index >= 0 && index < len(values) && values[index] == "TRUE" {
		return index + 1
	}
	return index + 3
}

func portablePostgreSQLHasPrefix(tokens []string, prefix ...string) bool {
	if len(tokens) < len(prefix) {
		return false
	}
	for index, value := range prefix {
		if tokens[index] != value {
			return false
		}
	}
	return true
}

func portablePostgreSQLHasSequence(tokens []string, sequence ...string) bool {
	for index := 0; index+len(sequence) <= len(tokens); index++ {
		if portablePostgreSQLHasPrefix(tokens[index:], sequence...) {
			return true
		}
	}
	return false
}

func portablePostgreSQLContains(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

func isPortableSQLSpace(character byte) bool {
	return character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '\f'
}

func isPortableSQLIdentifierStart(character byte) bool {
	return character == '_' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}

func isPortableSQLIdentifierPart(character byte) bool {
	return isPortableSQLIdentifierStart(character) || character >= '0' && character <= '9' || character == '$'
}
