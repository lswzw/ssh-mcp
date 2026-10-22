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
