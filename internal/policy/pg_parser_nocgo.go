//go:build !cgo

package policy

import (
	"errors"
	"strings"
	"time"

	"github.com/pganalyze/pg_query_go/v6"

	"ssh-mcp/internal/store"
)

// The generated PostgreSQL protobuf types are pure Go, but pg_query's parser
// and deparser are CGO-only. Portable builds retain direct execution with a
// conservative lexical boundary for fixed hard-stop rules; AST normalization
// remains available only in CGO builds.
var errPostgreSQLParserUnavailable = errors.New("PostgreSQL parser is unavailable in this CGO-free build")

func evaluatePostgreSQL(result Result, engine store.DatabaseEngine, statement string, timeout time.Duration, maxRows, maxBytes int) Result {
	statements := splitPortablePostgreSQL(statement)
	if len(statements) == 0 {
		result.ExecutionClass = SQLExecutionMayWrite
		return withDecision(result, DecisionAllowed, ReasonDiagnostic)
	}
	result = sqlResult(engine, strings.Join(statements, ";\n"), timeout, maxRows, maxBytes)
	result.ExecutionClass = SQLExecutionRead
	for _, item := range statements {
		if match, found := portablePostgreSQLHardStop(item); found {
			return withHardStop(result, match)
		}
		if !portablePostgreSQLReadOnly(item) {
			result.ExecutionClass = SQLExecutionMayWrite
		}
	}
	return withDecision(result, DecisionAllowed, ReasonDiagnostic)
}

func parsePostgreSQL(string) (*pg_query.ParseResult, error) {
	return nil, errPostgreSQLParserUnavailable
}

func deparsePostgreSQL(*pg_query.ParseResult) (string, error) {
	return "", errPostgreSQLParserUnavailable
}

func splitPostgreSQLStatements(statement string) ([]string, error) {
	statements := splitPortablePostgreSQL(statement)
	if len(statements) == 0 {
		return nil, ErrNoStatements
	}
	return statements, nil
}
