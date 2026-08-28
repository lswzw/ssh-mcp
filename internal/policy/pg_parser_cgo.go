//go:build cgo

package policy

import (
	"time"

	"github.com/pganalyze/pg_query_go/v6"

	"ssh-mcp/internal/store"
)

func evaluatePostgreSQL(result Result, engine store.DatabaseEngine, statement string, timeout time.Duration, maxRows, maxBytes int) Result {
	return evaluatePostgreSQLDefaultAllow(result, engine, statement, timeout, maxRows, maxBytes)
}

func parsePostgreSQL(statement string) (*pg_query.ParseResult, error) {
	return pg_query.Parse(statement)
}

func deparsePostgreSQL(tree *pg_query.ParseResult) (string, error) {
	return pg_query.Deparse(tree)
}

func splitPostgreSQLStatements(statement string) ([]string, error) {
	tree, err := parsePostgreSQLStatements(statement)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(tree.GetStmts()))
	for _, raw := range tree.GetStmts() {
		single := &pg_query.ParseResult{Version: tree.GetVersion(), Stmts: []*pg_query.RawStmt{raw}}
		deparsed, err := deparsePostgreSQL(single)
		if err != nil {
			return nil, err
		}
		result = append(result, trimPostgreSQLStatement(deparsed))
	}
	if len(result) == 0 {
		return nil, ErrNoStatements
	}
	return result, nil
}
