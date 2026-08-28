//go:build dependencies

// Package dependencies pins approved implementation dependencies before their
// runtime packages are introduced in later phases. It is never built normally.
package dependencies

import (
	_ "charm.land/bubbles/v2"
	_ "charm.land/bubbletea/v2"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5"
	_ "github.com/pganalyze/pg_query_go/v6"
	_ "golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
	_ "vitess.io/vitess/go/vt/sqlparser"
)
