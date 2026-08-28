package dbtransport

import (
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestKnownFailureKindClassifiesOnlyExplicitServerFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "MySQL syntax", err: fmt.Errorf("query: %w", &mysql.MySQLError{Number: 1064}), want: FailureKindSyntax},
		{name: "MySQL permission", err: &mysql.MySQLError{Number: 1142}, want: FailureKindPermission},
		{name: "MySQL constraint", err: &mysql.MySQLError{Number: 1062}, want: FailureKindConstraint},
		{name: "PostgreSQL syntax", err: &pgconn.PgError{Code: "42601"}, want: FailureKindSyntax},
		{name: "PostgreSQL permission", err: &pgconn.PgError{Code: "42501"}, want: FailureKindPermission},
		{name: "PostgreSQL constraint", err: &pgconn.PgError{Code: "23505"}, want: FailureKindConstraint},
		{name: "transport failure", err: fmt.Errorf("connection reset"), want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := KnownFailureKind(test.err); got != test.want {
				t.Fatalf("KnownFailureKind() = %q, want %q", got, test.want)
			}
		})
	}
}
