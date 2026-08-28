package dbtransport

import (
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	FailureKindSyntax     = "syntax"
	FailureKindPermission = "permission"
	FailureKindConstraint = "constraint"
)

// KnownFailureKind 只归类服务器明确返回且不需要暴露原始错误文本的 SQL 失败。
// 其余错误保留为 outcome_unknown，避免把连接或协议故障伪装成确定结果。
func KnownFailureKind(err error) string {
	var mysqlError *mysql.MySQLError
	if errors.As(err, &mysqlError) {
		switch mysqlError.Number {
		case 1064, 1149:
			return FailureKindSyntax
		case 1044, 1045, 1142, 1227:
			return FailureKindPermission
		case 1062, 1451, 1452, 3819, 4025:
			return FailureKindConstraint
		}
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch {
		case postgresError.Code == "42601":
			return FailureKindSyntax
		case postgresError.Code == "42501" || postgresError.Code == "28000" || postgresError.Code == "28P01":
			return FailureKindPermission
		case strings.HasPrefix(postgresError.Code, "23"):
			return FailureKindConstraint
		}
	}
	return ""
}
