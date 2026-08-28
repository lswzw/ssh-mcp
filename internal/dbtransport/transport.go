// Package dbtransport provides one-shot, direct database connections.
package dbtransport

import (
	"context"
	"errors"

	"ssh-mcp/internal/store"
)

var (
	ErrInvalidEndpoint   = errors.New("invalid database endpoint")
	ErrInvalidLimits     = errors.New("invalid database result limits")
	ErrInvalidStatements = errors.New("invalid transaction statements")
)

type Security = store.TransportSecurity

const (
	SecurityTLSVerified   = store.TransportTLSVerified
	SecurityTLSUnverified = store.TransportTLSUnverified
	SecurityPlaintext     = store.TransportPlaintext
)

type Endpoint struct {
	Host            string
	Port            int
	Engine          store.DatabaseEngine
	Database        string
	Username        string
	Password        []byte
	TransportPolicy store.DatabaseTransportPolicy
	TLSCAPath       string
}

// DatabaseVersion 是传输层从已建立连接中观察到的数据库主版本。
// 它仅用于配置和运行状态展示，不参与 SQL 派发裁决。
type DatabaseVersion struct {
	Major int
}

type Limits struct {
	MaxRows  int
	MaxBytes int
}

type QueryResult struct {
	Columns           []string
	Rows              [][]string
	RowsTruncated     bool
	BytesTruncated    bool
	TransportSecurity Security
}

type DatabaseListResult struct {
	Databases         []string
	OutputTruncated   bool
	TransportSecurity Security
}

type ExecutionResult struct {
	AffectedRows      int64
	TransportSecurity Security
}

type Transport interface {
	Test(context.Context, Endpoint) (Security, error)
	ProbeVersion(context.Context, Endpoint) (DatabaseVersion, error)
	ListDatabases(context.Context, Endpoint) (DatabaseListResult, error)
	Query(context.Context, Endpoint, string, Limits) (QueryResult, error)
	ExecuteStatements(context.Context, Endpoint, []string) (ExecutionResult, error)
}
