package dbtransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"ssh-mcp/internal/store"
)

const (
	defaultMaxRows         = 1000
	defaultMaxBytes        = 16 << 10
	postgresSSLRequestCode = 80877103
)

type NativeTransport struct{}

func (NativeTransport) Test(ctx context.Context, endpoint Endpoint) (Security, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return "", err
	}
	switch endpoint.Engine {
	case store.EngineMySQL:
		return testMySQL(ctx, endpoint)
	case store.EnginePostgreSQL:
		return testPostgres(ctx, endpoint)
	default:
		return "", ErrInvalidEndpoint
	}
}

func (NativeTransport) ProbeVersion(ctx context.Context, endpoint Endpoint) (DatabaseVersion, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return DatabaseVersion{}, err
	}
	switch endpoint.Engine {
	case store.EngineMySQL:
		return probeMySQLVersion(ctx, endpoint)
	case store.EnginePostgreSQL:
		return probePostgresVersion(ctx, endpoint)
	default:
		return DatabaseVersion{}, ErrInvalidEndpoint
	}
}

func (NativeTransport) ListDatabases(ctx context.Context, endpoint Endpoint) (DatabaseListResult, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return DatabaseListResult{}, err
	}
	switch endpoint.Engine {
	case store.EngineMySQL:
		return listMySQLDatabases(ctx, endpoint)
	case store.EnginePostgreSQL:
		return listPostgresDatabases(ctx, endpoint)
	default:
		return DatabaseListResult{}, ErrInvalidEndpoint
	}
}

func (NativeTransport) Query(ctx context.Context, endpoint Endpoint, statement string, limits Limits) (QueryResult, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return QueryResult{}, err
	}
	if strings.TrimSpace(statement) == "" {
		return QueryResult{}, ErrInvalidStatements
	}
	if _, err := newResultCollector(limits); err != nil {
		return QueryResult{}, err
	}
	switch endpoint.Engine {
	case store.EngineMySQL:
		return queryMySQL(ctx, endpoint, statement, limits)
	case store.EnginePostgreSQL:
		return queryPostgres(ctx, endpoint, statement, limits)
	default:
		return QueryResult{}, ErrInvalidEndpoint
	}
}

// ExecuteStatements runs the parser-approved statements one at a time on one
// connection. It deliberately does not create an implicit transaction, so an
// operator-controlled BEGIN/COMMIT and each engine's DDL semantics remain
// visible and are not silently changed by this service.
func (NativeTransport) ExecuteStatements(ctx context.Context, endpoint Endpoint, statements []string) (ExecutionResult, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return ExecutionResult{}, err
	}
	if err := validateStatements(statements); err != nil {
		return ExecutionResult{}, err
	}
	switch endpoint.Engine {
	case store.EngineMySQL:
		return executeMySQLStatements(ctx, endpoint, statements)
	case store.EnginePostgreSQL:
		return executePostgresStatements(ctx, endpoint, statements)
	default:
		return ExecutionResult{}, ErrInvalidEndpoint
	}
}

func testMySQL(ctx context.Context, endpoint Endpoint) (Security, error) {
	database, connection, err := openMySQL(ctx, endpoint)
	if err != nil {
		return "", err
	}
	defer database.Close()
	defer connection.Close()
	var value int
	if err := connection.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil {
		return "", fmt.Errorf("run MySQL connection test: %w", err)
	}
	return mysqlSecurity(ctx, connection, endpoint)
}

func probeMySQLVersion(ctx context.Context, endpoint Endpoint) (DatabaseVersion, error) {
	database, connection, err := openMySQL(ctx, endpoint)
	if err != nil {
		return DatabaseVersion{}, err
	}
	defer database.Close()
	defer connection.Close()
	return mysqlVersion(ctx, connection)
}

func mysqlVersion(ctx context.Context, connection *sql.Conn) (DatabaseVersion, error) {
	var value string
	if err := connection.QueryRowContext(ctx, "SELECT VERSION()").Scan(&value); err != nil {
		return DatabaseVersion{}, fmt.Errorf("read MySQL version: %w", err)
	}
	major, err := parseMajorVersion(value)
	if err != nil {
		return DatabaseVersion{}, fmt.Errorf("parse MySQL version: %w", err)
	}
	return DatabaseVersion{Major: major}, nil
}

func listMySQLDatabases(ctx context.Context, endpoint Endpoint) (DatabaseListResult, error) {
	database, connection, err := openMySQL(ctx, endpoint)
	if err != nil {
		return DatabaseListResult{}, err
	}
	defer database.Close()
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, "SHOW DATABASES")
	if err != nil {
		return DatabaseListResult{}, fmt.Errorf("list MySQL databases: %w", err)
	}
	result, err := collectSQLRows(rows, Limits{MaxRows: defaultMaxRows, MaxBytes: defaultMaxBytes})
	if err != nil {
		return DatabaseListResult{}, err
	}
	security, err := mysqlSecurity(ctx, connection, endpoint)
	if err != nil {
		return DatabaseListResult{}, err
	}
	return DatabaseListResult{Databases: firstColumn(result.Rows), OutputTruncated: result.RowsTruncated || result.BytesTruncated, TransportSecurity: security}, nil
}

func queryMySQL(ctx context.Context, endpoint Endpoint, statement string, limits Limits) (QueryResult, error) {
	database, connection, err := openMySQL(ctx, endpoint)
	if err != nil {
		return QueryResult{}, err
	}
	defer database.Close()
	defer connection.Close()
	transaction, err := connection.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return QueryResult{}, fmt.Errorf("begin MySQL read-only transaction: %w", err)
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, statement)
	if err != nil {
		return QueryResult{}, fmt.Errorf("query MySQL: %w", err)
	}
	result, err := collectSQLRows(rows, limits)
	if err != nil {
		return QueryResult{}, err
	}
	if err := transaction.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return QueryResult{}, fmt.Errorf("rollback MySQL read-only transaction: %w", err)
	}
	result.TransportSecurity, err = mysqlSecurity(ctx, connection, endpoint)
	if err != nil {
		return QueryResult{}, err
	}
	return result, nil
}

func executeMySQLStatements(ctx context.Context, endpoint Endpoint, statements []string) (ExecutionResult, error) {
	database, connection, err := openMySQL(ctx, endpoint)
	if err != nil {
		return ExecutionResult{}, err
	}
	defer database.Close()
	defer connection.Close()
	var affected int64
	for _, statement := range statements {
		result, err := connection.ExecContext(ctx, statement)
		if err != nil {
			return ExecutionResult{}, fmt.Errorf("execute MySQL statement: %w", err)
		}
		if rows, err := result.RowsAffected(); err == nil {
			affected += rows
		}
	}
	security, err := mysqlSecurity(ctx, connection, endpoint)
	if err != nil {
		return ExecutionResult{}, err
	}
	return ExecutionResult{AffectedRows: affected, TransportSecurity: security}, nil
}

func openMySQL(ctx context.Context, endpoint Endpoint) (*sql.DB, *sql.Conn, error) {
	return openMySQLAttempt(ctx, endpoint)
}

func openMySQLAttempt(ctx context.Context, endpoint Endpoint) (*sql.DB, *sql.Conn, error) {
	config := mysql.NewConfig()
	config.User = endpoint.Username
	config.Passwd = string(endpoint.Password)
	config.Net = "tcp"
	config.Addr = net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port))
	config.DBName = endpoint.Database
	config.MultiStatements = false
	if effectiveTransportPolicy(endpoint) == store.DatabaseTLSVerified {
		tlsConfig, err := verifiedTLSConfig(endpoint)
		if err != nil {
			return nil, nil, err
		}
		config.TLS = tlsConfig
	}
	connector, err := mysql.NewConnector(config)
	if err != nil {
		return nil, nil, fmt.Errorf("create MySQL connector: %w", err)
	}
	database := sql.OpenDB(connector)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(0)
	connection, err := database.Conn(ctx)
	if err != nil {
		_ = database.Close()
		return nil, nil, fmt.Errorf("connect MySQL: %w", err)
	}
	return database, connection, nil
}

func mysqlSecurity(ctx context.Context, connection *sql.Conn, endpoint Endpoint) (Security, error) {
	if effectiveTransportPolicy(endpoint) == store.DatabaseLegacyPlaintext {
		return SecurityPlaintext, nil
	}
	var name string
	var cipher sql.NullString
	if err := connection.QueryRowContext(ctx, "SHOW STATUS LIKE 'Ssl_cipher'").Scan(&name, &cipher); err != nil {
		return "", fmt.Errorf("read MySQL TLS status: %w", err)
	}
	if cipher.Valid && strings.TrimSpace(cipher.String) != "" {
		return SecurityTLSVerified, nil
	}
	return "", errors.New("MySQL server did not negotiate required TLS")
}

func testPostgres(ctx context.Context, endpoint Endpoint) (Security, error) {
	connection, security, err := openPostgres(ctx, endpoint)
	if err != nil {
		return "", err
	}
	defer connection.Close(context.Background())
	if _, err := connection.Exec(ctx, "SELECT 1"); err != nil {
		return "", fmt.Errorf("run PostgreSQL connection test: %w", err)
	}
	return security, nil
}

func probePostgresVersion(ctx context.Context, endpoint Endpoint) (DatabaseVersion, error) {
	connection, _, err := openPostgres(ctx, endpoint)
	if err != nil {
		return DatabaseVersion{}, err
	}
	defer connection.Close(context.Background())
	return postgresVersion(ctx, connection)
}

func postgresVersion(ctx context.Context, connection *pgx.Conn) (DatabaseVersion, error) {
	var value string
	if err := connection.QueryRow(ctx, "SHOW server_version_num").Scan(&value); err != nil {
		return DatabaseVersion{}, fmt.Errorf("read PostgreSQL version: %w", err)
	}
	numeric, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || numeric < 10000 {
		return DatabaseVersion{}, errors.New("invalid PostgreSQL server version number")
	}
	return DatabaseVersion{Major: numeric / 10000}, nil
}

func parseMajorVersion(value string) (int, error) {
	value = strings.TrimSpace(value)
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, errors.New("missing major version")
	}
	major, err := strconv.Atoi(value[:end])
	if err != nil || major < 1 {
		return 0, errors.New("invalid major version")
	}
	return major, nil
}

func listPostgresDatabases(ctx context.Context, endpoint Endpoint) (DatabaseListResult, error) {
	connection, security, err := openPostgres(ctx, endpoint)
	if err != nil {
		return DatabaseListResult{}, err
	}
	defer connection.Close(context.Background())
	rows, err := connection.Query(ctx, "SELECT datname FROM pg_database WHERE has_database_privilege(datname, 'CONNECT') ORDER BY datname")
	if err != nil {
		return DatabaseListResult{}, fmt.Errorf("list PostgreSQL databases: %w", err)
	}
	result, err := collectPGXRows(rows, Limits{MaxRows: defaultMaxRows, MaxBytes: defaultMaxBytes})
	if err != nil {
		return DatabaseListResult{}, err
	}
	return DatabaseListResult{Databases: firstColumn(result.Rows), OutputTruncated: result.RowsTruncated || result.BytesTruncated, TransportSecurity: security}, nil
}

func queryPostgres(ctx context.Context, endpoint Endpoint, statement string, limits Limits) (QueryResult, error) {
	connection, security, err := openPostgres(ctx, endpoint)
	if err != nil {
		return QueryResult{}, err
	}
	defer connection.Close(context.Background())
	transaction, err := connection.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return QueryResult{}, fmt.Errorf("begin PostgreSQL read-only transaction: %w", err)
	}
	defer transaction.Rollback(context.Background())
	rows, err := transaction.Query(ctx, statement)
	if err != nil {
		return QueryResult{}, fmt.Errorf("query PostgreSQL: %w", err)
	}
	result, err := collectPGXRows(rows, limits)
	if err != nil {
		return QueryResult{}, err
	}
	result.TransportSecurity = security
	return result, nil
}

func executePostgresStatements(ctx context.Context, endpoint Endpoint, statements []string) (ExecutionResult, error) {
	connection, security, err := openPostgres(ctx, endpoint)
	if err != nil {
		return ExecutionResult{}, err
	}
	defer connection.Close(context.Background())
	var affected int64
	for _, statement := range statements {
		tag, err := connection.Exec(ctx, statement)
		if err != nil {
			return ExecutionResult{}, fmt.Errorf("execute PostgreSQL statement: %w", err)
		}
		affected += tag.RowsAffected()
	}
	return ExecutionResult{AffectedRows: affected, TransportSecurity: security}, nil
}

func openPostgres(ctx context.Context, endpoint Endpoint) (*pgx.Conn, Security, error) {
	config, err := pgx.ParseConfig("sslmode=disable")
	if err != nil {
		return nil, "", fmt.Errorf("create PostgreSQL configuration: %w", err)
	}
	config.Host = endpoint.Host
	config.Port = uint16(endpoint.Port)
	config.Database = endpoint.Database
	config.User = endpoint.Username
	config.Password = string(endpoint.Password)
	config.Fallbacks = nil
	if effectiveTransportPolicy(endpoint) == store.DatabaseTLSVerified {
		tlsConfig, err := verifiedTLSConfig(endpoint)
		if err != nil {
			return nil, "", err
		}
		config.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return negotiatePostgresTLS(ctx, net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port)), tlsConfig)
		}
	}
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, "", fmt.Errorf("connect PostgreSQL: %w", err)
	}
	if effectiveTransportPolicy(endpoint) == store.DatabaseTLSVerified {
		return connection, SecurityTLSVerified, nil
	}
	return connection, SecurityPlaintext, nil
}

func negotiatePostgresTLS(ctx context.Context, address string, config *tls.Config) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial PostgreSQL: %w", err)
	}
	var request [8]byte
	binary.BigEndian.PutUint32(request[:4], 8)
	binary.BigEndian.PutUint32(request[4:], postgresSSLRequestCode)
	if _, err := connection.Write(request[:]); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("request PostgreSQL TLS: %w", err)
	}
	var response [1]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("read PostgreSQL TLS response: %w", err)
	}
	switch response[0] {
	case 'N':
		_ = connection.Close()
		return nil, errors.New("PostgreSQL server refused required TLS")
	case 'S':
		tlsConnection := tls.Client(connection, config)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("negotiate PostgreSQL TLS: %w", err)
		}
		return tlsConnection, nil
	default:
		_ = connection.Close()
		return nil, fmt.Errorf("invalid PostgreSQL TLS response")
	}
}

func verifiedTLSConfig(endpoint Endpoint) (*tls.Config, error) {
	certificate, err := os.ReadFile(endpoint.TLSCAPath)
	if err != nil {
		return nil, fmt.Errorf("read database CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("parse database CA certificate")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: endpoint.Host,
	}, nil
}

func effectiveTransportPolicy(endpoint Endpoint) store.DatabaseTransportPolicy {
	if endpoint.TransportPolicy == "" {
		return store.DatabaseLegacyPlaintext
	}
	return endpoint.TransportPolicy
}

func validateEndpoint(endpoint Endpoint) error {
	if _, err := netip.ParseAddr(endpoint.Host); err != nil || endpoint.Port < 1 || endpoint.Port > 65535 ||
		(endpoint.Engine != store.EngineMySQL && endpoint.Engine != store.EnginePostgreSQL) ||
		strings.TrimSpace(endpoint.Username) == "" || len(endpoint.Password) == 0 ||
		(endpoint.Engine == store.EnginePostgreSQL && strings.TrimSpace(endpoint.Database) == "") {
		return ErrInvalidEndpoint
	}
	policy := effectiveTransportPolicy(endpoint)
	if policy != store.DatabaseLegacyPlaintext && policy != store.DatabaseTLSVerified {
		return ErrInvalidEndpoint
	}
	if policy == store.DatabaseTLSVerified && strings.TrimSpace(endpoint.TLSCAPath) == "" {
		return ErrInvalidEndpoint
	}
	return nil
}

func validateStatements(statements []string) error {
	if len(statements) == 0 {
		return ErrInvalidStatements
	}
	for _, statement := range statements {
		if strings.TrimSpace(statement) == "" {
			return ErrInvalidStatements
		}
	}
	return nil
}

type resultCollector struct {
	limits         Limits
	rows           [][]string
	bytes          int
	rowsTruncated  bool
	bytesTruncated bool
}

func newResultCollector(limits Limits) (*resultCollector, error) {
	if limits.MaxRows < 0 || limits.MaxBytes < 0 {
		return nil, ErrInvalidLimits
	}
	if limits.MaxRows == 0 {
		limits.MaxRows = defaultMaxRows
	}
	if limits.MaxBytes == 0 {
		limits.MaxBytes = defaultMaxBytes
	}
	return &resultCollector{limits: limits}, nil
}

// addRow reports whether collection must stop after this row.
func (c *resultCollector) addRow(row []string) bool {
	if len(c.rows) >= c.limits.MaxRows {
		c.rowsTruncated = true
		return true
	}
	remaining := c.limits.MaxBytes - c.bytes
	for _, value := range row {
		if len(value) > remaining {
			c.bytesTruncated = true
			return true
		}
		remaining -= len(value)
	}
	copied := append([]string(nil), row...)
	c.rows = append(c.rows, copied)
	c.bytes = c.limits.MaxBytes - remaining
	return false
}

func (c *resultCollector) result(columns []string) QueryResult {
	return QueryResult{
		Columns:        append([]string(nil), columns...),
		Rows:           c.rows,
		RowsTruncated:  c.rowsTruncated,
		BytesTruncated: c.bytesTruncated,
	}
}

func collectSQLRows(rows *sql.Rows, limits Limits) (QueryResult, error) {
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return QueryResult{}, fmt.Errorf("read database columns: %w", err)
	}
	collector, err := newResultCollector(limits)
	if err != nil {
		return QueryResult{}, err
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for index := range values {
		pointers[index] = &values[index]
	}
	for rows.Next() {
		if err := rows.Scan(pointers...); err != nil {
			return QueryResult{}, fmt.Errorf("scan database row: %w", err)
		}
		if collector.addRow(stringValues(values)) {
			return collector.result(columns), nil
		}
	}
	if err := rows.Err(); err != nil {
		return QueryResult{}, fmt.Errorf("read database rows: %w", err)
	}
	return collector.result(columns), nil
}

func collectPGXRows(rows pgx.Rows, limits Limits) (QueryResult, error) {
	defer rows.Close()
	fields := rows.FieldDescriptions()
	columns := make([]string, len(fields))
	for index, field := range fields {
		columns[index] = field.Name
	}
	collector, err := newResultCollector(limits)
	if err != nil {
		return QueryResult{}, err
	}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return QueryResult{}, fmt.Errorf("read PostgreSQL row: %w", err)
		}
		if collector.addRow(stringValues(values)) {
			return collector.result(columns), nil
		}
	}
	if err := rows.Err(); err != nil {
		return QueryResult{}, fmt.Errorf("read PostgreSQL rows: %w", err)
	}
	return collector.result(columns), nil
}

func stringValues(values []any) []string {
	result := make([]string, len(values))
	for index, value := range values {
		switch value := value.(type) {
		case nil:
			result[index] = "NULL"
		case []byte:
			result[index] = string(value)
		default:
			result[index] = fmt.Sprint(value)
		}
	}
	return result
}

func firstColumn(rows [][]string) []string {
	result := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) > 0 {
			result = append(result, row[0])
		}
	}
	return result
}

var _ Transport = NativeTransport{}
