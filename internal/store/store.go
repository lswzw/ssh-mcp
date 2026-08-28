package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"ssh-mcp/internal/clock"
	"ssh-mcp/internal/paths"

	_ "modernc.org/sqlite"
)

var (
	ErrConflict                      = errors.New("target already exists")
	ErrInvalidTarget                 = errors.New("invalid target")
	ErrUnsupportedRemotePlatform     = errors.New("SSH remote platform is not supported")
	ErrAlreadyInitialized            = errors.New("credential store is already initialized")
	ErrUninitialized                 = errors.New("credential store is not initialized")
	ErrUnlockFailed                  = errors.New("could not unlock credential store")
	ErrLocked                        = errors.New("credential store is locked")
	ErrInvalidCredential             = errors.New("invalid credential")
	ErrCredentialNotFound            = errors.New("credential not found")
	ErrCredentialOwnerConflict       = errors.New("credential belongs to another target identity")
	ErrCredentialMigrationFailed     = errors.New("could not migrate target credentials")
	ErrWriteCredentialNotConfigured  = errors.New("database write credential is not configured")
	ErrCandidateVerificationRequired = errors.New("candidate target verification is required before enabling")
	ErrTargetNotFound                = errors.New("target not found")
	ErrTargetChanged                 = errors.New("target changed or revoked before connection")
	ErrHostKeyNotFound               = errors.New("SSH host key is not pinned")
	ErrHostKeyMismatch               = errors.New("SSH host key fingerprint changed")
	ErrBackupUnlockFailed            = errors.New("could not unlock encrypted backup")
	ErrInvalidBackup                 = errors.New("invalid encrypted backup")
)

type SSHMode string

const (
	SSHDirect SSHMode = "direct"
)

// SSHRemotePlatform describes the operating-system contract of a managed SSH
// endpoint. The command, path, and service-manager policies are currently
// implemented only for Linux targets.
type SSHRemotePlatform string

const SSHRemotePlatformLinux SSHRemotePlatform = "linux"

type DatabaseEngine string

const (
	EngineMySQL      DatabaseEngine = "mysql"
	EnginePostgreSQL DatabaseEngine = "postgresql"
)

type TransportSecurity string

const (
	TransportTLSVerified   TransportSecurity = "tls_verified"
	TransportTLSUnverified TransportSecurity = "tls_unverified"
	TransportPlaintext     TransportSecurity = "plaintext"
)

// DatabaseTransportPolicy controls how a target may connect. It is separate
// from TransportSecurity, which records the outcome of a connection test.
type DatabaseTransportPolicy string

const (
	DatabaseTLSVerified     DatabaseTransportPolicy = "tls_verified"
	DatabaseLegacyPlaintext DatabaseTransportPolicy = "legacy_plaintext"
)

// SSHIdentityStatus 表示 SSH 主机身份是否仍可用于远端派发。
type SSHIdentityStatus string

const (
	SSHIdentityVerified    SSHIdentityStatus = "identity_verified"
	SSHIdentityUnconfirmed SSHIdentityStatus = "identity_unconfirmed"
)

// DatabaseVersionStatus 记录候选连接时观察到的版本信息是否可用。
// 该状态仅用于显示和排障，不能作为 SQL 派发门禁。
type DatabaseVersionStatus string

const (
	DatabaseVersionVerified   DatabaseVersionStatus = "version_verified"
	DatabaseVersionUnverified DatabaseVersionStatus = "version_unverified"
)

type SSHTarget struct {
	IP                       string
	Mode                     SSHMode
	SSHPort                  int
	LoginUsername            string
	CredentialID             string
	CommandBlacklistPatterns []string
	// AllowFileOperations controls the dedicated SSH file read/deploy APIs.
	// It defaults to true for newly created and migrated targets.
	AllowFileOperations bool
	RemotePlatform      SSHRemotePlatform
	Description         string
	Environment         string
	Enabled             bool
	IdentityStatus      SSHIdentityStatus
	Revision            int64
}

type DatabaseInstance struct {
	Host              string
	Port              int
	Engine            DatabaseEngine
	DefaultDatabase   string
	ReadUsername      string
	WriteUsername     string
	ReadCredentialID  string
	WriteCredentialID string
	Description       string
	Environment       string
	TransportSecurity TransportSecurity
	TransportPolicy   DatabaseTransportPolicy
	TLSCAPath         string
	Enabled           bool
	MajorVersion      int
	VersionStatus     DatabaseVersionStatus
	Revision          int64
}

type Store struct {
	db                          *sql.DB
	credentialMigrationCommit   func(*sql.Tx) error
	sshConfigurationCommit      func(*sql.Tx) error
	databaseConfigurationCommit func(*sql.Tx) error
}

func Open(path string) (*Store, error) {
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}
	if err := paths.EnsureDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", sqliteOpenDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect sqlite database: %w", err)
	}
	if err := paths.EnsureRegularFile(path); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("secure sqlite database: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure sqlite database: %w", err)
	}

	store := &Store{db: db}
	if err := store.applyMigrations(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func sqliteOpenDSN(path string) string {
	return path + "?_pragma=busy_timeout%3d5000&_pragma=foreign_keys%3don"
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) AddSSHTarget(ctx context.Context, target SSHTarget) error {
	ip, err := canonicalIP(target.IP)
	if err != nil || target.Mode != SSHDirect {
		return ErrInvalidTarget
	}
	platform, err := normalizeSSHRemotePlatform(target.RemotePlatform)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ssh_targets (ip, connection_mode, remote_platform, allow_file_operations, enabled, created_at, updated_at)
		VALUES (?, ?, ?, 1, 1, ?, ?)`, ip, target.Mode, platform, nowUnix(), nowUnix())
	if err != nil {
		return mapConstraintError(err)
	}
	return nil
}

func (s *Store) AddDatabaseInstance(ctx context.Context, instance DatabaseInstance) error {
	host, err := canonicalIP(instance.Host)
	if err != nil || instance.Port < 1 || instance.Port > 65535 || !validEngine(instance.Engine) {
		return ErrInvalidTarget
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO database_instances (host, port, engine, enabled, created_at, updated_at)
		VALUES (?, ?, ?, 1, ?, ?)`, host, instance.Port, instance.Engine, nowUnix(), nowUnix())
	if err != nil {
		return mapConstraintError(err)
	}
	return nil
}

func (s *Store) applyMigrations(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at INTEGER NOT NULL
		)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}

	for _, migration := range migrations {
		var applied bool
		if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)", migration.version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %d: %w", migration.version, err)
		}
		if applied {
			continue
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", migration.version, err)
		}
		if err := applyMigration(ctx, tx, migration); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", migration.version, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", migration.version, nowUnix()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", migration.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", migration.version, err)
		}
	}

	return nil
}

func applyMigration(ctx context.Context, tx *sql.Tx, migration migration) error {
	if migration.apply != nil {
		return migration.apply(ctx, tx)
	}
	_, err := tx.ExecContext(ctx, migration.sql)
	return err
}

func canonicalIP(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", err
	}
	return address.String(), nil
}

func validEngine(engine DatabaseEngine) bool {
	return engine == EngineMySQL || engine == EnginePostgreSQL
}

func validTransportSecurity(security TransportSecurity) bool {
	return security == TransportTLSVerified || security == TransportTLSUnverified || security == TransportPlaintext
}

func validDatabaseTransportPolicy(policy DatabaseTransportPolicy) bool {
	return policy == DatabaseTLSVerified || policy == DatabaseLegacyPlaintext
}

func validSSHIdentityStatus(status SSHIdentityStatus) bool {
	return status == SSHIdentityVerified || status == SSHIdentityUnconfirmed
}

func validDatabaseVersionStatus(status DatabaseVersionStatus) bool {
	return status == DatabaseVersionVerified || status == DatabaseVersionUnverified
}

func mapConstraintError(err error) error {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect database path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database path must not be a symbolic link")
	}
	return nil
}

func nowUnix() int64 {
	return clock.Now().Unix()
}
