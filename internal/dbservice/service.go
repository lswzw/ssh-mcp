// Package dbservice resolves stored database targets into direct transport
// endpoints while keeping decrypted credentials within the local process.
package dbservice

import (
	"context"
	"strings"

	"ssh-mcp/internal/dbtransport"
	"ssh-mcp/internal/secret"
	"ssh-mcp/internal/store"
)

type CandidateCredentials struct {
	ReadPassword  []byte
	WritePassword []byte
}

type TestResult struct {
	TransportSecurity dbtransport.Security
	MajorVersion      int
	VersionStatus     store.DatabaseVersionStatus
}

type Service struct {
	store     *store.Store
	transport dbtransport.Transport
}

func New(credentialStore *store.Store, transport dbtransport.Transport) *Service {
	return &Service{store: credentialStore, transport: transport}
}

func (s *Service) TestInstance(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance, candidates CandidateCredentials) (TestResult, error) {
	return s.ValidateInstanceConfiguration(ctx, vault, instance, candidates)
}

// ValidateInstanceConfiguration 在提交本地配置变更前验证候选数据库实例。
// 候选密码存在时不会依赖调用方传入的凭据标识，也不会持久化任何数据。
func (s *Service) ValidateInstanceConfiguration(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance, candidates CandidateCredentials) (TestResult, error) {
	readEndpoint, err := s.configurationEndpoint(ctx, vault, instance, false, candidates.ReadPassword)
	if err != nil {
		return TestResult{}, err
	}
	defer secret.Zero(readEndpoint.Password)
	security, err := s.transport.Test(ctx, readEndpoint)
	if err != nil {
		return TestResult{}, err
	}
	if strings.TrimSpace(instance.WriteUsername) != "" {
		writePassword := candidates.WritePassword
		if usesReadCredentialForWrite(instance) && len(writePassword) == 0 {
			writePassword = candidates.ReadPassword
		}
		writeEndpoint, err := s.configurationEndpoint(ctx, vault, instance, true, writePassword)
		if err != nil {
			return TestResult{}, err
		}
		defer secret.Zero(writeEndpoint.Password)
		if _, err := s.transport.Test(ctx, writeEndpoint); err != nil {
			return TestResult{}, err
		}
	}
	result := TestResult{TransportSecurity: security, VersionStatus: store.DatabaseVersionUnverified}
	version, err := s.transport.ProbeVersion(ctx, readEndpoint)
	if err == nil && version.Major > 0 {
		result.MajorVersion = version.Major
		result.VersionStatus = store.DatabaseVersionVerified
	}
	return result, nil
}

func (s *Service) ListDatabases(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance) (dbtransport.DatabaseListResult, error) {
	instance, err := s.currentInstance(ctx, instance)
	if err != nil {
		return dbtransport.DatabaseListResult{}, err
	}
	endpoint, err := s.endpoint(ctx, vault, instance, false, nil)
	if err != nil {
		return dbtransport.DatabaseListResult{}, err
	}
	defer secret.Zero(endpoint.Password)
	return s.transport.ListDatabases(ctx, endpoint)
}

func (s *Service) Query(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance, database, statement string, limits dbtransport.Limits) (dbtransport.QueryResult, error) {
	instance, err := s.currentInstance(ctx, instance)
	if err != nil {
		return dbtransport.QueryResult{}, err
	}
	endpoint, err := s.endpoint(ctx, vault, instance, false, nil)
	if err != nil {
		return dbtransport.QueryResult{}, err
	}
	defer secret.Zero(endpoint.Password)
	if database = strings.TrimSpace(database); database != "" {
		endpoint.Database = database
	}
	return s.transport.Query(ctx, endpoint, statement, limits)
}

func (s *Service) ExecuteStatements(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance, database string, statements []string) (dbtransport.ExecutionResult, error) {
	instance, err := s.currentInstance(ctx, instance)
	if err != nil {
		return dbtransport.ExecutionResult{}, err
	}
	endpoint, err := s.endpoint(ctx, vault, instance, true, nil)
	if err != nil {
		return dbtransport.ExecutionResult{}, err
	}
	defer secret.Zero(endpoint.Password)
	if database = strings.TrimSpace(database); database != "" {
		endpoint.Database = database
	}
	return s.transport.ExecuteStatements(ctx, endpoint, statements)
}

func (s *Service) currentInstance(ctx context.Context, instance store.DatabaseInstance) (store.DatabaseInstance, error) {
	current, err := s.store.DatabaseInstance(ctx, instance.Host, instance.Port)
	if err != nil {
		return store.DatabaseInstance{}, err
	}
	if current.Revision != instance.Revision {
		return store.DatabaseInstance{}, store.ErrTargetChanged
	}
	return current, nil
}

func (s *Service) endpoint(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance, write bool, candidatePassword []byte) (dbtransport.Endpoint, error) {
	if !instance.Enabled {
		return dbtransport.Endpoint{}, store.ErrTargetNotFound
	}
	username, credentialID := instance.ReadUsername, instance.ReadCredentialID
	if write {
		if strings.TrimSpace(instance.WriteUsername) == "" {
			return dbtransport.Endpoint{}, store.ErrWriteCredentialNotConfigured
		}
		username, credentialID = instance.WriteUsername, instance.WriteCredentialID
		if usesReadCredentialForWrite(instance) {
			credentialID = instance.ReadCredentialID
		}
		if strings.TrimSpace(credentialID) == "" {
			return dbtransport.Endpoint{}, store.ErrWriteCredentialNotConfigured
		}
	}
	return s.endpointWithCredentials(ctx, vault, instance, username, credentialID, candidatePassword)
}

func (s *Service) configurationEndpoint(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance, write bool, candidatePassword []byte) (dbtransport.Endpoint, error) {
	instance.Enabled = true
	username, credentialID := instance.ReadUsername, instance.ReadCredentialID
	if write {
		username, credentialID = instance.WriteUsername, instance.WriteCredentialID
		if usesReadCredentialForWrite(instance) {
			credentialID = instance.ReadCredentialID
		}
	}
	return s.endpointWithCredentials(ctx, vault, instance, username, credentialID, candidatePassword)
}

func usesReadCredentialForWrite(instance store.DatabaseInstance) bool {
	return strings.TrimSpace(instance.WriteUsername) != "" &&
		instance.WriteUsername == instance.ReadUsername && strings.TrimSpace(instance.WriteCredentialID) == ""
}

func (s *Service) endpointWithCredentials(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance, username, credentialID string, candidatePassword []byte) (dbtransport.Endpoint, error) {
	if strings.TrimSpace(username) == "" {
		return dbtransport.Endpoint{}, store.ErrInvalidTarget
	}
	password := append([]byte(nil), candidatePassword...)
	if len(password) == 0 {
		if strings.TrimSpace(credentialID) == "" {
			return dbtransport.Endpoint{}, store.ErrInvalidTarget
		}
		var err error
		password, err = vault.Credential(ctx, credentialID)
		if err != nil {
			return dbtransport.Endpoint{}, err
		}
	}
	return dbtransport.Endpoint{
		Host: instance.Host, Port: instance.Port, Engine: instance.Engine, Database: instance.DefaultDatabase,
		Username: username, Password: password, TransportPolicy: instance.TransportPolicy, TLSCAPath: instance.TLSCAPath,
	}, nil
}
