package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ssh-mcp/internal/secret"
)

func TestVaultCommitsValidatedDatabaseInstanceConfiguration(t *testing.T) {
	ctx := context.Background()
	credentialStore, vault := openDatabaseConfigurationTestVault(t)
	current := saveDatabaseConfigurationTestInstance(t, credentialStore, vault, DatabaseInstance{
		Host: "192.0.2.90", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", WriteUsername: "app_write", TransportSecurity: TransportTLSUnverified, Enabled: true,
	}, []byte("previous-read-password"), []byte("previous-write-password"))
	other := saveDatabaseConfigurationTestInstance(t, credentialStore, vault, DatabaseInstance{
		Host: "192.0.2.91", Port: 3306, Engine: EngineMySQL, DefaultDatabase: "app",
		ReadUsername: "other_read", WriteUsername: "other_write", TransportSecurity: TransportPlaintext, Enabled: true,
	}, []byte("other-read-password"), []byte("other-write-password"))
	otherReadCiphertext := databaseConfigurationCredentialCiphertext(t, credentialStore, other.ReadCredentialID)
	otherWriteCiphertext := databaseConfigurationCredentialCiphertext(t, credentialStore, other.WriteCredentialID)
	sshTarget := saveDatabaseConfigurationTestSSHTarget(t, credentialStore, vault)
	sshCiphertext := databaseConfigurationCredentialCiphertext(t, credentialStore, sshTarget.CredentialID)

	updated, err := vault.CommitValidatedDatabaseInstanceConfiguration(ctx, ValidatedDatabaseInstanceConfiguration{
		Instance: DatabaseInstance{
			Host: "192.0.2.90", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app_next",
			ReadUsername: "next_read", WriteUsername: "next_write",
			ReadCredentialID: "caller-read-id", WriteCredentialID: "caller-write-id",
			Description: "更新后的数据库登记目标", Environment: "production",
			TransportSecurity: TransportTLSVerified, TransportPolicy: DatabaseTLSVerified,
			TLSCAPath: filepath.Join(t.TempDir(), "database-ca.pem"), Enabled: false,
		},
		ReadPassword:  []byte("replacement-read-password"),
		WritePassword: []byte("replacement-write-password"),
	})
	if err != nil {
		t.Fatalf("提交已验证的数据库登记目标配置失败：%v", err)
	}
	if updated.ReadCredentialID == current.ReadCredentialID || updated.WriteCredentialID == current.WriteCredentialID {
		t.Fatalf("轮换后的凭据标识未替换旧记录：更新后 (%q, %q)，更新前 (%q, %q)", updated.ReadCredentialID, updated.WriteCredentialID, current.ReadCredentialID, current.WriteCredentialID)
	}
	if updated.ReadCredentialID == "caller-read-id" || updated.WriteCredentialID == "caller-write-id" {
		t.Fatalf("提交接受了调用方指定的数据库凭据标识：%#v", updated)
	}
	saved, err := credentialStore.DatabaseInstance(ctx, current.Host, current.Port)
	if err != nil {
		t.Fatalf("读取已提交的数据库登记目标失败：%v", err)
	}
	if saved != updated || saved.DefaultDatabase != "app_next" || saved.Description != "更新后的数据库登记目标" || saved.Enabled {
		t.Fatalf("已提交的数据库登记目标 = %#v，返回值 = %#v", saved, updated)
	}
	assertDatabaseConfigurationCredential(t, vault, saved.ReadCredentialID, "replacement-read-password")
	assertDatabaseConfigurationCredential(t, vault, saved.WriteCredentialID, "replacement-write-password")
	for _, credentialID := range []string{current.ReadCredentialID, current.WriteCredentialID} {
		if _, err := vault.Credential(ctx, credentialID); !errors.Is(err, ErrCredentialNotFound) {
			t.Fatalf("轮换后读取旧凭据 %q 错误 = %v，期望 ErrCredentialNotFound", credentialID, err)
		}
	}
	otherSaved, err := credentialStore.DatabaseInstance(ctx, other.Host, other.Port)
	if err != nil || otherSaved != other {
		t.Fatalf("其他数据库登记目标被改变：%#v，错误 = %v", otherSaved, err)
	}
	if after := databaseConfigurationCredentialCiphertext(t, credentialStore, other.ReadCredentialID); !bytes.Equal(after, otherReadCiphertext) {
		t.Fatal("更新一个数据库登记目标改变了其他目标的只读凭据")
	}
	if after := databaseConfigurationCredentialCiphertext(t, credentialStore, other.WriteCredentialID); !bytes.Equal(after, otherWriteCiphertext) {
		t.Fatal("更新一个数据库登记目标改变了其他目标的可写凭据")
	}
	sshSaved, err := credentialStore.SSHTarget(ctx, sshTarget.IP)
	if err != nil || !reflect.DeepEqual(sshSaved, sshTarget) {
		t.Fatalf("SSH 登记目标被改变：%#v，错误 = %v", sshSaved, err)
	}
	if after := databaseConfigurationCredentialCiphertext(t, credentialStore, sshTarget.CredentialID); !bytes.Equal(after, sshCiphertext) {
		t.Fatal("更新数据库登记目标改变了 SSH 凭据")
	}
}

func TestVaultRetainsDatabaseCredentialsWithoutReplacementPasswords(t *testing.T) {
	ctx := context.Background()
	credentialStore, vault := openDatabaseConfigurationTestVault(t)
	current := saveDatabaseConfigurationTestInstance(t, credentialStore, vault, DatabaseInstance{
		Host: "192.0.2.95", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", WriteUsername: "app_write", TransportSecurity: TransportTLSUnverified, Enabled: true,
	}, []byte("previous-read-password"), []byte("previous-write-password"))
	before := databaseConfigurationStateSnapshot(t, credentialStore)

	updated, err := vault.CommitValidatedDatabaseInstanceConfiguration(ctx, ValidatedDatabaseInstanceConfiguration{
		Instance: DatabaseInstance{
			Host: current.Host, Port: current.Port, Engine: current.Engine, DefaultDatabase: current.DefaultDatabase,
			ReadUsername: current.ReadUsername, WriteUsername: current.WriteUsername,
			ReadCredentialID: "调用方伪造的只读凭据标识", WriteCredentialID: "调用方伪造的可写凭据标识",
			Description: "只更新登记元数据", TransportSecurity: current.TransportSecurity,
			TransportPolicy: current.TransportPolicy, TLSCAPath: current.TLSCAPath, Enabled: current.Enabled,
		},
	})
	if err != nil {
		t.Fatalf("保留数据库专属凭据的配置提交失败：%v", err)
	}
	if updated.ReadCredentialID != current.ReadCredentialID || updated.WriteCredentialID != current.WriteCredentialID {
		t.Fatalf("保留凭据后的凭据标识 = (%q, %q)，期望 (%q, %q)", updated.ReadCredentialID, updated.WriteCredentialID, current.ReadCredentialID, current.WriteCredentialID)
	}
	after := databaseConfigurationStateSnapshot(t, credentialStore)
	if !bytes.Equal(after.Credentials[current.ReadCredentialID], before.Credentials[current.ReadCredentialID]) ||
		!bytes.Equal(after.Credentials[current.WriteCredentialID], before.Credentials[current.WriteCredentialID]) {
		t.Fatal("未替换密码的数据库配置提交改变了凭据密文")
	}
	if !reflect.DeepEqual(after.Owners, before.Owners) {
		t.Fatalf("未替换密码的数据库配置提交改变了凭据归属：提交前 %#v，提交后 %#v", before.Owners, after.Owners)
	}
	assertDatabaseConfigurationCredential(t, vault, current.ReadCredentialID, "previous-read-password")
	assertDatabaseConfigurationCredential(t, vault, current.WriteCredentialID, "previous-write-password")
}

func TestVaultRemovesUnreferencedWriteCredentialWhenWriteIdentityIsRemoved(t *testing.T) {
	ctx := context.Background()
	credentialStore, vault := openDatabaseConfigurationTestVault(t)
	current := saveDatabaseConfigurationTestInstance(t, credentialStore, vault, DatabaseInstance{
		Host: "192.0.2.96", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", WriteUsername: "app_write", TransportSecurity: TransportTLSUnverified, Enabled: true,
	}, []byte("read-password"), []byte("write-password"))

	updated, err := vault.CommitValidatedDatabaseInstanceConfiguration(ctx, ValidatedDatabaseInstanceConfiguration{
		Instance: DatabaseInstance{
			Host: current.Host, Port: current.Port, Engine: current.Engine, DefaultDatabase: current.DefaultDatabase,
			ReadUsername: current.ReadUsername, TransportSecurity: current.TransportSecurity,
			TransportPolicy: current.TransportPolicy, TLSCAPath: current.TLSCAPath, Enabled: current.Enabled,
		},
	})
	if err != nil {
		t.Fatalf("移除数据库可写身份失败：%v", err)
	}
	if updated.WriteUsername != "" || updated.WriteCredentialID != "" {
		t.Fatalf("移除后的数据库可写身份 = %#v", updated)
	}
	if _, err := vault.Credential(ctx, current.WriteCredentialID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("移除可写身份后读取旧可写凭据错误 = %v，期望 ErrCredentialNotFound", err)
	}
	assertDatabaseConfigurationCredential(t, vault, updated.ReadCredentialID, "read-password")
}

func TestVaultCommitValidatedDatabaseInstanceConfigurationRollsBackOnFailure(t *testing.T) {
	testCases := []struct {
		name   string
		inject func(*testing.T, *Store)
	}{
		{
			name: "只读凭据写入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_database_configuration_read_credential
					BEFORE INSERT ON credentials
					WHEN NEW.purpose = 'database-read-password'
					BEGIN
					SELECT RAISE(ABORT, '注入的数据库只读凭据写入失败');
					END;`); err != nil {
					t.Fatalf("注入数据库只读凭据写入失败失败：%v", err)
				}
			},
		},
		{
			name: "可写凭据写入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_database_configuration_write_credential
					BEFORE INSERT ON credentials
					WHEN NEW.purpose = 'database-write-password'
					BEGIN
					SELECT RAISE(ABORT, '注入的数据库可写凭据写入失败');
					END;`); err != nil {
					t.Fatalf("注入数据库可写凭据写入失败失败：%v", err)
				}
			},
		},
		{
			name: "登记目标写入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_database_configuration_target
					BEFORE UPDATE ON database_instances
					BEGIN
					SELECT RAISE(ABORT, '注入的数据库登记目标写入失败');
					END;`); err != nil {
					t.Fatalf("注入数据库登记目标写入失败失败：%v", err)
				}
			},
		},
		{
			name: "提交失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				credentialStore.databaseConfigurationCommit = func(*sql.Tx) error {
					return errors.New("注入的数据库配置提交失败")
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			credentialStore, vault := openDatabaseConfigurationTestVault(t)
			current := saveDatabaseConfigurationTestInstance(t, credentialStore, vault, DatabaseInstance{
				Host: "192.0.2.93", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
				ReadUsername: "app_read", WriteUsername: "app_write", TransportSecurity: TransportTLSUnverified, Enabled: true,
			}, []byte("previous-read-password"), []byte("previous-write-password"))
			saveDatabaseConfigurationTestInstance(t, credentialStore, vault, DatabaseInstance{
				Host: "192.0.2.94", Port: 3306, Engine: EngineMySQL, DefaultDatabase: "app",
				ReadUsername: "other_read", WriteUsername: "other_write", TransportSecurity: TransportPlaintext, Enabled: true,
			}, []byte("other-read-password"), []byte("other-write-password"))
			saveDatabaseConfigurationTestSSHTarget(t, credentialStore, vault)
			testCase.inject(t, credentialStore)
			before := databaseConfigurationStateSnapshot(t, credentialStore)

			_, err := vault.CommitValidatedDatabaseInstanceConfiguration(ctx, ValidatedDatabaseInstanceConfiguration{
				Instance: DatabaseInstance{
					Host: current.Host, Port: current.Port, Engine: EnginePostgreSQL, DefaultDatabase: "app_next",
					ReadUsername: "next_read", WriteUsername: "next_write", TransportSecurity: TransportTLSVerified,
					TransportPolicy: DatabaseTLSVerified, TLSCAPath: filepath.Join(t.TempDir(), "database-ca.pem"), Enabled: false,
				},
				ReadPassword:  []byte("replacement-read-password"),
				WritePassword: []byte("replacement-write-password"),
			})
			if err == nil {
				t.Fatal("故障注入后数据库登记目标配置提交意外成功")
			}
			if strings.Contains(err.Error(), "replacement-read-password") || strings.Contains(err.Error(), "replacement-write-password") {
				t.Fatal("数据库登记目标配置提交错误泄露了明文凭据")
			}
			after := databaseConfigurationStateSnapshot(t, credentialStore)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("失败的数据库登记目标配置提交改变了状态：提交前 %#v，提交后 %#v", before, after)
			}
		})
	}
}

func TestVaultCommitValidatedNewDatabaseInstanceConfigurationRollsBackOnFailure(t *testing.T) {
	testCases := []struct {
		name   string
		inject func(*testing.T, *Store)
	}{
		{
			name: "只读凭据插入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_new_database_configuration_read_credential
					BEFORE INSERT ON credentials
					WHEN NEW.purpose = 'database-read-password'
					BEGIN
					SELECT RAISE(ABORT, '注入的新数据库只读凭据插入失败');
					END;`); err != nil {
					t.Fatalf("注入新数据库只读凭据插入失败失败：%v", err)
				}
			},
		},
		{
			name: "可写凭据插入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_new_database_configuration_write_credential
					BEFORE INSERT ON credentials
					WHEN NEW.purpose = 'database-write-password'
					BEGIN
					SELECT RAISE(ABORT, '注入的新数据库可写凭据插入失败');
					END;`); err != nil {
					t.Fatalf("注入新数据库可写凭据插入失败失败：%v", err)
				}
			},
		},
		{
			name: "登记目标插入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_new_database_configuration_target
					BEFORE INSERT ON database_instances
					BEGIN
					SELECT RAISE(ABORT, '注入的新数据库登记目标插入失败');
					END;`); err != nil {
					t.Fatalf("注入新数据库登记目标插入失败失败：%v", err)
				}
			},
		},
		{
			name: "提交失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				credentialStore.databaseConfigurationCommit = func(*sql.Tx) error {
					return errors.New("注入的新数据库配置提交失败")
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			credentialStore, vault := openDatabaseConfigurationTestVault(t)
			saveDatabaseConfigurationTestInstance(t, credentialStore, vault, DatabaseInstance{
				Host: "192.0.2.97", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
				ReadUsername: "other_read", WriteUsername: "other_write", TransportSecurity: TransportTLSUnverified, Enabled: true,
			}, []byte("other-read-password"), []byte("other-write-password"))
			testCase.inject(t, credentialStore)
			before := databaseConfigurationStateSnapshot(t, credentialStore)

			_, err := vault.CommitValidatedDatabaseInstanceConfiguration(ctx, ValidatedDatabaseInstanceConfiguration{
				Instance: DatabaseInstance{
					Host: "192.0.2.98", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
					ReadUsername: "app_read", WriteUsername: "app_write", TransportSecurity: TransportTLSVerified,
					TransportPolicy: DatabaseTLSVerified, TLSCAPath: filepath.Join(t.TempDir(), "database-ca.pem"), Enabled: true,
				},
				ReadPassword:  []byte("new-read-password"),
				WritePassword: []byte("new-write-password"),
			})
			if err == nil {
				t.Fatal("故障注入后新数据库登记目标配置提交意外成功")
			}
			if strings.Contains(err.Error(), "new-read-password") || strings.Contains(err.Error(), "new-write-password") {
				t.Fatal("新数据库登记目标配置提交错误泄露了明文凭据")
			}
			after := databaseConfigurationStateSnapshot(t, credentialStore)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("失败的新数据库登记目标配置提交改变了状态：提交前 %#v，提交后 %#v", before, after)
			}
		})
	}
}

func openDatabaseConfigurationTestVault(t *testing.T) (*Store, *Vault) {
	t.Helper()
	credentialStore := openTestStore(t)
	vault, err := credentialStore.Initialize(context.Background(), []byte("database-configuration-master-password"))
	if err != nil {
		t.Fatalf("初始化数据库登记目标配置凭据库失败：%v", err)
	}
	t.Cleanup(vault.Lock)
	return credentialStore, vault
}

func saveDatabaseConfigurationTestInstance(t *testing.T, credentialStore *Store, vault *Vault, instance DatabaseInstance, readPassword, writePassword []byte) DatabaseInstance {
	t.Helper()
	readCredentialID, err := vault.PutDatabaseReadCredential(context.Background(), instance, readPassword)
	if err != nil {
		t.Fatalf("写入数据库只读测试凭据失败：%v", err)
	}
	instance.ReadCredentialID = readCredentialID
	if instance.WriteUsername != "" {
		writeCredentialID, err := vault.PutDatabaseWriteCredential(context.Background(), instance, writePassword)
		if err != nil {
			t.Fatalf("写入数据库可写测试凭据失败：%v", err)
		}
		instance.WriteCredentialID = writeCredentialID
	}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("写入数据库登记目标测试配置失败：%v", err)
	}
	saved, err := credentialStore.DatabaseInstance(context.Background(), instance.Host, instance.Port)
	if err != nil {
		t.Fatalf("读取数据库登记目标测试配置失败：%v", err)
	}
	return saved
}

func saveDatabaseConfigurationTestSSHTarget(t *testing.T, credentialStore *Store, vault *Vault) SSHTarget {
	t.Helper()
	target := SSHTarget{IP: "192.0.2.92", Mode: SSHDirect, LoginUsername: "ops", Enabled: true}
	credentialID, err := vault.PutSSHTargetCredential(context.Background(), target, []byte("ssh-password"))
	if err != nil {
		t.Fatalf("写入 SSH 测试凭据失败：%v", err)
	}
	target.CredentialID = credentialID
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("写入 SSH 测试配置失败：%v", err)
	}
	saved, err := credentialStore.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("读取 SSH 测试配置失败：%v", err)
	}
	return saved
}

func databaseConfigurationCredentialCiphertext(t *testing.T, credentialStore *Store, credentialID string) []byte {
	t.Helper()
	var ciphertext []byte
	if err := credentialStore.db.QueryRow("SELECT ciphertext FROM credentials WHERE id = ?", credentialID).Scan(&ciphertext); err != nil {
		t.Fatalf("读取数据库登记目标凭据密文失败：%v", err)
	}
	return bytes.Clone(ciphertext)
}

func assertDatabaseConfigurationCredential(t *testing.T, vault *Vault, credentialID, expected string) {
	t.Helper()
	credential, err := vault.Credential(context.Background(), credentialID)
	if err != nil {
		t.Fatalf("读取数据库登记目标凭据失败：%v", err)
	}
	defer secret.Zero(credential)
	if !bytes.Equal(credential, []byte(expected)) {
		t.Fatalf("数据库登记目标凭据 = %q，期望 %q", credential, expected)
	}
}

type databaseConfigurationState struct {
	Databases   []DatabaseInstance
	SSH         []SSHTarget
	Credentials map[string][]byte
	Owners      []databaseConfigurationCredentialOwner
}

type databaseConfigurationCredentialOwner struct {
	CredentialID string
	Protocol     string
	TargetHost   string
	TargetPort   int
	Identity     string
}

func databaseConfigurationStateSnapshot(t *testing.T, credentialStore *Store) databaseConfigurationState {
	t.Helper()
	state := databaseConfigurationState{Credentials: make(map[string][]byte)}
	var err error
	state.Databases, err = credentialStore.ListDatabaseInstances(context.Background())
	if err != nil {
		t.Fatalf("读取数据库登记目标状态快照失败：%v", err)
	}
	state.SSH, err = credentialStore.ListSSHTargets(context.Background())
	if err != nil {
		t.Fatalf("读取 SSH 登记目标状态快照失败：%v", err)
	}
	credentialRows, err := credentialStore.db.Query("SELECT id, ciphertext FROM credentials ORDER BY id")
	if err != nil {
		t.Fatalf("读取数据库配置凭据状态快照失败：%v", err)
	}
	defer credentialRows.Close()
	for credentialRows.Next() {
		var credentialID string
		var ciphertext []byte
		if err := credentialRows.Scan(&credentialID, &ciphertext); err != nil {
			t.Fatalf("读取数据库配置凭据状态快照行失败：%v", err)
		}
		state.Credentials[credentialID] = bytes.Clone(ciphertext)
	}
	if err := credentialRows.Err(); err != nil {
		t.Fatalf("遍历数据库配置凭据状态快照失败：%v", err)
	}
	ownerRows, err := credentialStore.db.Query(`
		SELECT credential_id, protocol, target_host, target_port, identity
		FROM credential_owners
		ORDER BY credential_id`)
	if err != nil {
		t.Fatalf("读取数据库配置凭据归属状态快照失败：%v", err)
	}
	defer ownerRows.Close()
	for ownerRows.Next() {
		var owner databaseConfigurationCredentialOwner
		if err := ownerRows.Scan(&owner.CredentialID, &owner.Protocol, &owner.TargetHost, &owner.TargetPort, &owner.Identity); err != nil {
			t.Fatalf("读取数据库配置凭据归属状态快照行失败：%v", err)
		}
		state.Owners = append(state.Owners, owner)
	}
	if err := ownerRows.Err(); err != nil {
		t.Fatalf("遍历数据库配置凭据归属状态快照失败：%v", err)
	}
	return state
}
