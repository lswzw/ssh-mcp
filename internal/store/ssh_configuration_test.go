package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"ssh-mcp/internal/secret"
)

func TestVaultCommitsValidatedSSHTargetConfiguration(t *testing.T) {
	ctx := context.Background()
	credentialStore, vault := openSSHConfigurationTestVault(t)
	current := saveSSHConfigurationTestTarget(t, credentialStore, vault, SSHTarget{
		IP: "192.0.2.80", Mode: SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true,
	}, []byte("previous-password"), "SHA256:previous")
	other := saveSSHConfigurationTestTarget(t, credentialStore, vault, SSHTarget{
		IP: "192.0.2.81", Mode: SSHDirect, SSHPort: 2222, LoginUsername: "deploy", Enabled: true,
	}, []byte("other-password"), "SHA256:other")
	otherCiphertext := sshConfigurationCredentialCiphertext(t, credentialStore, other.CredentialID)

	updated, err := vault.CommitValidatedSSHTargetConfiguration(ctx, ValidatedSSHTargetConfiguration{
		Target: SSHTarget{
			IP: "192.0.2.80", Mode: SSHDirect, SSHPort: 2200, LoginUsername: "ops",
			CredentialID: "caller-supplied-id", Description: "更新后的登记目标", Environment: "production", Enabled: false,
		},
		Password:             []byte("replacement-password"),
		ConfirmedFingerprint: "SHA256:replacement",
	})
	if err != nil {
		t.Fatalf("提交已验证的 SSH 登记目标配置失败：%v", err)
	}
	if updated.CredentialID == current.CredentialID {
		t.Fatalf("轮换后的 SSH 凭据标识仍为旧记录 %q", updated.CredentialID)
	}
	if updated.CredentialID == "caller-supplied-id" {
		t.Fatal("提交接受了调用方指定的凭据标识")
	}
	saved, err := credentialStore.SSHTarget(ctx, current.IP)
	if err != nil {
		t.Fatalf("读取已提交的 SSH 登记目标失败：%v", err)
	}
	if !reflect.DeepEqual(saved, updated) || saved.SSHPort != 2200 || saved.Description != "更新后的登记目标" || saved.Enabled {
		t.Fatalf("已提交的 SSH 登记目标 = %#v，返回值 = %#v", saved, updated)
	}
	password, err := vault.Credential(ctx, saved.CredentialID)
	if err != nil {
		t.Fatalf("读取更新后的 SSH 凭据失败：%v", err)
	}
	defer secret.Zero(password)
	if !bytes.Equal(password, []byte("replacement-password")) {
		t.Fatal("更新后的 SSH 凭据未保留新值")
	}
	if _, err := vault.Credential(ctx, current.CredentialID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("轮换后读取旧 SSH 凭据错误 = %v，期望 ErrCredentialNotFound", err)
	}
	if _, err := credentialStore.HostKeyFingerprint(ctx, current.IP, 22); !errors.Is(err, ErrHostKeyNotFound) {
		t.Fatalf("旧 SSH 端口的主机身份错误 = %v，期望 ErrHostKeyNotFound", err)
	}
	fingerprint, err := credentialStore.HostKeyFingerprint(ctx, current.IP, 2200)
	if err != nil || fingerprint != "SHA256:replacement" {
		t.Fatalf("更新后的 SSH 主机身份 = %q，错误 = %v", fingerprint, err)
	}
	otherSaved, err := credentialStore.SSHTarget(ctx, other.IP)
	if err != nil || !reflect.DeepEqual(otherSaved, other) {
		t.Fatalf("其他 SSH 登记目标被改变：%#v，错误 = %v", otherSaved, err)
	}
	if after := sshConfigurationCredentialCiphertext(t, credentialStore, other.CredentialID); !bytes.Equal(after, otherCiphertext) {
		t.Fatal("更新一个 SSH 登记目标改变了其他目标的凭据")
	}
	otherFingerprint, err := credentialStore.HostKeyFingerprint(ctx, other.IP, other.SSHPort)
	if err != nil || otherFingerprint != "SHA256:other" {
		t.Fatalf("其他 SSH 登记目标的主机身份 = %q，错误 = %v", otherFingerprint, err)
	}
}

func TestVaultCommitValidatedSSHTargetConfigurationRetainsCredentialWithoutPassword(t *testing.T) {
	ctx := context.Background()
	credentialStore, vault := openSSHConfigurationTestVault(t)
	current := saveSSHConfigurationTestTarget(t, credentialStore, vault, SSHTarget{
		IP: "192.0.2.82", Mode: SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true,
	}, []byte("existing-password"), "SHA256:existing")

	updated, err := vault.CommitValidatedSSHTargetConfiguration(ctx, ValidatedSSHTargetConfiguration{
		Target: SSHTarget{
			IP: "192.0.2.82", Mode: SSHDirect, SSHPort: 22, LoginUsername: "operator",
			CredentialID: "caller-supplied-id", Description: "保留凭据", Enabled: true,
		},
		ConfirmedFingerprint: "SHA256:confirmed-again",
	})
	if err != nil {
		t.Fatalf("无密码提交已验证的 SSH 登记目标配置失败：%v", err)
	}
	if updated.CredentialID != current.CredentialID {
		t.Fatalf("无密码更新后的凭据标识 = %q，期望 %q", updated.CredentialID, current.CredentialID)
	}
	password, err := vault.Credential(ctx, updated.CredentialID)
	if err != nil {
		t.Fatalf("读取保留的 SSH 凭据失败：%v", err)
	}
	defer secret.Zero(password)
	if !bytes.Equal(password, []byte("existing-password")) {
		t.Fatal("无密码更新改变了既有 SSH 凭据")
	}
	fingerprint, err := credentialStore.HostKeyFingerprint(ctx, current.IP, current.SSHPort)
	if err != nil || fingerprint != "SHA256:confirmed-again" {
		t.Fatalf("无密码更新后的 SSH 主机身份 = %q，错误 = %v", fingerprint, err)
	}
}

func TestVaultCommitValidatedSSHTargetConfigurationAdvancesExecutionRevisionForHostIdentityChange(t *testing.T) {
	ctx := context.Background()
	credentialStore, vault := openSSHConfigurationTestVault(t)
	current := saveSSHConfigurationTestTarget(t, credentialStore, vault, SSHTarget{
		IP: "192.0.2.83", Mode: SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true,
	}, []byte("existing-password"), "SHA256:original")
	confirmed, err := vault.CommitValidatedSSHTargetConfiguration(ctx, ValidatedSSHTargetConfiguration{
		Target:               current,
		ConfirmedFingerprint: "SHA256:original",
	})
	if err != nil {
		t.Fatalf("建立已确认 SSH 主机身份基线失败：%v", err)
	}

	updated, err := vault.CommitValidatedSSHTargetConfiguration(ctx, ValidatedSSHTargetConfiguration{
		Target:               confirmed,
		ConfirmedFingerprint: "SHA256:replacement",
	})
	if err != nil {
		t.Fatalf("提交变更 SSH 主机身份的配置失败：%v", err)
	}
	if updated.Revision <= confirmed.Revision {
		t.Fatalf("SSH 主机身份变化未推进执行版本：更新前 %d，更新后 %d", confirmed.Revision, updated.Revision)
	}
	fingerprint, err := credentialStore.HostKeyFingerprint(ctx, current.IP, current.SSHPort)
	if err != nil || fingerprint != "SHA256:replacement" {
		t.Fatalf("更新后的 SSH 主机身份 = %q，错误 = %v", fingerprint, err)
	}
}

func TestVaultCommitValidatedSSHTargetConfigurationRollsBackOnFailure(t *testing.T) {
	testCases := []struct {
		name   string
		inject func(*testing.T, *Store)
	}{
		{
			name: "凭据写入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_ssh_configuration_credential
					BEFORE INSERT ON credentials
					BEGIN
					SELECT RAISE(ABORT, '注入的 SSH 凭据写入失败');
					END;`); err != nil {
					t.Fatalf("注入 SSH 凭据写入失败失败：%v", err)
				}
			},
		},
		{
			name: "登记目标写入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_ssh_configuration_target
					BEFORE UPDATE ON ssh_targets
					BEGIN
					SELECT RAISE(ABORT, '注入的 SSH 登记目标写入失败');
					END;`); err != nil {
					t.Fatalf("注入 SSH 登记目标写入失败失败：%v", err)
				}
			},
		},
		{
			name: "主机身份写入失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_ssh_configuration_host_key
					BEFORE INSERT ON known_hosts
					BEGIN
					SELECT RAISE(ABORT, '注入的 SSH 主机身份写入失败');
					END;`); err != nil {
					t.Fatalf("注入 SSH 主机身份写入失败失败：%v", err)
				}
			},
		},
		{
			name: "提交失败",
			inject: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				credentialStore.sshConfigurationCommit = func(*sql.Tx) error {
					return errors.New("注入的 SSH 配置提交失败")
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			credentialStore, vault := openSSHConfigurationTestVault(t)
			current := saveSSHConfigurationTestTarget(t, credentialStore, vault, SSHTarget{
				IP: "192.0.2.83", Mode: SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true,
			}, []byte("previous-password"), "SHA256:previous")
			saveSSHConfigurationTestTarget(t, credentialStore, vault, SSHTarget{
				IP: "192.0.2.84", Mode: SSHDirect, SSHPort: 2222, LoginUsername: "deploy", Enabled: true,
			}, []byte("other-password"), "SHA256:other")
			testCase.inject(t, credentialStore)
			before := sshConfigurationStateSnapshot(t, credentialStore)

			_, err := vault.CommitValidatedSSHTargetConfiguration(ctx, ValidatedSSHTargetConfiguration{
				Target: SSHTarget{
					IP: current.IP, Mode: SSHDirect, SSHPort: 2200, LoginUsername: "ops", Enabled: false,
				},
				Password:             []byte("replacement-password"),
				ConfirmedFingerprint: "SHA256:replacement",
			})
			if err == nil {
				t.Fatal("故障注入后 SSH 登记目标配置提交意外成功")
			}
			if strings.Contains(err.Error(), "replacement-password") {
				t.Fatal("SSH 登记目标配置提交错误泄露了明文凭据")
			}
			after := sshConfigurationStateSnapshot(t, credentialStore)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("失败的 SSH 登记目标配置提交改变了状态：提交前 %#v，提交后 %#v", before, after)
			}
		})
	}
}

func openSSHConfigurationTestVault(t *testing.T) (*Store, *Vault) {
	t.Helper()
	credentialStore := openTestStore(t)
	vault, err := credentialStore.Initialize(context.Background(), []byte("ssh-configuration-master-password"))
	if err != nil {
		t.Fatalf("初始化 SSH 登记目标配置凭据库失败：%v", err)
	}
	t.Cleanup(vault.Lock)
	return credentialStore, vault
}

func saveSSHConfigurationTestTarget(t *testing.T, credentialStore *Store, vault *Vault, target SSHTarget, password []byte, fingerprint string) SSHTarget {
	t.Helper()
	credentialID, err := vault.PutSSHTargetCredential(context.Background(), target, password)
	if err != nil {
		t.Fatalf("写入 SSH 登记目标测试凭据失败：%v", err)
	}
	target.CredentialID = credentialID
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("写入 SSH 登记目标测试配置失败：%v", err)
	}
	if err := credentialStore.PinInitialHostKey(context.Background(), target.IP, target.SSHPort, fingerprint); err != nil {
		t.Fatalf("写入 SSH 登记目标测试主机身份失败：%v", err)
	}
	saved, err := credentialStore.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("读取 SSH 登记目标测试配置失败：%v", err)
	}
	return saved
}

func sshConfigurationCredentialCiphertext(t *testing.T, credentialStore *Store, credentialID string) []byte {
	t.Helper()
	var ciphertext []byte
	if err := credentialStore.db.QueryRow("SELECT ciphertext FROM credentials WHERE id = ?", credentialID).Scan(&ciphertext); err != nil {
		t.Fatalf("读取 SSH 登记目标凭据密文失败：%v", err)
	}
	return bytes.Clone(ciphertext)
}

type sshConfigurationState struct {
	Targets     []SSHTarget
	Credentials map[string][]byte
	Owners      []sshConfigurationCredentialOwner
	KnownHosts  map[string]string
}

type sshConfigurationCredentialOwner struct {
	CredentialID string
	Protocol     string
	TargetHost   string
	TargetPort   int
	Identity     string
}

func sshConfigurationStateSnapshot(t *testing.T, credentialStore *Store) sshConfigurationState {
	t.Helper()
	state := sshConfigurationState{
		Credentials: make(map[string][]byte),
		KnownHosts:  make(map[string]string),
	}
	var err error
	state.Targets, err = credentialStore.ListSSHTargets(context.Background())
	if err != nil {
		t.Fatalf("读取 SSH 登记目标状态快照失败：%v", err)
	}
	credentialRows, err := credentialStore.db.Query("SELECT id, ciphertext FROM credentials ORDER BY id")
	if err != nil {
		t.Fatalf("读取 SSH 凭据状态快照失败：%v", err)
	}
	defer credentialRows.Close()
	for credentialRows.Next() {
		var credentialID string
		var ciphertext []byte
		if err := credentialRows.Scan(&credentialID, &ciphertext); err != nil {
			t.Fatalf("读取 SSH 凭据状态快照行失败：%v", err)
		}
		state.Credentials[credentialID] = bytes.Clone(ciphertext)
	}
	if err := credentialRows.Err(); err != nil {
		t.Fatalf("遍历 SSH 凭据状态快照失败：%v", err)
	}
	ownerRows, err := credentialStore.db.Query(`
		SELECT credential_id, protocol, target_host, target_port, identity
		FROM credential_owners
		ORDER BY credential_id`)
	if err != nil {
		t.Fatalf("读取 SSH 凭据归属状态快照失败：%v", err)
	}
	defer ownerRows.Close()
	for ownerRows.Next() {
		var owner sshConfigurationCredentialOwner
		if err := ownerRows.Scan(&owner.CredentialID, &owner.Protocol, &owner.TargetHost, &owner.TargetPort, &owner.Identity); err != nil {
			t.Fatalf("读取 SSH 凭据归属状态快照行失败：%v", err)
		}
		state.Owners = append(state.Owners, owner)
	}
	if err := ownerRows.Err(); err != nil {
		t.Fatalf("遍历 SSH 凭据归属状态快照失败：%v", err)
	}
	hostRows, err := credentialStore.db.Query("SELECT host, port, fingerprint FROM known_hosts ORDER BY host, port")
	if err != nil {
		t.Fatalf("读取 SSH 主机身份状态快照失败：%v", err)
	}
	defer hostRows.Close()
	for hostRows.Next() {
		var host, fingerprint string
		var port int
		if err := hostRows.Scan(&host, &port, &fingerprint); err != nil {
			t.Fatalf("读取 SSH 主机身份状态快照行失败：%v", err)
		}
		state.KnownHosts[fmt.Sprintf("%s:%d", host, port)] = fingerprint
	}
	if err := hostRows.Err(); err != nil {
		t.Fatalf("遍历 SSH 主机身份状态快照失败：%v", err)
	}
	return state
}
