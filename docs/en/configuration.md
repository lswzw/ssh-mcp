# Target & Vault Configuration Guide

[English](configuration.md) | [中文说明](../configuration.md)

All targets, passwords, and security boundaries are managed exclusively through the local Terminal User Interface (TUI). MCP clients can only discover non-sensitive target metadata; they cannot add, edit, or delete targets.

---

## 1. SSH Target Configuration

In the TUI, press `t` to open the target list, then press `n` to create a new target (or select an existing one and press `Enter` to edit).

| Field | Description |
| :--- | :--- |
| **IP** | Remote IPv4 or IPv6 address. (Domain names/hostnames are currently not accepted to prevent DNS rebinding attacks). |
| **SSH Port** | Target SSH port (default: `22`). |
| **Username / Password** | Authentication credentials. Leave password blank when editing to retain existing encrypted credentials. |
| **Command Blacklist** | Comma-separated Go RE2 regular expressions. Matching commands are blocked immediately. |
| **Description / Environment** | Local metadata for operator context and agent discovery (e.g., `production`, `staging`). |
| **Allow File Operations** | Boolean (`true`/`false`). Controls access to `read_ssh_file` and `deploy_ssh_binary`. Defaults to `true`. |

### Connection Testing & Host Fingerprint Pinning
Upon pressing `Ctrl+S` to save, `ssh-mcp` immediately tests the connection:
- **First-time connection**: The server presents the remote host's public key fingerprint. You must manually inspect and confirm it by typing `y`.
- **Fingerprint mismatch**: If a previously pinned fingerprint changes, the connection is blocked with a security warning. The target is never blindly trusted.
- **Target OS**: Remote target semantics must be Linux.

### Command Blacklist Syntax & Examples
The blacklist accepts Go RE2 regular expressions separated by commas:

```text
rm /data/.*, cat /etc/passwd, passwd.*
```

> [!NOTE]
> The target-level blacklist only adds extra restrictions; it cannot bypass the 11 built-in pre-dispatch guardrails. Leaving this field blank means relying solely on the built-in system guardrails. Updating a blacklist automatically invalidates active SSH working sessions for that target.

---

## 2. Database Target Configuration

In the target list (`t`), press `d` to register a database instance. Supported engines:
- **MySQL / MariaDB** (MySQL 5.7+, 8.0+; MariaDB 10.3+)
- **PostgreSQL** (version 12+)

| Field | Description |
| :--- | :--- |
| **IP:Port** | Unique instance identifier. IPv6 addresses must be bracketed (e.g., `[2001:db8::10]:5432`). |
| **Default Database** | Fallback database name when the MCP client query does not specify one. |
| **Read-Only User / Pass** | Mandatory credentials used for queries, schemas, and table listings. |
| **Writable User / Pass** | Optional credentials required for queries containing write keywords. If left blank, write operations are strictly blocked. |
| **Transport Policy** | `tls_verified` or `legacy_plaintext`. |
| **CA Certificate Path** | Mandatory local absolute path to the root CA certificate when using `tls_verified`. |
| **Description / Environment** | Local metadata for agent context. |

### TLS & Account Segregation Safeguards
- **Mandatory Validation**: When `tls_verified` is selected, server certificates are strictly validated against the CA. Verification failures will abort the connection rather than downgrade to plaintext.
- **Strict Account Isolation**: If no writable user is configured, any write query fails with `write_credential_not_configured`. `ssh-mcp` never silently executes write queries using read-only credentials.

---

## 3. Target Lifecycle: Toggle, Delete, & Re-enable

- **Toggle Enable/Disable (`x`)**: Disables or re-enables a target. Re-enabling a disabled target requires pressing `Enter` to re-verify connectivity and fingerprint before saving.
- **Delete Target (`Delete`)**: Removes the target and its credentials permanently (requires typing `y` to confirm).
- **Refresh (`r`)**: Reloads the target list from the database.

---

## 4. Vault Encryption & Master Password

The master password protects the encrypted credential envelope stored inside `state.db`. Secrets are decrypted in daemon memory only while the vault is unlocked.

The TUI provides built-in vault management commands:
- **`u`**: Unlock credential vault (or initialize on first run).
- **`l`**: Lock credential vault immediately (erases decrypted keys from daemon memory).
- **`p`**: Change master password.
- **`k`**: Rotate data encryption key (requires typing `ROTATE`).
- **`b`**: Export an encrypted vault backup.
- **`o`**: Restore vault from an encrypted backup file.
- **`e`**: Toggle TUI interface language between English and Chinese (`en` / `zh`), persisted automatically across sessions.

> [!WARNING]
> If you lose your master password, the encrypted credentials cannot be recovered by the MCP server or agent. Always store your master password in a password manager and maintain encrypted backups.
