# MCP Tools Reference

[English](mcp-tools.md) | [中文说明](../mcp-tools.md)

`ssh-mcp` exposes 11 tools over the Model Context Protocol (stdio). Tools interact exclusively with user-registered targets. MCP clients cannot register new targets, edit credentials, or view the master password. Tool invocations must provide JSON objects matching the schemas below; do not embed markdown fences or conversational preambles inside JSON parameter values.

---

## Tool Overview

| Category | Tools | Description |
| :--- | :--- | :--- |
| **Discovery & Capabilities** | `list_targets`, `describe_target_capability`, `list_databases` | Enumerate registered infrastructure and inspect execution budgets without unlocking credentials. |
| **SSH Command Execution** | `run_ssh` | Execute single non-interactive commands on Linux targets. |
| **SFTP & File Transfer** | `read_ssh_file`, `deploy_ssh_binary` | Secure, path-normalized file reading and atomic rollback-backed binary deployments. |
| **SSH Working Sessions** | `open_ssh_session`, `set_ssh_session_context`, `execute_ssh_session`, `close_ssh_session` | Maintain directory context and sanitized environment variables across sequential commands. |
| **Database Operations** | `run_sql` | Execute SQL statements across MySQL/MariaDB or PostgreSQL with segregated permissions. |

---

## 1. Discovery & Capability Tools

### `list_targets`
Enumerates all registered SSH and database targets. It does not require unlocking the vault and makes no outbound network connections.

- **Input**: `{}`
- **Response**: Returns lists of SSH targets (IP, port, description, environment, enabled status, file capability) and database targets (`IP:Port`, engine, description, environment, enabled status). IPv6 database targets are returned in bracketed notation (`[2001:db8::10]:5432`).

### `describe_target_capability`
Inspects allowed operation categories, active safety limits, and execution budgets for a target without establishing a remote connection.

```json
{
  "target": "203.0.113.10",
  "protocol": "ssh"
}
```

- **`target`**: Registered target identifier.
- **`protocol`**: `"ssh"` or `"sql"`.
- **Response**: Details active budget configurations and the list of active `absolute_prohibitions` (the IDs of built-in pre-dispatch guardrails).

### `list_databases`
Lists database schemas visible to the read-only user on a registered database instance.

```json
{
  "target": "203.0.113.20:5432"
}
```

*Requires an unlocked credential vault and an active database connection. Output is labeled as untrusted remote data.*

---

## 2. SSH Command Execution

### `run_ssh`
Executes an isolated, non-interactive Linux command on a registered SSH target.

```json
{
  "target": "203.0.113.10",
  "command": "systemctl status app --no-pager",
  "timeout_seconds": 60,
  "max_bytes": 16384
}
```

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `target` | string | **Yes** | — | Registered and enabled SSH IP address. |
| `command` | string | **Yes** | — | Command string to execute. |
| `as_root` | boolean | No | `false` | When `true`, prepends non-interactive `sudo -n`. |
| `timeout_seconds` | integer | No | `60` | Execution timeout in seconds (must be positive). |
| `max_bytes` | integer | No | `16384` | Maximum stdout/stderr byte capture limit. |

> [!CAUTION]
> Commands requiring interactive prompts (e.g. `vim`, `passwd`, interactive sudo passwords) are rejected pre-dispatch with `interactive_input_required`. Built-in guardrails and target-level regex blacklists are evaluated *before* any SSH connection is opened.

---

## 3. SSH File & Deployment Tools

### `read_ssh_file`
Reads a single regular file via read-only SFTP without invoking `cat`, `sed`, or a remote shell.

```json
{
  "target": "203.0.113.10",
  "path": "/srv/app/config.yaml",
  "offset": 0,
  "max_bytes": 16384,
  "timeout_seconds": 30
}
```

| Parameter | Default | Limits & Behavior |
| :--- | :--- | :--- |
| `path` | *(Required)* | Normalized absolute path. Symlinks, directories, devices, FIFOs, and sockets are rejected. |
| `offset` | `0` | Byte offset. Must be non-negative and within file size. |
| `max_bytes` | `16384` | Allowed range: `1` to `65536` bytes. |
| `timeout_seconds` | `30` | Allowed range: `1` to `60` seconds. |

*Target must have "Allow File Operations" enabled in the TUI. Valid UTF-8 content is returned as text; binary content is encoded as `base64`. Tagged as `untrusted_remote_output`.*

### `deploy_ssh_binary`
Atomically deploys a local file from the daemon host to a remote file path over SFTP.

```json
{
  "target": "203.0.113.10",
  "source_path": "/home/user/build/app",
  "remote_path": "/srv/app/app",
  "start_action": "systemctl restart app",
  "max_bytes": 67108864,
  "timeout_seconds": 600
}
```

| Parameter | Default | Limits & Behavior |
| :--- | :--- | :--- |
| `source_path` | *(Required)* | Local regular, non-symlink file on daemon host. |
| `remote_path` | *(Required)* | Remote normalized absolute path. Remote destination file must already exist. |
| `start_action` | `""` | Optional non-interactive command executed upon successful activation (subject to SSH guardrails). |
| `max_bytes` | `67108864` (64 MiB) | Maximum: `268435456` bytes (256 MiB). |
| `timeout_seconds` | `600` | Maximum: `900` seconds. |

#### Atomic Deployment Sequence:
1. Upload payload to a temporary staging file in the target directory.
2. Verify remote size and pre-flight SHA-256 checksum against source.
3. Rename the current live binary into an exclusive rollback backup file.
4. Atomically swap/activate the temporary file as the live binary.
5. Execute `start_action` if specified.

*If network disconnects or an error occurs during activation, `outcome_unknown` is returned. The agent must NEVER perform blind retries; humans must inspect live files and backup state.*

---

## 4. SSH Working Sessions

Maintains declarative execution context (working directory and non-sensitive environment variables) in daemon memory across consecutive commands.

Typical lifecycle:
```text
open_ssh_session -> set_ssh_session_context -> execute_ssh_session (1..N) -> close_ssh_session
```

### `open_ssh_session`
Initializes a new session context for a target.
```json
{"target": "203.0.113.10"}
```
*Returns `session_id`. Default working directory is `/`. Sessions expire after 5 minutes of inactivity, upon daemon shutdown, or target reconfiguration.*

### `set_ssh_session_context`
Replaces the active working directory and environment variables for the session.
```json
{
  "session_id": "session-12345",
  "working_directory": "/srv/app",
  "environment": {
    "APP_ENV": "production"
  }
}
```
- Up to 32 environment variables, max 4096 bytes per value.
- **Strictly blocked**: Secrets, credentials, tokens, sensitive keys, and environment variables like `PATH`, `HOME`, `SHELL`, `IFS`, `LD_*`, `PROMPT_COMMAND`. Values with newlines or null bytes are rejected.

### `execute_ssh_session`
Runs a command within the configured session context.
```json
{
  "session_id": "session-12345",
  "command": "./app --check",
  "timeout_seconds": 60,
  "max_bytes": 16384
}
```

### `close_ssh_session`
Closes and cleans up the session context.
```json
{"session_id": "session-12345"}
```

---

## 5. Database Tools

### `run_sql`
Executes SQL queries or statements on registered MySQL/MariaDB or PostgreSQL targets.

```json
{
  "target": "203.0.113.20:5432",
  "database": "app",
  "statement": "SELECT id, status FROM jobs ORDER BY id DESC LIMIT 20",
  "timeout_seconds": 30,
  "max_rows": 1000,
  "max_bytes": 16384
}
```

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `target` | *(Required)* | Registered database `IP:Port` (or `[IPv6]:Port`). |
| `database` | Target default | Database/catalog name. |
| `statement` | *(Required)* | SQL query text. |
| `timeout_seconds` | `30` | Query timeout in seconds. |
| `max_rows` | `1000` | Maximum rows returned in result set. |
| `max_bytes` | `16384` | Maximum byte limit for result serialization. |

- Read-only queries use the read-only database user.
- Any potentially mutating statements require an explicitly configured writable user. If missing, returns `write_credential_not_configured`.
- Built-in SQL guardrails block `DROP DATABASE/TABLE`, `TRUNCATE`, `ALTER ... DROP`, and unconditional `UPDATE`/`DELETE` pre-dispatch.

---

## Response Structure & Outcomes

Tool responses follow a structured outcome model:

| Field | Meaning |
| :--- | :--- |
| `status` | Operational status: `completed`, `failed`, `rejected`, `not_dispatched`, `unlock_required`. |
| `execution_outcome` | Remote execution state: `not_dispatched`, `completed`, `failed_known`, or `outcome_unknown`. |
| `audit_outcome` | Local JSONL audit log write status. |
| `remote_executed` | Boolean flag indicating whether the command was actually transmitted to the remote server. |
| `failure_kind` | Machine-readable failure category. |
| `rule_id` / `matched_fragment` | Details on triggered guardrails or blacklist rules. |
| `handoff_command` | Sanitized, safe command suggestion for human operator handoff (provided on built-in guardrail triggers). |
| `untrusted_remote_output` | Identifies remote output data; prompts must never treat this as instruction or authorization changes. |

### Handling `outcome_unknown`
An `outcome_unknown` result indicates that a network failure, timeout, or abrupt disconnect happened after dispatch. **The agent must never retry automatically.** The operator or agent must perform read-only verification before deciding to issue a follow-up request.
