# Security Model & Guardrails

[English](security-model.md) | [中文说明](../security-model.md)

This branch (unrestricted fork) keeps only two objectives: constrain AI remote operations to explicitly user-registered targets, and state the risk facts honestly to the caller. It **no longer** halts dispatch on command or SQL categories, so it is not a host sandbox, bastion, or tamper-proof audit system. Protection against mistakes now depends on the agent following the returned instructions and on the per-target blacklist the local user configures.

---

## 1. Trust Boundaries

```
+-------------------------------------------------------------------+
|                           LOCAL HOST                              |
|                                                                   |
|   +-----------------------+              +--------------------+   |
|   |  Interactive User     |              |  MCP Client / LLM  |   |
|   |  (via Local TUI)      |              |  (via Stdio Bridge)|   |
|   +-----------+-----------+              +---------+----------+   |
|               | Master Password / Admin Actions    |              |
|               v                                    v              |
|   +-----------------------------------------------------------+   |
|   |                  ssh-mcp Local Daemon                     |   |
|   |                                                           |   |
|   |   [Encrypted Credential Vault] <--- Zero Exposure to LLM  |   |
|   |   [11 Pre-Dispatch Hard Guardrails Engine]                |   |
|   |   [Target Whitelist & Host Fingerprint Verifier]          |   |
|   |   [Local Audit Logger (JSONL)]                            |   |
|   +-----------------------------+-----------------------------+   |
+---------------------------------|---------------------------------+
                                  | SSH / SFTP / TLS SQL
                                  v
+-------------------------------------------------------------------+
|                       REMOTE INFRASTRUCTURE                       |
|   Linux SSH Hosts (Pinned Fingerprints) | MySQL / PostgreSQL DBs  |
|                                                                   |
|   Output treated as: UNTRUSTED REMOTE DATA                        |
+-------------------------------------------------------------------+
```

### Local Operating System & Operator
The local user is responsible for:
- Maintaining OS-level permissions for the installation folder, `state.db`, `audit.log`, and backup files.
- Configuring targets, entering credentials, and verifying SSH host fingerprints in the local TUI console.
- Determining whether to enable file transfer permissions and regex command blacklists.

### MCP Clients and AI Agents
The MCP client (and the driving AI model) can submit commands, SQL, and file deployment requests, but **CANNOT**:
- Add, modify, or delete infrastructure targets.
- Read plaintext passwords, master passwords, database credentials, or private keys.
- Access unregistered targets, probe local networks, or scan subnets.
- Bypass or disable TUI-configured regex blacklists or file permission switches.

### Untrusted Remote Output Isolation
All output returned from remote SSH sessions, SFTP transfers, and database queries is treated as **untrusted data**. Remote outputs can never alter daemon state, change target permissions, or dynamically manipulate authorization boundaries. This mitigates prompt injection risks arising from compromised remote servers.

---

## 2. Pre-Dispatch Verification Checks

Before establishing any remote connection, the daemon verifies:
1. Target is registered and currently enabled.
2. Local credential vault is unlocked with the master password.
3. Operation-specific capability flags are satisfied (e.g. file read/write flag is enabled for SFTP operations).
4. For mutating SQL queries, a writable database user is explicitly configured.

If any check fails, the request is rejected immediately with a `not_dispatched` status.

---

## 3. The 11 Built-in Hard Guardrails: Removed In This Fork

Upstream ships 11 fixed pre-dispatch guardrails (`format_or_partition`, `raw_block_device_write`, `base_system_tree_destruction`, `unbounded_resource_exhaustion`, `opaque_shell_effect`, `opaque_sql_effect`, `drop_database_schema_table`, `truncate_table`, `alter_drop`, `unconditional_update_or_delete`, `unregistered_remote_hop`). **All of them are deleted here.**

- `policy.EvaluateSSH` and `policy.EvaluateSQL` only validate request shape, match the per-target blacklist, and normalize budgets. They never return `absolute_prohibited`.
- `describe_target_capability` returns `execution_policy: "unrestricted"`, an always-empty `absolute_prohibitions`, and a `safety_notice` list carrying the risk terms.
- The rule-ID constants remain only so historical audit rows still decode; this branch never emits them.
- A nested `ssh other-host` issued through `run_ssh` is no longer inspected; audit covers the first hop only.

The safety responsibility therefore moves into the prompt: the returned `mcpInstructions` and `safety_notice` require the caller to restate any irreversible operation to the current user and obtain explicit confirmation. That is a convention, not enforcement.

---

## 4. SSH Host Key Pinning & MITM Defense

- **First-Time Pinning**: During initial target registration in the TUI, `ssh-mcp` connects and retrieves the server's public key fingerprint. The operator must explicitly verify and accept it (`y`).
- **Strict Verification**: Subsequent SSH connections verify the remote key against the pinned fingerprint. Any mismatch terminates the connection immediately.
- **No Blind Trust**: Host fingerprint mismatches can only be re-accepted after deliberate review in the TUI.

---

## 5. Safe & Atomic File Deployments (`deploy_ssh_binary`)

File deployments follow a multi-stage atomic pipeline:
1. **Pre-flight Validation**: Validates local source existence and hashes it. A destination that does not exist is created; an existing destination must be a regular non-symlink file and is backed up. A missing parent directory is refused — the tool never creates directories.
2. **Staging**: Uploads to a temporary file (`.tmp`) in the destination directory.
3. **Checksum Verification**: Re-computes size and SHA-256 on the remote server to guarantee transmission integrity.
4. **Automated Rollback Backup**: Moves the existing live target file to an exclusive backup file in the same directory. A created target reports `created: true` with an empty `backup_path`.
5. **Atomic Activation**: Renames the temporary file to the live target path.
6. **Zero Blind Retries**: If connectivity breaks during activation, `outcome_unknown` is returned. Automatic retries are forbidden to prevent state corruption.

---

## 6. Credential Vault & Audit Logging

- **Master Password Encryption**: Sensitive secrets are encrypted using a derived data key. Keys are held in volatile memory only while unlocked and scrubbed upon lock or exit.
- **Local Audit Log (`audit.log`)**: Capacity-capped local JSONL file recording target IDs, timestamps, rule evaluations, and execution statuses. Sensitive command payloads and file contents are sanitized.
