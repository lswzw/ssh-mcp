# Security Model & Guardrails

[English](security-model.md) | [中文说明](../security-model.md)

The security objective of `ssh-mcp` is to constrain AI remote operations strictly to explicitly user-registered targets, and to halt dispatch on identifiable high-risk command categories before they touch the network.

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
All output returned from remote SSH sessions, SFTP transfers, and database queries is treated as **untrusted data**. Remote outputs can never alter daemon state, change target permissions, bypass pre-dispatch guardrails, or dynamically manipulate authorization boundaries. This mitigates prompt injection risks arising from compromised remote servers.

---

## 2. Pre-Dispatch Verification Checks

Before establishing any remote connection, the daemon verifies:
1. Target is registered and currently enabled.
2. Local credential vault is unlocked with the master password.
3. Operation-specific capability flags are satisfied (e.g. file read/write flag is enabled for SFTP operations).
4. For mutating SQL queries, a writable database user is explicitly configured.

If any check fails, the request is rejected immediately with a `not_dispatched` status.

---

## 3. The 11 Built-in Hard Guardrails

The daemon implements 11 hard-coded lexical and structural inspection guardrails. If a command matches any guardrail, it is rejected **prior to dispatch**:

| Rule ID | Interception Scope |
| :--- | :--- |
| `format_or_partition` | Formatting disks, repartitioning, or altering filesystem partition tables. |
| `raw_block_device_write` | Direct writes, overwrites, or zeroing of raw block devices (e.g., `dd of=/dev/sdX`). |
| `base_system_tree_destruction` | Recursive deletion or destruction of essential OS trees (`/`, `/boot`, `/etc`, `/bin`, `/sbin`, `/lib*`, `/usr`, `/dev`, `/proc`, `/sys`, `/run`). |
| `unbounded_resource_exhaustion` | Obvious resource exhaustion patterns (fork bombs, infinite output loops without bounds). |
| `opaque_shell_effect` | Opaque shell constructs whose effects cannot be statically determined (e.g., `eval`, `source`, dynamic substitution, `curl ... \| bash`, base64 piping into bash). |
| `opaque_sql_effect` | Stored procedure execution, dynamic SQL construction, triggers, and host-interacting SQL commands (e.g., `INTO OUTFILE`, `LOAD DATA`). |
| `drop_database_schema_table` | Catastrophic structural removal: `DROP DATABASE`, `DROP SCHEMA`, `DROP TABLE`. |
| `truncate_table` | Bulk table clearance: `TRUNCATE TABLE`. |
| `alter_drop` | Structural destruction via alteration: `ALTER TABLE ... DROP COLUMN/PARTITION`. |
| `unconditional_update_or_delete` | Bulk mutations without a `WHERE` clause (or with tautological conditions like `WHERE 1=1`). |
| `unregistered_remote_hop` | Lateral pivoting or tunneling through nested SSH, SCP, SFTP, or port forwarding to unregistered network hops. |

When a hard guardrail is triggered, `ssh-mcp` returns the `rule_id`, `matched_fragment`, and a sanitized `handoff_command`. Agents are instructed never to circumvent guardrails through obfuscation; tasks should instead be handed off to a human operator.

---

## 4. SSH Host Key Pinning & MITM Defense

- **First-Time Pinning**: During initial target registration in the TUI, `ssh-mcp` connects and retrieves the server's public key fingerprint. The operator must explicitly verify and accept it (`y`).
- **Strict Verification**: Subsequent SSH connections verify the remote key against the pinned fingerprint. Any mismatch terminates the connection immediately.
- **No Blind Trust**: Host fingerprint mismatches can only be re-accepted after deliberate review in the TUI.

---

## 5. Safe & Atomic File Deployments (`deploy_ssh_binary`)

File deployments follow a multi-stage atomic pipeline:
1. **Pre-flight Validation**: Validates local file existence, ensures neither source nor destination are symlinks, and calculates source size and SHA-256 hash.
2. **Staging**: Uploads to a temporary file (`.tmp`) in the destination directory.
3. **Checksum Verification**: Re-computes size and SHA-256 on the remote server to guarantee transmission integrity.
4. **Automated Rollback Backup**: Moves the existing live target file to an exclusive backup file in the same directory.
5. **Atomic Activation**: Renames the temporary file to the live target path.
6. **Zero Blind Retries**: If connectivity breaks during activation, `outcome_unknown` is returned. Automatic retries are forbidden to prevent state corruption.

---

## 6. Credential Vault & Audit Logging

- **Master Password Encryption**: Sensitive secrets are encrypted using a derived data key. Keys are held in volatile memory only while unlocked and scrubbed upon lock or exit.
- **Local Audit Log (`audit.log`)**: Capacity-capped local JSONL file recording target IDs, timestamps, rule evaluations, and execution statuses. Sensitive command payloads and file contents are sanitized.
