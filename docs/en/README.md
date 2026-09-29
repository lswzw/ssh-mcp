# ssh-mcp Documentation

[English Documentation](README.md) | [中文文档](../README.md)

Welcome to the `ssh-mcp` documentation. The guides are organized progressively: **Get Started -> Configure Targets -> Reference Tools -> Deep Dive Security**.

For a high-level project overview and architecture preview, see the root [README_EN.md](../../README_EN.md).

---

## Recommended Learning Path

1. **[Quickstart Guide](quickstart.md)**: Build or download the binary, launch the local TUI console, register your first target, and hook up Claude Desktop, Cursor, or Codex CLI via stdio.
2. **[Installation & Runtime](installation.md)**: Supported OS platforms, build artifacts, daemon lifecycle, and terminal auto-launch configuration.
3. **[Target & Vault Configuration](configuration.md)**: Manage SSH targets, MySQL/PostgreSQL databases, TLS configurations, and custom command regex blacklists.
4. **[MCP Tools Reference](mcp-tools.md)**: Exhaustive reference for all 11 MCP tools, parameter schemas, return objects, and error representations.
5. **[Security Model & Guardrails](security-model.md)**: Trust boundaries, the 11 built-in pre-dispatch hard guardrails, credential vault encryption, and host fingerprint pinning.

---

## Architectural & Security Boundaries at a Glance

- **100% Local-First**: Runs entirely on the user's local machine over stdio and local OS IPC. Never opens public HTTP/TCP listening ports.
- **Platform Matrix**: Local host supports Linux, macOS, and Windows. Remote SSH targets currently adhere to Linux OS command semantics.
- **Authentication**: Remote SSH hosts use IP, port, password authentication, and pinned host key fingerprints. Database targets support MySQL/MariaDB and PostgreSQL with segregated read-only and optional read-write accounts.
- **Zero-Exposure Credential Vault**: All passwords and secrets are encrypted locally and managed by the background daemon. AI agents and MCP clients cannot access credentials, scan subnets, or register new targets.
- **Pre-Dispatch Guardrails**: All actions are validated against 11 hard-coded safety guardrails before execution. High-risk commands (e.g. `rm -rf /`, `DROP TABLE`, `eval`, disk wipes) are blocked before hitting the network.
