# Installation & Runtime Guide

[English](installation.md) | [中文说明](../installation.md)

This document provides detailed instructions on downloading, compiling, and running `ssh-mcp`, managing daemon lifecycles, and configuring desktop terminal launchers.

---

## Supported Platforms

| Dimension | Supported Range |
| :--- | :--- |
| **Local Host OS** | Linux, macOS, Windows |
| **Default Release Targets** | Linux amd64, macOS arm64 (Apple Silicon), Windows amd64 |
| **Remote SSH Targets** | Linux command semantics; direct IP/password connections |
| **Databases** | MySQL 5.7+ / 8.0+, MariaDB 10.3+, PostgreSQL 12+ |

The project is developed with Go `1.26.5` (as pinned in `go.mod`). `ssh-mcp` does not require any cloud accounts, API keys from third-party model providers, nor does it open any public HTTP, TCP, or remote listening ports.

---

## Downloading Prebuilt Releases

You can download prebuilt binaries directly from [GitHub Releases](https://github.com/lswzw/ssh-mcp/releases). The `latest/download` links always resolve to the newest release:

| Platform | Binary Name | Direct Download Link |
| :--- | :--- | :--- |
| **Linux amd64** | `ssh-mcp-linux-amd64` | [`releases/latest/download/ssh-mcp-linux-amd64`](https://github.com/lswzw/ssh-mcp/releases/latest/download/ssh-mcp-linux-amd64) |
| **macOS arm64** | `ssh-mcp-darwin-arm64` | [`releases/latest/download/ssh-mcp-darwin-arm64`](https://github.com/lswzw/ssh-mcp/releases/latest/download/ssh-mcp-darwin-arm64) |
| **Windows amd64** | `ssh-mcp-windows-amd64.exe` | [`releases/latest/download/ssh-mcp-windows-amd64.exe`](https://github.com/lswzw/ssh-mcp/releases/latest/download/ssh-mcp-windows-amd64.exe) |

On Linux and macOS, grant execution permissions after downloading:
```bash
chmod +x ssh-mcp-linux-amd64
mv ssh-mcp-linux-amd64 /usr/local/bin/ssh-mcp # Or your preferred PATH directory
```

---

## Building from Source

To compile manually for your host or cross-compile all official release targets:

```bash
# Compile for current machine (output: bin/ssh-mcp or bin/ssh-mcp.exe)
make build

# Compile all three cross-platform release targets (output: bin/)
make
```

Artifacts will be generated in `bin/`:
- `bin/ssh-mcp-linux-amd64`
- `bin/ssh-mcp-darwin-arm64`
- `bin/ssh-mcp-windows-amd64.exe`

---

## Command Modes & CLI Usage

| Command | Description |
| :--- | :--- |
| `ssh-mcp` | Interactive terminal: launches the local TUI console. Non-interactive pipe: operates as a stdio MCP bridge. |
| `ssh-mcp serve` | Explicit stdio MCP bridge mode used by AI clients (Claude Desktop, Cursor, Codex, etc.). |
| `ssh-mcp manage` | Launches or connects to the daemon and opens the interactive TUI (requires an interactive TTY). |
| `ssh-mcp status` | Displays daemon health, vault lock state, and the count of active MCP bridge sessions. |
| `ssh-mcp stop` | Gracefully shuts down the background daemon (refuses if active client sessions exist). |
| `ssh-mcp stop --force` | Forcibly terminates active sessions and shuts down the daemon after double interactive confirmation (`yes`). |

The local daemon and TUI are managed seamlessly by `serve` and `manage`. Users do not need to manually manage low-level background daemons.

---

## Terminal Launcher Configuration

When an agent requests an action that requires user interaction (such as unlocking the vault), `ssh-mcp` can automatically spawn a terminal window.

By default, `ssh-mcp` attempts to detect your system's default terminal:
- **Linux**: `gnome-terminal`, `x-terminal-emulator`
- **macOS**: Terminal.app (via AppleScript)
- **Windows**: Windows Terminal (`wt`), standard console window

### Overriding via `SSH_MCP_TERMINAL`
If terminal auto-detection fails or you prefer a specific emulator, configure the `SSH_MCP_TERMINAL` environment variable in your client's MCP configuration:

Common shortcuts:
```text
gnome-terminal
x-terminal-emulator
osascript
open
wt
cmd
```

Custom terminal commands must place the `{command}` placeholder exactly once at the end and must **not** contain shell pipes, redirects, or dynamic substitutions:
```text
alacritty -e {command}
kitty --hold {command}
```

> [!IMPORTANT]
> The environment variable is read when the daemon initializes. If a daemon is already running, run `./bin/ssh-mcp stop` first before re-launching your MCP client.

---

## Data & File Locations

All persistent state files are stored in the same directory as the executable binary:

```text
bin/
├── ssh-mcp                 # Executable
├── state.db                # SQLite metadata and encrypted secrets
├── state.db-wal / -shm     # SQLite write-ahead log sidecars
├── audit.log               # Local operational audit log (JSONL)
├── instance.lock           # Daemon single-instance lock file
└── .ssh-mcp-runtime/       # Ephemeral sockets and PID files
```

- **`.ssh-mcp-runtime/`**: Contains ephemeral Unix domain sockets and PID files. It should NOT be backed up or copied.
- **Permissions**: `ssh-mcp` adheres to OS default umask and permissions. Ensure the directory is placed where only trusted local OS users have read/write access.

---

## Upgrades & Uninstallation

### Upgrading
1. Close all active MCP agent/client sessions.
2. Stop the daemon: `./bin/ssh-mcp stop`.
3. Export an encrypted backup using the TUI (`manage` -> `b`), or preserve `state.db` along with its WAL sidecars and rotated `audit.log` archives.
4. Replace the `ssh-mcp` binary with the new version.
5. Restart your MCP client.

### Uninstallation
Removing the MCP registration from your client does not delete the database or credential vault. To completely remove `ssh-mcp`, deregister the server from your client and delete the binary and its accompanying `state.db` and `audit.log` files.
