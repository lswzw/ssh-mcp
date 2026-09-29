# Quickstart Guide

[English](quickstart.md) | [中文说明](../quickstart.md)

This guide walks you through setting up `ssh-mcp` for the first time. The service runs locally on the machine hosting your AI Agent or MCP client, serving tools over the standard `stdio` transport.

---

## Prerequisites

- **Local Machine**: Linux, macOS, or Windows.
- **Go**: `1.26.5` or later (required only if building from source, as pinned in `go.mod`).
- **MCP Client**: Any agent or client supporting local stdio MCP servers (e.g., Claude Desktop, Cursor, Codex CLI, Cline, Windsurf).
- **Interactive Terminal**: An interactive terminal environment capable of running the local TUI console.
- **Remote Targets**: Remote Linux SSH hosts (IPv4/IPv6), or MySQL/MariaDB and PostgreSQL database instances.

> [!NOTE]
> SSH targets currently use IP addresses, SSH ports, password authentication, and pinned host key fingerprints. Database targets use `IP:Port` notation (e.g., `[2001:db8::10]:5432` for IPv6). Hostnames, SSH private keys/agents, and remote Windows/macOS execution semantics are outside the current scope.

---

## 1. Get the Binary

### Option A: Download Prebuilt Releases (Recommended)
Download the binary matching your platform and architecture from [GitHub Releases](https://github.com/lswzw/ssh-mcp/releases/latest). Place it in a stable directory (e.g., `~/.local/bin` or within your project directory). On Linux/macOS, ensure the executable permission is set:
```bash
chmod +x ./bin/ssh-mcp
```

### Option B: Build from Source
If no prebuilt release matches your platform, compile from the repository root:
```bash
git clone https://github.com/lswzw/ssh-mcp.git
cd ssh-mcp
make build
```
The compiled executable will be located at `bin/ssh-mcp` (or `bin/ssh-mcp.exe` on Windows).

---

## 2. Initialize the Vault & Register Targets (TUI)

Before your AI agent can perform operations, you must initialize the local encrypted vault and register your infrastructure targets:

```bash
./bin/ssh-mcp manage
```

In the interactive TUI console, follow these steps:

1. **Unlock/Initialize Vault**: Press `u` to set your master password and initialize the credential vault. (On first run, this creates the local SQLite metadata database and encrypted key container).
2. **Toggle Language (Optional)**: Press `e` on the dashboard to toggle between English and Chinese interface language. Your preference is automatically persisted in the local database.
3. **Open Targets List**: Press `t` to view targets.
4. **Add Target**: Press `n` to add an SSH host, or `d` to add a database target.
5. **Input Details & Save**: Fill in the target IP, port, and credentials, then press `Ctrl+S`. `ssh-mcp` will test the connection immediately.
6. **Pin Host Fingerprint (SSH)**: On the first connection to an SSH host, review the displayed fingerprint and press `y` to confirm and pin it.
7. **Exit Console**: Press `Esc` to return and `q` to quit the TUI.

> [!IMPORTANT]
> Target credentials and host keys can **only** be configured via the local TUI. The MCP client and AI agents have no administrative ability to register, alter, or delete targets.

---

## 3. Connect to MCP Clients

`ssh-mcp serve` functions as a stdio MCP bridge. It connects to or automatically spawns the local background daemon on demand.

### Universal Stdio Contract
- **Transport**: `stdio`
- **Command**: `/absolute/path/to/bin/ssh-mcp`
- **Arguments**: `["serve"]`

### Configuration Examples

#### Claude Desktop
Add `ssh-mcp` to your `claude_desktop_config.json`:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "/absolute/path/to/bin/ssh-mcp",
      "args": ["serve"]
    }
  }
}
```

#### Cursor / VS Code (Cline, Roo Code)
Add to your client's MCP configuration file or UI:
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "/absolute/path/to/bin/ssh-mcp",
      "args": ["serve"]
    }
  }
}
```

#### Codex CLI
In the repository root or your working terminal, run:
```bash
codex mcp add ssh-mcp -- "$PWD/bin/ssh-mcp" serve
codex mcp get ssh-mcp
```

### Specifying Terminal Launcher (Optional)
If your agent triggers a workflow requiring an interactive terminal (e.g., prompt for unlocking), you can configure the terminal launcher via an environment variable:
```bash
# Example for GNOME Terminal on Linux:
codex mcp remove ssh-mcp
codex mcp add ssh-mcp \
  --env SSH_MCP_TERMINAL=gnome-terminal \
  -- "$PWD/bin/ssh-mcp" serve
```
*(macOS and Windows typically select the native terminal emulator automatically. Ensure you stop any running daemon before changes take effect).*

---

## 4. Issue Your First Request

Prompt your AI Agent to operate through `ssh-mcp`:

```text
Use ssh-mcp to check the free memory and disk space across my registered SSH hosts.
```

The agent will first call `list_targets` and `describe_target_capability` to verify access permissions, followed by:

```json
{
  "target": "203.0.113.10",
  "command": "free -m"
}
```

---

## 5. Daemon Verification & Shutdown

Check daemon health and active bridge sessions:
```bash
./bin/ssh-mcp status
```

Gracefully stop the daemon:
```bash
./bin/ssh-mcp stop
```

If there are active MCP client connections, normal `stop` will refuse to terminate. To forcibly disconnect all sessions, run:
```bash
./bin/ssh-mcp stop --force
```
*(Requires typing `yes` twice in an interactive terminal. Stopping the daemon never deletes targets or stored credentials).*

---

## Troubleshooting FAQ

| Problem | Cause / Solution |
| :--- | :--- |
| **`unlock_required` error** | The vault is locked. Run `./bin/ssh-mcp manage`, press `u`, and enter your master password. |
| **`Target not found` error** | The target is unregistered or disabled. Register it via the TUI console; MCP tools cannot auto-discover unwhitelisted hosts. |
| **SSH Host Fingerprint Changed** | Security protection against MITM. Stop operations, verify the remote host identity, and re-confirm the fingerprint in the TUI. |
| **Database Write Denied** | The target is configured in read-only mode. Configure a writable database user in the TUI. |
| **TUI fails to pop up automatically** | Check your desktop terminal configuration or specify `SSH_MCP_TERMINAL` in the MCP environment. |
