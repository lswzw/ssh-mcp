# 快速开始

本指南适合第一次安装 `ssh-mcp` 的用户。服务需要运行在 MCP Agent/客户端所在的本机上，并通过 stdio 向支持该传输方式的客户端提供 MCP 工具。

## 准备环境

- Linux、macOS 或 Windows 本机。
- Go `1.26.5`，版本以仓库 `go.mod` 为准。
- 已安装并可以配置本地 stdio MCP server 的 Agent/客户端（例如 Codex CLI）。
- 可打开交互终端的桌面环境，用于运行本地 TUI。
- 要管理的远端：Linux SSH 主机，或 MySQL/MariaDB、PostgreSQL 数据库。

SSH 目标当前使用 IP、端口、账号密码和主机指纹；数据库目标使用 `IP:端口`（IPv6 使用方括号，例如 `[2001:db8::10]:5432`）。主机名、SSH 私钥/agent 和远端 Windows/macOS 命令语义不在当前支持范围内。

## 获取程序

有对应发布版本时，优先从 [GitHub Releases](https://github.com/lswzw/ssh-mcp/releases) 下载预编译文件；平台与文件名见 [安装与运行](installation.md#下载预编译版本)。下载后将文件放在稳定路径，Linux/macOS 需要设置执行权限。

如果没有匹配的发布文件，再按下面步骤从源码构建。

在仓库根目录执行：

```bash
make build
```

程序会生成到 `bin/ssh-mcp`；Windows 下文件名为 `bin/ssh-mcp.exe`。需要同时生成项目提供的三个发布目标时执行 `make`，产物位于 `bin/`。

## 打开本地控制台

```bash
./bin/ssh-mcp manage
```

在 TUI 中按以下顺序操作：

1. 按 `u` 设置主密码并解锁本地凭据库。第一次解锁会创建凭据库。
2. 按 `t` 进入目标列表。
3. 按 `n` 新增 SSH 目标，或按 `d` 新增数据库目标。
4. 填写表单并按 `Ctrl+S`。保存前程序会测试连接。
5. SSH 首次连接或指纹变化时，核对指纹后按 `y` 确认；按 `n` 会放弃保存。

保存成功后可按 `Esc` 返回，按 `q` 退出 TUI。目标配置只能在本地 TUI 中修改，MCP 工具不能代替这一步。

## 接入 MCP 客户端

`serve` 使用 stdio MCP。任何能启动本地 stdio MCP server 的 Agent/客户端都可以接入。按客户端的配置格式填写以下通用契约（字段名可能略有不同）：

```text
transport: stdio
command: /absolute/path/to/bin/ssh-mcp
args: ["serve"]
```

其中 `command` 必须是可执行文件的绝对路径；`args` 只需传入 `serve`。客户端配置完成后即可加载 `ssh-mcp` 工具。

### Codex CLI 示例

在仓库根目录执行：

```bash
codex mcp add ssh-mcp -- "$PWD/bin/ssh-mcp" serve
codex mcp get ssh-mcp
```

`serve` 是 stdio MCP bridge。它会在需要时连接或启动本地 daemon，不需要手动启动网络服务。其他客户端请使用其对应的 MCP server 配置或注册命令。

如果 TUI 无法自动打开终端，可先停止已有 daemon，再在客户端配置中指定终端启动器。例如下面仍以 Codex CLI 为例（Linux）：

```bash
./bin/ssh-mcp stop
codex mcp remove ssh-mcp
codex mcp add ssh-mcp \
  --env SSH_MCP_TERMINAL=gnome-terminal \
  -- "$PWD/bin/ssh-mcp" serve
```

macOS 和 Windows 通常可以省略该环境变量，让程序自动选择系统终端。必须先停止已有 daemon，新的 `SSH_MCP_TERMINAL` 才会在下次启动时生效。完整规则见 [安装与运行](installation.md)。

## 发起第一次请求

在所用 MCP Agent/客户端的任务中明确要求使用 `ssh-mcp`：

```text
使用 ssh-mcp 查看已登记 SSH 主机的内存和磁盘使用情况。
```

建议让 Agent 先调用 `list_targets` 和 `describe_target_capability`，确认目标和能力后再执行操作。工具调用必须使用与 schema 一致的 JSON 对象，例如：

```json
{"target":"203.0.113.10","command":"free -m"}
```

## 验证与停止

```bash
./bin/ssh-mcp status
./bin/ssh-mcp stop
```

有活动 MCP bridge 会话时，普通 `stop` 会拒绝停止。确认要中断所有客户端会话时，在交互终端执行：

```bash
./bin/ssh-mcp stop --force
```

该命令要求连续两次输入 `yes`。停止服务不会删除本地目标和凭据。

## 常见问题

| 现象 | 处理方式 |
| --- | --- |
| 返回 `unlock_required` | 在本地 TUI 按 `u` 解锁后重新调用工具。 |
| 返回目标未找到 | 在 TUI 新增目标并完成连接验证；MCP 不会自动登记目标。 |
| SSH 指纹变化 | 停止使用该目标，确认远端主机身份后在 TUI 重新验证并保存。 |
| 数据库写操作被拒绝 | 为该数据库目标填写可写账号；与只读账号相同可以复用只读密码。 |
| TUI 没有打开 | 检查桌面终端，或设置 `SSH_MCP_TERMINAL` 后重新注册 MCP。 |
