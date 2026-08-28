# 安装与运行

## 支持平台

| 项目 | 支持范围 |
| --- | --- |
| 本地主机 | Linux、macOS、Windows |
| 默认发布目标 | Linux amd64、macOS arm64、Windows amd64 |
| 远端 SSH | Linux 命令语义；使用登记的 IP 和密码直连 |
| 数据库 | MySQL/MariaDB、PostgreSQL |

Go 版本使用仓库 `go.mod` 声明的 `1.26.5`。程序不需要云端或特定模型提供商的 API key，也不监听 HTTP、TCP 或其他公网服务端口。

## 下载预编译版本

发布后可从 [GitHub Releases](https://github.com/lswzw/ssh-mcp/releases) 下载与本机平台匹配的资产。`latest/download` 链接会指向最新发布版本：

| 平台 | 文件 | 直接下载 |
| --- | --- | --- |
| Linux amd64 | `ssh-mcp-linux-amd64` | [`releases/latest/download/ssh-mcp-linux-amd64`](https://github.com/lswzw/ssh-mcp/releases/latest/download/ssh-mcp-linux-amd64) |
| macOS arm64 | `ssh-mcp-darwin-arm64` | [`releases/latest/download/ssh-mcp-darwin-arm64`](https://github.com/lswzw/ssh-mcp/releases/latest/download/ssh-mcp-darwin-arm64) |
| Windows amd64 | `ssh-mcp-windows-amd64.exe` | [`releases/latest/download/ssh-mcp-windows-amd64.exe`](https://github.com/lswzw/ssh-mcp/releases/latest/download/ssh-mcp-windows-amd64.exe) |

下载后请确认文件来自项目发布页，并在注册 MCP 前验证文件能正常启动。Linux/macOS 需要为文件设置执行权限；其他 CPU 架构目前请从源码构建。

## 构建

```bash
# 当前本机程序
make build

# 三个发布目标
make
```

本机程序位于 `bin/ssh-mcp`（Windows 为 `bin/ssh-mcp.exe`）。跨平台发布文件为：

- `bin/ssh-mcp-linux-amd64`
- `bin/ssh-mcp-darwin-arm64`
- `bin/ssh-mcp-windows-amd64.exe`

## 命令模式

| 命令 | 用途 |
| --- | --- |
| `ssh-mcp` | 在交互终端中进入本地管理；非交互环境中作为 stdio MCP 服务运行。 |
| `ssh-mcp serve` | 为支持 stdio 的 MCP 客户端提供 bridge。 |
| `ssh-mcp manage` | 连接或启动 daemon 并打开本地 TUI；必须在交互终端运行。 |
| `ssh-mcp status` | 显示 daemon 是否运行、凭据库锁定状态和活动 bridge 数量。 |
| `ssh-mcp stop` | 在没有活动会话时停止 daemon。 |
| `ssh-mcp stop --force` | 经过两次交互确认后中断活动会话并停止 daemon。 |

后台 daemon 和本地 TUI 由 `serve` 与 `manage` 自动管理，普通用户不需要手动启动内部生命周期入口。

## TUI 终端启动器

程序会按系统尝试以下终端：Linux 的 `gnome-terminal` 或 `x-terminal-emulator`，macOS 的 Terminal，Windows 的 Windows Terminal 或新控制台窗口。

终端选择异常时可设置 `SSH_MCP_TERMINAL`。常用简写包括：

```text
gnome-terminal
x-terminal-emulator
osascript
open
wt
cmd
```

自定义启动器必须在配置末尾包含一次 `{command}`，且配置不能包含 shell 管道、重定向或命令替换字符。例如：

```text
my-terminal --profile ops {command}
```

设置后先结束使用该 bridge 的活动 MCP 客户端会话并执行 `./bin/ssh-mcp stop`，再按所用客户端重新加载或注册 MCP server。以 Codex CLI 为例，可执行 `codex mcp remove ssh-mcp` 和 `codex mcp add ...`。该环境变量由 daemon 启动时读取；仅重新加载客户端配置不会更新已经运行的 daemon。

## 文件位置

状态和审计文件位于可执行文件同目录：

```text
state.db
audit.log
instance.lock
.ssh-mcp-runtime/
```

`.ssh-mcp-runtime/` 只保存 socket、PID 等可重建运行时文件，不作为备份内容复制。迁移优先使用 TUI 创建的加密备份；若必须手工复制，先停止 daemon，确保 SQLite 的 `state.db-wal`/`state.db-shm` 已合并或一并处理，并复制全部 `audit.log` 轮转归档，再在新路径按客户端重新注册或加载 MCP server。程序沿用操作系统默认文件权限和 umask；请把整个安装目录放在只有受信任本地用户可访问的位置。

## 更新与卸载

更新程序前：

1. 结束使用该 MCP server 的活动客户端会话。
2. 执行 `./bin/ssh-mcp stop`。
3. 替换程序并从加密备份恢复；手工迁移时仅在 daemon 停止后处理 `state.db` 及其 WAL sidecar，并一并保留全部 `audit.log` 轮转归档。
4. 重新启动 MCP 客户端；如程序路径改变，按客户端方式重新注册 MCP。

移除客户端中的 MCP 注册不会删除本地凭据库。下面是 Codex CLI 的移除示例：

```bash
codex mcp remove ssh-mcp
```
