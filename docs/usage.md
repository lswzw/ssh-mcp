# 使用指南

这篇文档按常见运维任务组织示例。所有示例都假定目标已经在本地 TUI 登记、启用，并且凭据库已经解锁。

## 先确认目标

先让 Codex 调用：

```json
{}
```

对应工具是 `list_targets`。找到目标后，再调用 `describe_target_capability`：

```json
{"target":"203.0.113.10","protocol":"ssh"}
```

这样可以看到该目标支持的操作类别、文件能力和当前 daemon 识别的固定拦截规则。

## 排查 SSH 服务

使用 `run_ssh` 执行单个、完整的非交互命令：

```json
{
  "target":"203.0.113.10",
  "command":"systemctl status example.service --no-pager"
}
```

常见排查命令包括 `uptime`、`free -m`、`df -h`、`ss -lntp` 和服务管理器的状态查询。命令的标准输出、标准错误、退出码和是否截断会在结构化结果中返回。

需要 root 权限时使用 `as_root`：

```json
{
  "target":"203.0.113.10",
  "command":"journalctl -u example.service -n 100 --no-pager",
  "as_root":true
}
```

远端必须允许非交互 `sudo -n`。需要密码提示或 TTY 的命令不能通过 MCP 完成。

## 查看远端配置文件

使用 `read_ssh_file`，不要把文件路径拼进 Shell 命令：

```json
{
  "target":"203.0.113.10",
  "path":"/etc/example/application.yaml",
  "offset":0,
  "max_bytes":16384
}
```

该工具只读取一个普通文件，返回 UTF-8 文本或 Base64 字节。文件能力必须在 TUI 中启用；需要查看更多内容时使用新的 `offset` 请求，并保持每次读取在 64 KiB 上限内。

## 部署并切换文件

使用 `deploy_ssh_binary` 将 daemon 本机上的文件部署到远端已有文件：

```json
{
  "target":"203.0.113.10",
  "source_path":"/srv/builds/example",
  "remote_path":"/srv/example/example",
  "start_action":"systemctl restart example.service"
}
```

部署完成后，结果会返回远端目标、备份路径、上传大小、SHA-256、激活状态和启动状态。若结果为 `outcome_unknown`，先检查 live 文件、备份文件和服务状态，再决定是否重试；不要直接再次覆盖目标。

## 查询数据库

查询数据库时使用 `run_sql`：

```json
{
  "target":"203.0.113.20:5432",
  "database":"example",
  "statement":"SELECT id, status FROM jobs ORDER BY id DESC LIMIT 20"
}
```

`SELECT` 等只读查询使用只读账号。`INSERT`、`UPDATE`、`DELETE`、DDL 或事务等可能写入的语句使用 TUI 中配置的可写账号；没有可写账号时请求会在远端连接前停止。

执行前建议为变更语句写出明确的 `WHERE` 条件，并使用有限的 `max_rows` 和 `max_bytes`。固定高危 SQL 类别不会派发。

## 连续执行相关 SSH 命令

当多个命令需要同一个工作目录或非机密环境变量时，使用工作会话：

```text
open_ssh_session
  target = 203.0.113.10

set_ssh_session_context
  working_directory = /srv/example
  environment = {"APP_ENV":"production"}

execute_ssh_session
  command = ./example --check

close_ssh_session
```

会话只保存声明式上下文，不保存交互 Shell 状态。会话空闲五分钟、目标配置改变或 bridge 关闭后可能失效；失效后重新打开会话即可。

## 处理拒绝和失败

根据返回字段区分三种情况：

1. `not_dispatched`：请求在连接远端前被拒绝，例如目标未启用、文件能力关闭或命中黑名单。
2. `failed_known`：远端已经返回明确失败，例如权限、语法或约束错误。
3. `outcome_unknown`：请求可能已经开始，但连接中断或超时导致结果未知。

固定硬拦截会返回 `rule_id`、`matched_fragment` 和脱敏的 `handoff_command`。目标黑名单命中不会返回交接命令；应由本地用户在 TUI 调整规则后再提交新的请求。对于结果未知的操作，先核验远端状态，不要自动重放。
