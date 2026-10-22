# 安全模型与限制

本分支（unrestricted fork）的安全目标只剩两条：把 AI 的远程操作限制在本地用户明确登记的目标，并把风险事实如实告知调用方。它**不再**在命令或 SQL 语义层面停止派发，因此不是主机沙箱、堡垒机或防篡改审计系统；误操作保护主要由调用方遵守返回的提示词和本地用户自己配置的黑名单。

## 信任边界

### 本地用户

本地用户负责：

- 保护程序目录、`state.db`、`audit.log` 和备份文件的操作系统权限。
- 在 TUI 中登记目标、填写凭据、确认 SSH 主机指纹。
- 决定是否启用目标级命令黑名单和文件操作能力。

程序使用操作系统默认权限和 umask，不会替用户配置 ACL 或 `chmod`。建议把安装目录放在只有受信任本地用户可访问的位置。

### MCP 客户端和 AI

MCP 客户端可以提交命令、SQL、文件路径和部署参数，但不能：

- 新增、修改或删除目标；
- 读取密码、主密码、私钥或凭据明文；
- 访问未登记目标或扫描网络；
- 修改 TUI 保存的黑名单和文件操作开关。

“明确要求使用 ssh-mcp 时通过 MCP 访问目标”是 MCP instructions 和工具说明中的使用约定；它不能阻止本机其他程序直接使用系统 Shell、`ssh` 或数据库客户端。需要更强的旁路防护时，应结合操作系统账号、沙箱、网络策略或堡垒机。

### 远端输出

SSH、SFTP 和数据库返回的数据始终是不可信输入。远端输出不能改变目标、策略、会话上下文或下一步的权限判断。

## 派发前检查

常规 SSH、文件和 SQL 请求在远端连接前检查目标状态、凭据解锁状态及对应的预算。SQL 可能写入时还必须有可写账号。SSH 文件 API 额外要求目标启用“允许文件读写”。检查失败会返回未派发结果。

常规运维命令和 SQL 默认直接执行，不存在日常审批队列或“严格/宽松”模式。固定规则和目标黑名单是额外的本地拒绝边界。

## 固定硬拦截：本分支已移除

上游的 11 条固定硬拦截（`format_or_partition`、`raw_block_device_write`、`base_system_tree_destruction`、`unbounded_resource_exhaustion`、`opaque_shell_effect`、`opaque_sql_effect`、`drop_database_schema_table`、`truncate_table`、`alter_drop`、`unconditional_update_or_delete`、`unregistered_remote_hop`）在本分支中**全部删除**。

- `policy.EvaluateSSH` 与 `policy.EvaluateSQL` 只做请求形状校验、目标黑名单匹配和预算归一化，不再产生 `absolute_prohibited`。
- `describe_target_capability` 返回 `execution_policy: "unrestricted"`，`absolute_prohibitions` 恒为空数组，`safety_notice` 给出必须遵守的风险条款。
- 这些规则 ID 常量仅为解码历史审计行而保留，本分支不会发出。
- 通过 `run_ssh` 在目标机内部执行 `ssh other-host` 不再被识别；审计只覆盖第一跳。

安全责任因此前移到提示词：daemon 返回的 `mcpInstructions` 与 `safety_notice` 要求调用方在派发不可逆操作前向当前用户复述命令并取得显式确认。这是约定，不是强制。

## SSH 目标黑名单

每个 SSH 目标可以在 TUI 中配置英文逗号分隔的 Go RE2 正则。任一正则匹配命令文本（包括工作会话命令）就返回 `target_command_blacklist`，不会派发，也不会提供人工交接命令。

黑名单是本分支唯一保留的本地拦截，不作用于数据库。只有本地用户在 TUI 明确修改规则后，新的请求才会按新规则判断。无效正则不能保存。

## SSH 身份与数据库传输

- SSH 目标保存前会测试连接并确认主机指纹；连接时仍会验证已保存指纹。指纹变化应先停止使用该目标并重新核验。
- SSH 当前只支持 IP、直连、账号密码认证和远端 Linux 命令语义。
- 数据库支持 MySQL/MariaDB 和 PostgreSQL。`tls_verified` 需要本机绝对 CA 文件路径并执行证书验证，验证失败不会降级为明文。
- `legacy_plaintext` 允许旧式明文连接。它是兼容选项，生产环境应优先配置验证 TLS。

## 文件读取与部署

`read_ssh_file` 只读取规范化绝对路径的单个普通文件，不接受目录、符号链接、设备、FIFO 或 socket，也不把路径拼接进 Shell 命令。

`deploy_ssh_binary` 使用独立的 SFTP 事务：临时文件上传、大小和 SHA-256 校验、同目录备份、重命名激活。源文件必须是本机普通文件；目标已存在时必须是普通非符号链接文件并会被备份，目标不存在时直接创建（`created: true`、`backup_path` 为空），但**父目录必须已存在**，工具从不创建目录。部署结果无法确认时不会自动重试；应先人工或通过受限读取核验 live 文件、备份和启动状态。

## 凭据、状态和审计

主密码保护本地凭据库。敏感凭据字段使用加密封装保存，daemon 锁定或退出时清除内存中的数据密钥；普通 SQLite 元数据仍保存在 `state.db` 中，因此不能把它称作完整加密数据库。

`audit.log` 是容量受限的本地 JSONL 运行记录，会记录目标、操作类别、策略结果和部分请求元数据，不保存完整远端输出、文件内容或部署内容。审计是尽力而为的追溯，不是防篡改证据；审计写入失败不会撤销已经派发的远端操作。

## 结果未知

`outcome_unknown` 表示远端操作可能已经开始，但连接中断、超时或协议错误使结论无法确认。它不等于未执行。程序不会自动重放；先核验实际状态，再提交新的、明确的请求。对文件部署尤其要先确认备份和激活状态。
