# 开源发布清单

这份清单用于发布到 GitHub 前的最后检查。它不会改变程序行为，但能让用户和搜索引擎更容易理解项目。

## 仓库信息

建议将 GitHub 仓库 Description 设置为：

```text
Local SSH MCP server for Codex CLI: run commands and SQL, inspect files, and deploy safely through registered targets.
```

建议 Topics（使用 GitHub 支持的短词）：

```text
mcp
model-context-protocol
codex-cli
ssh
devops
remote-operations
mysql
postgresql
golang
```

README 的第一段应保持项目名称、用途、支持范围和许可证清晰可见。不要使用与实际能力不符的关键词，例如 Kubernetes、SSH 私钥认证或云端托管服务。

## 发布前检查

- 根目录存在 `README.md`、`LICENSE`、`CONTRIBUTING.md` 和 `SECURITY.md`。
- README 中的截图来自脱敏环境，`docs/assets/` 中的路径可访问。
- 快速开始命令能在干净环境中执行，且 Codex MCP 注册路径正确。
- 文档中的工具名称、参数、默认值和平台范围与当前版本一致。
- 不提交 `state.db`、`audit.log`、备份文件、主密码、SSH 密码或私钥。
- 远程目标、数据库连接和 TLS 配置使用示例地址，不使用生产数据。
- 在 GitHub 仓库设置中选择 GPL-3.0 License，并检查默认分支的许可证识别结果。

## 维护建议

发布后，优先维护根目录 README、[快速开始](quickstart.md) 和 [MCP 工具参考](mcp-tools.md)。每次增加工具或改变参数时，同步更新这三处和安全模型文档。搜索引擎通常需要时间重新抓取页面，无法由 README 保证固定排名。
