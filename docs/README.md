# ssh-mcp 文档

这里的文档按“先运行、再配置、再深入”组织。项目首页请看仓库根目录的 [README](../README.md)。

## 推荐阅读路径

1. [快速开始](quickstart.md)：从源码构建、打开 TUI、登记目标并连接 Codex。
2. [使用指南](usage.md)：按排障、文件查看、部署和数据库任务查找示例。
3. [目标配置](configuration.md)：填写 SSH、数据库、TLS 和文件能力配置。
4. [MCP 工具参考](mcp-tools.md)：查看 11 个工具的参数、默认值和返回结果。
5. [日常维护](operations.md)：状态、停止、备份、恢复、锁定和升级。
6. [安全模型与限制](security-model.md)：了解固定拦截、黑名单、凭据和信任边界。

## 其他说明

- [安装与运行](installation.md) 介绍平台、构建产物和命令生命周期。
- [工作原理与架构](architecture.md) 介绍 stdio bridge、daemon、TUI 和远程连接之间的关系。
- [参与贡献](contributing.md) 介绍面向开源贡献者的基本流程。
- [开源发布清单](open-source-release.md) 提供 GitHub Description、Topics 和发布前检查项。

## 能力边界速览

`ssh-mcp` 运行在本地，不提供公网服务。当前本地主机支持 Linux、macOS 和 Windows；远端 SSH 只支持登记的 Linux 目标，目标使用 IP、端口、账号密码和已确认的主机指纹。数据库目标使用 `IP:端口`，支持 MySQL/MariaDB 和 PostgreSQL。

所有远程操作都必须满足：目标已登记并启用、凭据库已解锁，以及请求没有命中固定拦截或目标级限制。MCP 客户端不能新增目标、修改黑名单或读取凭据。
