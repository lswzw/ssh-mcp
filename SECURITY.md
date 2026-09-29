# Security Policy / 安全问题报告

[English](#security-policy) | [中文说明](#安全问题报告)

---

## Security Policy

We take the security of `ssh-mcp` seriously. Because `ssh-mcp` governs infrastructure access and command execution boundaries, please handle potential vulnerabilities with care.

### Reporting a Vulnerability

- **Do NOT** disclose passwords, private keys, host credentials, or exploitable vulnerability details in public Issues, Discussions, or Pull Requests.
- **Private Reporting**: Please report vulnerabilities confidentially via [GitHub Private Vulnerability Reporting](https://github.com/lswzw/ssh-mcp/security/advisories/new). If this interface is temporarily inaccessible, reach out to the project maintainers directly through their GitHub profiles.
- **Details to Include**: Please specify the affected release version, host operating system, exact reproduction steps, and minimal proof-of-concept evidence.
- For our security architecture, trust boundaries, and built-in guardrails, please consult the [Security Model Guide](docs/en/security-model.md) (or [Chinese version](docs/security-model.md)).

---

## 安全问题报告

请不要在公开 Issue、讨论区或 Pull Request 中发布密码、私钥、主机凭据或可直接利用的漏洞细节。

请优先通过 [GitHub Private Vulnerability Reporting](https://github.com/lswzw/ssh-mcp/security/advisories/new) 私下提交报告；如果该入口暂时不可用，可在仓库主页联系维护者。请提供受影响版本、复现条件和必要的最小证据。一般使用问题请先查看 [安全模型与限制](docs/security-model.md) 和 [日常维护](docs/operations.md)。
