# Claw Guard Server 技能

此技能可帮助代理使用原始 HTTP 完成安全的技能哈希校验，以及 guard/report API 调用。

## 这个技能能做什么

- 使用确定性的 manifest-hash 算法，在本地计算 `skill_scan_artifacts.manifestHash`。
- 调用 `POST /v1/guard/skill-hash`，查询某个已知 manifest hash 的服务端状态。
- 通过 `POST /v1/guard/evaluate` 做执行前策略判断（`allow`、`warn`、`block`）。
- 通过 `POST /v1/guard/events` 记录执行后的审计事件。
- 通过以下接口上报 hash 或 zip 样本：
  - `POST /v1/skill-report/upload-hash`
  - `POST /v1/skill-report/upload-file`
- 全流程使用原始 HTTP，提供 `curl`（macOS/Linux）和 PowerShell（Windows）示例。

## 安全说明

- 该技能用于校验与证据收集，不等于自动信任。
- 遇到未知 hash 或响应含糊不清时，应要求人工确认。
- `upload-hash`、`upload-file`、`guard/events` 仅用于上报/记录，不是判定结果接口。

## 安装

```bash
openclaw skills install Claw_Guard
```

## 兼容代理

此技能兼容满足以下条件的代理：

- 能加载基于 `SKILL.md` 的技能。
- 能运行 shell 命令（macOS/Linux 使用 `curl`，Windows 使用 PowerShell）。
- 能向外部 API 发送原始 HTTP 请求。

典型的兼容环境包括：

- OpenClaw
- NanoBot
- CoPaw
- LobsterAI
- NanoClaw
- NullClaw
