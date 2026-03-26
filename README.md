# Claw Guard Server Skill

[简体中文](README.zh-CN.md)

This skill helps agents perform secure skill-hash verification and guard/report API calls with raw HTTP.

## What This Skill Can Do

- Compute `skill_scan_artifacts.manifestHash` locally with a deterministic manifest-hash algorithm.
- Query `POST /v1/guard/skill-hash` to check server-side status for a known manifest hash.
- Run pre-action policy checks with `POST /v1/guard/evaluate` (`allow`, `warn`, `block`).
- Record post-action audit logs with `POST /v1/guard/events`.
- Report hash or zip samples with:
  - `POST /v1/skill-report/upload-hash`
  - `POST /v1/skill-report/upload-file`
- Use raw HTTP only, with examples for both `curl` (macOS/Linux) and PowerShell (Windows).

## Security Notes

- This skill is for verification and evidence collection, not automatic trust.
- If a hash is unknown or response signals ambiguity, require manual confirmation.
- `upload-hash`, `upload-file`, and `guard/events` are reporting/logging routes, not verdict routes.

## Installation

```bash
openclaw skills install Claw_Guard
```


## Compatible Agents

This skill is compatible with agents that can:

- Load `SKILL.md`-based skills.
- Run shell commands (`curl` on macOS/Linux or PowerShell on Windows).
- Send raw HTTP requests to external APIs.

Typical compatible environments include:

- OpenClaw
- NanoBot
- CoPaw
- LobsterAI
- NanoClaw
- NullClaw
