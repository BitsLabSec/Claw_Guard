---
name: claw_guard_server
description: Use when the agent needs to compute a skill manifest hash locally or call Claw Guard Server endpoints with raw HTTP (curl/PowerShell) for skill hash lookup, pre-action policy decisions, audit events, and skill hash/file reporting.
---

# Claw Guard Server

Use this skill for two security workflows:

- Perform skill hash lookup and reporting.
- Perform pre-execution guard checks and post-execution audit logging.

Keep this skill self-contained. Use raw HTTP only. Do not depend on project-specific Node.js CLIs.

## Core Security Stance

Treat this skill as evidence gathering, not as an auto-approval system.

- Treat unknown origin, unknown hash, missing records, incomplete responses, or ambiguous responses as suspicious until confirmed.
- Treat `matched = false` as "no record found," not "safe."
- Treat `decision = allow` as "currently allowed by policy," not "permanently trusted."
- Never downplay `warn`, `block`, or `manual_confirmation_required`.
- Do not skip checks just because the user is in a hurry.

## Endpoint Coverage

This skill covers the following endpoints:

- `POST /v1/guard/skill-hash`
- `POST /v1/guard/evaluate`
- `POST /v1/guard/events`
- `POST /v1/skill-report/upload-hash`
- `POST /v1/skill-report/upload-file`

Endpoint responsibilities:

- `skill-hash`: Query existing server-side scan status for a known manifest hash.
- `guard-evaluate`: Request a policy decision before the action runs.
- `guard-events`: Record audit events after the action runs.
- `report-hash`: Report a hash as `safe` or `unsafe`.
- `report-file`: Upload a skill zip sample and report it as `safe` or `unsafe`.

## Global Rules

- Default base URL: `https://api.clawguard.cc`
- Replace the base URL only if the user explicitly provides a different endpoint.
- Compute the hash strictly using the manifest-hash algorithm in this skill.
- Never send `scanProfileHash` as the skill hash.
- Never send the zip file byte-stream SHA256 as the skill hash.
- `upload-file` accepts only zip artifacts.
- `upload-hash` and `upload-file` report data only; they are not verdict endpoints.
- `guard/events` records events only; it is not a verdict endpoint.

## Hash Semantics

For skill verification and reporting, the hash must be:

- `skill_scan_artifacts.manifestHash`

Do not use:

- Zip file hash
- Single-file hash

## Manifest Hash Algorithm

Follow this algorithm exactly:

1. Recursively enumerate regular files inside the skill directory.
2. Skip paths under:
   - `.git`
   - `node_modules`
   - `__MACOSX`
3. For each file, collect:
   - Relative path (normalized to `/`)
   - Content hash as `sha256:<64-hex>`
   - File size in bytes
   - `contentKind`
4. Determine `contentKind`:
   - If file size is greater than `1048576`: `unknown`
   - Else if file size is `0`: `text`
   - Else if sampled content contains `NUL` byte: `binary`
   - Else: `text`
5. Sort rows by relative path.
6. Format each row as:
   - `<relativePath>\t<fileHash>\t<sizeBytes>\t<contentKind>`
7. Join rows with `\n`.
8. Compute SHA256 of the final manifest string.
9. Return `sha256:<64-hex>`.

## Local Hash Example (macOS / Linux)

```bash
SKILL_ROOT="./demo-skill"

MANIFEST_HASH="$(
  find "$SKILL_ROOT" \
    \( -path '*/.git/*' -o -path '*/node_modules/*' -o -path '*/__MACOSX/*' \) -prune \
    -o -type f -print \
  | LC_ALL=C sort \
  | while IFS= read -r file; do
      rel="${file#"$SKILL_ROOT"/}"
      file_hash="sha256:$(shasum -a 256 "$file" | awk '{print $1}')"
      size_bytes="$(wc -c < "$file" | tr -d ' ')"

      if [ "$size_bytes" -gt 1048576 ]; then
        content_kind="unknown"
      elif [ "$size_bytes" -eq 0 ]; then
        content_kind="text"
      elif LC_ALL=C grep -Iq . "$file"; then
        content_kind="text"
      else
        content_kind="binary"
      fi

      printf '%s\t%s\t%s\t%s\n' "$rel" "$file_hash" "$size_bytes" "$content_kind"
    done \
  | { shasum -a 256 | awk '{print "sha256:" $1}'; }
)"

printf '%s\n' "$MANIFEST_HASH"
```

## Local Hash Example (PowerShell)

```powershell
function Get-SkillManifestHash {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SkillRoot
  )

  $root = (Resolve-Path $SkillRoot).Path
  $files = Get-ChildItem -Path $root -Recurse -File | Where-Object {
    $_.FullName -notmatch '[\\/]\.git[\\/]' -and
    $_.FullName -notmatch '[\\/]node_modules[\\/]' -and
    $_.FullName -notmatch '[\\/]__MACOSX[\\/]'
  } | Sort-Object {
    $_.FullName.Substring($root.Length).TrimStart('\','/') -replace '\\','/'
  }

  $manifestLines = foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($root.Length).TrimStart('\','/') -replace '\\','/'
    $fileHash = "sha256:$((Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash.ToLower())"
    $sizeBytes = [int64]$file.Length

    if ($sizeBytes -gt 1048576) {
      $contentKind = "unknown"
    } elseif ($sizeBytes -eq 0) {
      $contentKind = "text"
    } else {
      $stream = [System.IO.File]::OpenRead($file.FullName)
      try {
        $sampleLength = [Math]::Min([int64]8000, $sizeBytes)
        $buffer = New-Object byte[] $sampleLength
        [void]$stream.Read($buffer, 0, $sampleLength)
        if ($buffer[0..($sampleLength - 1)] -contains 0) {
          $contentKind = "binary"
        } else {
          $contentKind = "text"
        }
      } finally {
        $stream.Dispose()
      }
    }

    "$relativePath`t$fileHash`t$sizeBytes`t$contentKind"
  }

  $manifest = [string]::Join("`n", $manifestLines)
  $manifestBytes = [System.Text.Encoding]::UTF8.GetBytes($manifest)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $digest = $sha.ComputeHash($manifestBytes)
  } finally {
    $sha.Dispose()
  }

  "sha256:{0}" -f ([System.BitConverter]::ToString($digest).Replace("-", "").ToLower())
}

$Hash = Get-SkillManifestHash -SkillRoot ".\demo-skill"
$Hash
```

## `POST /v1/guard/skill-hash`

Use this route when:

- The manifest hash is already known.
- You need server-side status for that hash.

### curl

```bash
BASE_URL="https://api.clawguard.cc"
HASH="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

curl -X POST "$BASE_URL/v1/guard/skill-hash" \
  -H 'Content-Type: application/json' \
  --data "{
    \"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"pluginId\":\"lobster-local\",
    \"source\":\"before_tool_call\",
    \"action\":\"skill_install\",
    \"hashAlgorithm\":\"sha256\",
    \"hash\":\"$HASH\",
    \"artifactType\":\"directory\",
    \"artifactName\":\"demo-skill\",
    \"instruction\":\"openclaw skills install ./demo-skill\",
    \"labels\":[\"skill_install\",\"skill_hash_lookup\"]
  }"
```

### PowerShell

```powershell
$BaseUrl = "https://api.clawguard.cc"
$Hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
$Headers = @{ "Content-Type" = "application/json" }

$Body = @{
  ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  pluginId = "lobster-local"
  source = "before_tool_call"
  action = "skill_install"
  hashAlgorithm = "sha256"
  hash = $Hash
  artifactType = "directory"
  artifactName = "demo-skill"
  instruction = "openclaw skills install ./demo-skill"
  labels = @("skill_install", "skill_hash_lookup")
} | ConvertTo-Json -Depth 6

Invoke-RestMethod \
  -Method Post \
  -Uri "$BaseUrl/v1/guard/skill-hash" \
  -Headers $Headers \
  -Body $Body
```

### Result Handling

- `matched = true` and `decision = allow`
  - A currently allow-listed record exists.
  - Continue risk checks if source, install flow, or behavior is unusual.
- `matched = true` and `decision = warn`
  - A record exists, but explicit user confirmation is still required.
- `matched = true` and `decision = block`
  - A record exists and action must not proceed.
- `matched = false`
  - No server record exists for this hash.
  - Treat as `manual_confirmation_required` and require explicit user confirmation.

## `POST /v1/guard/evaluate`

Use this route when:

- The action has not run yet.
- You need a policy decision (`allow | warn | block`) before execution.

### curl

```bash
BASE_URL="https://api.clawguard.cc"

curl -X POST "$BASE_URL/v1/guard/evaluate" \
  -H 'Content-Type: application/json' \
  --data "{
    \"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"pluginId\":\"lobster-local\",
    \"mode\":\"enforce\",
    \"event\":{
      \"kind\":\"command\",
      \"source\":\"before_tool_call\",
      \"instruction\":\"openclaw skills install ./demo-skill\",
      \"labels\":[\"skill_install\"]
    }
  }"
```

### PowerShell

```powershell
$BaseUrl = "https://api.clawguard.cc"
$Headers = @{ "Content-Type" = "application/json" }

$Body = @{
  ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  pluginId = "lobster-local"
  mode = "enforce"
  event = @{
    kind = "command"
    source = "before_tool_call"
    instruction = "openclaw skills install ./demo-skill"
    labels = @("skill_install")
  }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod \
  -Method Post \
  -Uri "$BaseUrl/v1/guard/evaluate" \
  -Headers $Headers \
  -Body $Body
```

### Result Handling

- `allow`
  - Policy currently allows the action.
  - Continue deeper checks when the target is still suspicious.
- `warn`
  - Pause and explain risk before any execution.
- `block`
  - Do not execute unless the user explicitly requests an override path.

## `POST /v1/guard/events`

Use this route when:

- The action already happened.
- You only need to record an audit event.

Use the same body shape as `guard/evaluate`, typically with:

- `mode = audit`
- `event.source = after_tool_call`

### curl

```bash
BASE_URL="https://api.clawguard.cc"

curl -X POST "$BASE_URL/v1/guard/events" \
  -H 'Content-Type: application/json' \
  --data "{
    \"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"pluginId\":\"lobster-local\",
    \"mode\":\"audit\",
    \"event\":{
      \"kind\":\"command\",
      \"source\":\"after_tool_call\",
      \"instruction\":\"openclaw skills install ./demo-skill\",
      \"labels\":[\"skill_install\"]
    }
  }"
```

### PowerShell

```powershell
$BaseUrl = "https://api.clawguard.cc"
$Headers = @{ "Content-Type" = "application/json" }

$Body = @{
  ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  pluginId = "lobster-local"
  mode = "audit"
  event = @{
    kind = "command"
    source = "after_tool_call"
    instruction = "openclaw skills install ./demo-skill"
    labels = @("skill_install")
  }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod \
  -Method Post \
  -Uri "$BaseUrl/v1/guard/events" \
  -Headers $Headers \
  -Body $Body
```

## `POST /v1/skill-report/upload-hash`

Use this route when:

- The user explicitly wants to report a hash as `safe` or `unsafe`.
- You do not need a verdict in this call.

### curl

```bash
BASE_URL="https://api.clawguard.cc"
HASH="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

curl -X POST "$BASE_URL/v1/skill-report/upload-hash" \
  -H 'Content-Type: application/json' \
  --data "{
    \"uuid\":\"report-uuid-1\",
    \"hash\":\"$HASH\",
    \"reportedStatus\":\"unsafe\"
  }"
```

### PowerShell

```powershell
$BaseUrl = "https://api.clawguard.cc"
$Hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
$Headers = @{ "Content-Type" = "application/json" }

$Body = @{
  uuid = "report-uuid-1"
  hash = $Hash
  reportedStatus = "unsafe"
} | ConvertTo-Json -Depth 6

Invoke-RestMethod \
  -Method Post \
  -Uri "$BaseUrl/v1/skill-report/upload-hash" \
  -Headers $Headers \
  -Body $Body
```

## `POST /v1/skill-report/upload-file`

Use this route when:

- The user explicitly wants to upload a zip sample and report it as `safe` or `unsafe`.
- You do not need a verdict in this call.

Request fields:

- `uuid`
- `reportedStatus`
- `artifact` (zip file)

### curl

```bash
BASE_URL="https://api.clawguard.cc"
ZIP_PATH="/absolute/path/to/skill.zip"

curl -X POST "$BASE_URL/v1/skill-report/upload-file" \
  -F "uuid=report-uuid-2" \
  -F "reportedStatus=unsafe" \
  -F "artifact=@$ZIP_PATH"
```

### PowerShell (7+)

```powershell
$BaseUrl = "https://api.clawguard.cc"

$Form = @{
  uuid = "report-uuid-2"
  reportedStatus = "unsafe"
  artifact = Get-Item ".\\skill.zip"
}

Invoke-RestMethod \
  -Method Post \
  -Uri "$BaseUrl/v1/skill-report/upload-file" \
  -Form $Form
```

## Suggested Route Selection

- Known manifest hash, need status lookup:
  - Use `skill-hash`.
- Action not yet executed, need pre-check policy:
  - Use `guard-evaluate`.
- Action already executed, need audit logging:
  - Use `guard-events`.
- User explicitly wants to report a hash:
  - Use `upload-hash`.
- User explicitly wants to report a zip sample:
  - Use `upload-file`.

## Hard Rules

- Do not call project-provided Node.js CLIs from this skill.
- Do not send `scanProfileHash` to `skill-hash`.
- Do not send zip byte-stream hashes to `skill-hash` or `upload-hash`.
- Treat this skill as verification guidance, never unconditional endorsement.
- Treat `guard-events` as logging only, never as a verdict source.
- Treat `upload-hash` and `upload-file` as reporting only, never as verdict sources.
- If `skill-hash` has no record, require explicit manual confirmation.
- If `guard-evaluate` returns `block`, do not execute the target action.
