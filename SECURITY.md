# Security Policy

Caspian Security is itself a security tool — so its own posture has to be
exemplary. This document describes how to report a vulnerability, what we
consider in-scope, and the commitments we make in response.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a suspected security bug.**

Instead:

1. Preferred: use [GitHub Private Vulnerability Reporting](https://github.com/Caspian-Explorer/caspian-security/security/advisories/new)
   — this opens a private advisory visible only to the maintainers.
2. Fallback: email **fuad.jalilov@gmail.com** with subject prefix
   `[caspian-security security]`. PGP encryption is not required; plain text
   is acceptable. If the report contains proof-of-concept exploit code,
   flag it in the subject so we can triage quickly.

Please include, to the extent you are able to share it:

- The affected version (from the status bar, `Caspian Security: About`, or
  `vsce show CaspianTools.caspian-security`)
- A minimal reproducer — a file, a workspace, or a sequence of UI actions
- The impact (code execution, data disclosure, local file read/write, etc.)
- Whether you have publicly disclosed any details, and if so where

## Our response commitments

- We will acknowledge receipt within **72 hours** (most often the same day).
- We will confirm or reject the report as a valid vulnerability within
  **7 days** of acknowledgement.
- For confirmed issues we will provide a remediation timeline and keep you
  informed at each milestone. Our targets, by severity:
  - **Critical** (remote code execution, data exfiltration, credential
    theft): patch within 7 days, coordinated disclosure within 14 days.
  - **High** (local-privilege escalation, meaningful information
    disclosure): patch within 14 days.
  - **Medium / Low**: patch in the next scheduled release.
- We credit reporters in the release notes and the GitHub advisory unless
  you ask us not to.

## What's in scope

- The published VS Code extension
  (`CaspianTools.caspian-security` on the VS Code Marketplace, also published
  to Open VSX)
- The CLI shipped with the extension (the unified `caspian` command and the
  `out/cli/*.js` bins, including the agent-loop commands `scan-file`,
  `ship-check`, `baseline accept`, and `init` — the one command that writes
  into a user's repository) and the reusable GitHub Action at
  `.github/actions/scan`
- The MCP server (`out/cli/mcpServer.js`) and every tool it exposes
- The Claude Code plugin: the hook bundles under `plugin/hooks/` (code that
  executes inside users' agent sessions on every file write), `hooks.json`,
  and the plugin's bundled `.mcp.json`
- Webview panels (results, AI settings, learning dashboard, task detail,
  welcome, task tree)
- Code that handles API keys, telemetry, persisted scan state, and outbound
  HTTP (`aiFixService.ts`, `telemetryService.ts`, `fileStateTracker.ts`,
  `dependencyChecker.ts`)

Reports that the agent loop's enforcement can be bypassed or silenced by
the coding agent itself (e.g. a way for an agent to suppress findings,
tamper with the loop-guard state, or slip a blocked write past the
pre-write guard) are in scope and treated as security bugs, not rule
false-negatives — see the threat model, adversary G.

## What's out of scope

- Vulnerabilities in third-party AI provider APIs themselves (report those
  to Anthropic / OpenAI / Google).
- Issues in VS Code core, Electron, or Node.js.
- Issues in third-party npm dependencies — please file those with the
  upstream project. We will still update our lockfile when patched versions
  ship.
- False positives or false negatives in our scan rules — those are
  correctness bugs, not security bugs; please open a normal issue.
- Self-XSS (the scenario where a user pastes attacker-controlled content
  into the API key field or similar input).

## Coordinated disclosure

We ask that you give us the remediation window above before disclosing
publicly. If you need to disclose sooner (for example, because you have
observed active exploitation), tell us in your initial report so we can
accelerate.

We are happy to coordinate CVE assignment with GitHub or MITRE once a fix
is ready.

## Prior advisories

Public security advisories for this project are tracked at:
<https://github.com/Caspian-Explorer/caspian-security/security/advisories>

The v9.2.0 release addressed nine self-audit findings spanning the AI
surface, webview bus, and persistence layer — see the [CHANGELOG](CHANGELOG.md)
for details. No known in-the-wild exploitation occurred.
