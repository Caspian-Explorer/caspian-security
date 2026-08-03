# Caspian Security — Threat Model

This document captures the assets, trust boundaries, adversaries, and
mitigations relevant to the Caspian Security VS Code extension and its CLI.
It's kept deliberately short — a threat model that isn't read isn't useful.
When the design changes, update this file in the same PR.

Scope: extension v9.3.0 and later. Earlier versions should be read against
the CHANGELOG for what was different.

---

## 1. Assets

What an attacker who compromises Caspian can obtain or influence.

| Asset | Why it matters |
|---|---|
| **The user's source code** (every file in the open workspace) | Caspian reads every supported file during a scan. Secrets, proprietary logic, PII in comments. |
| **AI provider API keys** (Anthropic / OpenAI / Gemini) | Stored in `vscode.SecretStorage` (OS keychain). A compromised extension can spend these. |
| **Scan results and learning data** (`resultsStore`, `fixTracker`, `fileStateTracker`, `fixPatternMemory`, `codebaseProfile`, `ruleIntelligenceStore`, `scanHistoryStore`) | Persisted under `context.storageUri`. As of v9.2.0, matched-text `pattern` fields are no longer persisted. |
| **Outbound network capability** | Caspian can call three AI providers, one telemetry endpoint, and npm/OSV registries. Any of these could be pointed at an attacker. |
| **The user's VS Code command surface** | A webview with unchecked `postMessage` could invoke arbitrary registered commands. |
| **Agent-loop enforcement integrity** (v10.12.0+) | The hooks, `caspian.config.json`, `.caspianignore`, `.caspian/baseline.json`, and the loop-guard session state together decide what an AI agent gets away with writing. If any of them can be silently weakened, the scanner becomes decoration. |
| **Execution inside users' agent sessions** (v10.12.0+) | The plugin's hook bundles run `node` on every file write in every session that installs the plugin. Whoever controls those bundles controls code execution on subscribers' machines. |

## 2. Trust boundaries

Where adversary-controlled data meets Caspian-controlled code.

1. **The scanned source code itself.** Rules read `line`, `pattern`,
   `filePath`, etc. from whatever the workspace contains. A hostile
   repository is expected input, not a threat — but its content must never
   be treated as instructions. The most notable case is the AI-fix prompt
   (see §4.1).
2. **LLM response bodies.** Whatever the provider returns is *data*, not
   code. It's shown in a diff, applied only after user confirmation. A
   compromised provider returning a malicious patch is mitigated by the
   mandatory review-and-apply step — the user sees the diff before write.
3. **Webviews ↔ extension host.** The only transport is `postMessage`.
   Every `onDidReceiveMessage` handler treats inbound data as untrusted
   and validates command IDs against `ALLOWED_WEBVIEW_COMMANDS`
   ([src/webviewUtils.ts](src/webviewUtils.ts)).
4. **Persisted JSON stores.** On load, every field is parsed but not
   executed. `JSON.parse` errors fall back to default stores.
5. **Settings (`settings.json`).** Users can point `telemetryEndpoint` or
   `aiModel` anywhere — the telemetry endpoint is validated to be
   `https://` before use.
6. **Hook stdin (v10.12.0+).** Each Claude Code hook receives one JSON
   object on stdin whose `tool_input` is whatever the agent tried to
   write — adversarial by definition. Hooks parse it defensively
   ([src/hooks/hookIO.ts](src/hooks/hookIO.ts)): malformed input, unknown
   tool shapes, and thrown errors all exit 0 (fail open) with no output.
7. **Agent-writable guardrail files (v10.12.0+).** `caspian.config.json`,
   `.caspianignore`, and `.caspian/baseline.json` live in the repo, so an
   agent could in principle edit them to silence its own findings. See
   mitigation G.
8. **MCP tool arguments (v10.12.0+).** Paths arrive from the model;
   handlers resolve and validate them (`validatePath`, existence/type
   checks) before any filesystem access.
9. **The plugin distribution channel (v10.12.0+).** The plugin installs
   from this git repository with pre-built, committed hook bundles — the
   repo itself is the supply chain. See adversary B.

## 3. Adversaries we model

### A. Hostile workspace

A user opens a git repository that was crafted to attack the scanner.
Examples:

- A file containing ``` followed by "Ignore previous instructions…" to
  hijack the AI-fix prompt.
- A file path containing HTML-injection payloads.
- A `.caspianignore` with path-traversal patterns.
- A pathological input designed to trigger ReDoS on scan.

### B. Supply-chain / compromised update

An attacker publishes a malicious update of the extension (marketplace
account takeover), or compromises a downstream package consumed at
install time.

### C. Hostile local process / exfiltration

Another process on the user's machine can read extension storage. Laptops
with full-disk cloud sync (OneDrive, iCloud) effectively have an off-host
adversary too.

### D. Network adversary

Corporate TLS-intercepting proxy, a compromised DNS resolver, or an
attacker positioned on the user's network.

### E. Compromised LLM provider

Anthropic / OpenAI / Google infrastructure is compromised, or a
man-in-the-middle on the provider connection.

### F. Malicious webview

Any defence-in-depth scenario where a webview is compromised and sends
unexpected `postMessage`s.

### G. The coding agent in the loop (v10.12.0+)

The AI agent whose writes Caspian polices. Not malicious in the classic
sense, but *misaligned by incentive*: a finding that blocks its task is an
obstacle, and an agent will try the cheapest path around an obstacle —
adding an ignore rule, accepting a baseline, relaxing `blockOn`, editing
the loop-guard state, or phrasing a write so the guard doesn't match.
Prompt-injected agents (a hostile workspace instructing the agent to
disable the scanner) collapse into this same adversary.

## 4. Mitigations

Numbered to line up with the adversaries above.

### A. Hostile workspace

- User-supplied code is escape-hatched in the AI-fix prompt: triple-backtick
  fences are replaced with zero-width-space sequences, and the system
  prompt explicitly labels user sections as untrusted data
  ([src/aiFixService.ts](src/aiFixService.ts)).
- Scan has a 3-second per-file deadline and a 200 ms per-pattern ReDoS
  guard enforced at build time ([src/__tests__/redosGuard.test.ts](src/__tests__/redosGuard.test.ts)).
- File-path glob patterns in `.caspianignore` are matched against
  workspace-relative paths only; `..` sequences cannot escape the
  workspace ([src/caspianIgnore.ts](src/caspianIgnore.ts)).
- All HTML rendered in webviews passes through `escapeHtml` / `escapeAttr`.
  File paths and scan output are never interpolated as raw HTML.

### B. Supply-chain / compromised update

- Production `dependencies` are minimal; heavy lifting stays in
  `devDependencies` so a compromised dev dep cannot reach users.
- `package-lock.json` is committed; installs use `npm ci`.
- We publish to both VS Code Marketplace and Open VSX from the same
  signed VSIX so consumers can verify parity.
- The project's own CI runs `caspian-scan` against itself on every push
  ([`.github/workflows/self-scan.yml`](.github/workflows/self-scan.yml)).
- The plugin's hook bundles (`plugin/hooks/*.js`) are committed **unminified**
  so they are reviewable in diffs, and are regenerated only by
  `npm run build:plugin` from sources in `src/hooks/`. A marketplace entry
  can be pinned to a tag (`#vX.Y.Z`) by consumers who don't want to track
  `main`. Note the widened blast radius: compromising this repo now means
  code execution in every subscribed agent session, not just a bad scan —
  which is why bundle diffs get the same review bar as source.
- Reporting: see [SECURITY.md](SECURITY.md).

### C. Hostile local process

- API keys live in `vscode.SecretStorage` (OS keychain), never in
  `settings.json`.
- As of v9.2.0, `cachedIssues` are not persisted — the extension no
  longer writes matched secret text to disk.
- Storage path is `context.storageUri` (outside the workspace), so a
  stray `git add .` cannot commit it.

### D. Network adversary

- All outbound calls are HTTPS-only; the telemetry endpoint is validated
  to begin with `https://` before each use.
- Provider-issued TLS trust is used (no cert pinning yet — see §5).
- Gemini API key is sent via header (`x-goog-api-key`), not query string,
  so it doesn't appear in proxy / CDN access logs.

### E. Compromised LLM provider

- Every AI fix is shown in a VS Code diff view and requires two explicit
  user confirmations before the workspace is modified.
- Prompt consent dialog in v9.2.0 shows which provider, which file, and
  how much code will be sent — the user approves each invocation.
- Default is minimal-context mode: only ~20 lines around the finding
  leaves the workspace. Full-file mode is opt-in via
  `caspianSecurity.aiFixMinimalContext`.
- No automatic code execution — "apply fix" is always a manual action.

### F. Malicious webview

- Strict CSP on every panel:
  `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-<nonce>';`.
- Every `<script>` tag carries a per-render nonce.
- `localResourceRoots` scoped to `extensionUri` — webviews cannot reach
  files outside the extension directory.
- `postMessage` handlers reject any command ID not in
  `ALLOWED_WEBVIEW_COMMANDS`.
- No `enableCommandUris`, no `retainContextWhenHidden` for panels that
  don't need it.

### G. The coding agent in the loop

- **No self-silencing tools.** The MCP server deliberately exposes no
  `suppress_finding`, `accept_baseline`, or config-mutation tool. Baseline
  acceptance is CLI-only (`caspian baseline accept`) — a human action.
- **Guardrail-file writes require human approval.** The pre-write guard
  answers `ask` (not allow) when the agent targets `caspian.config.json`,
  `.caspianignore`, or `.caspian/baseline.json`
  ([src/hooks/preWriteGuard.ts](src/hooks/preWriteGuard.ts)).
- **Config can relax, never disarm.** `caspian.config.json` may reduce
  what's reported, but `critical` findings (live credentials, wide-open
  platform rules) block regardless of `blockOn`
  ([src/agentLoop/severity.ts](src/agentLoop/severity.ts)).
- **Loop-guard state lives outside the repository**
  (`CLAUDE_PLUGIN_DATA` or the OS temp dir), so it is not editable through
  the guarded Write/Edit path.
- **Defence in depth across three hooks.** A write that slips past the
  narrow pre-write guard is caught by the post-write scan; a finding the
  agent ignores mid-turn is caught by the stop gate before the turn ends.
- **Findings are phrased as facts, not instructions**, so hostile file
  content echoed in a report cannot masquerade as system commands to the
  agent reading it.

## 5. Known residual risk

Things we know we haven't mitigated fully.

- **No TLS pinning** on outbound calls to providers or the telemetry
  endpoint. Corporate SSL-inspection proxies can still MITM. Tracked as
  a future consideration; pinning adds operational friction (cert
  rotation) that isn't worth it for the current threat level.
- **No attestation of the running extension binary** — we rely on VS
  Code Marketplace / Open VSX signature checks. Caspian doesn't verify
  itself at activation. Adding this is being considered for a future
  release.
- **AI-provider content moderation**. We don't redact secrets before
  sending to the provider; the minimal-context default keeps the surface
  small but a secret on the same line as the finding will still go out.
  Future work: client-side `pattern`-based redaction before the outbound
  POST.
- **No sandboxing of rule regexes beyond the ReDoS time budget.** A
  sufficiently bad regex could still consume 3 seconds of CPU per file.
  Acceptable for now; the build-time guard stops this at commit time.
- **Telemetry session ID** rotates daily but could correlate activity
  within a 24-hour window. The payload contains no file paths or
  identifiers, so the correlation value is low.
- **Hooks fail open by design** (v10.12.0+). Any hook crash, timeout, or
  missing engine exits 0 silently — a broken scanner must never break the
  user's session, so a crash also silently stops enforcement. Accepted
  trade-off: the alternative (fail closed) turns every Caspian bug into a
  denial of service on the user's coding loop.
- **The hooks only guard the Write/Edit tool path** (v10.12.0+). An agent
  that writes a file via `Bash` (`echo … > file`, `sed -i`, a script)
  bypasses both the pre-write guard and the post-write scan. The stop gate
  partially compensates — it scans the whole working tree regardless of
  how files got there — but only blocks on `critical`, and only once per
  finding set. Hooking `Bash` was explicitly rejected for v1 (far too
  noisy); revisit if bypass-via-shell shows up in practice.
- **Loop-guard state is only as private as the OS temp dir.** Another
  local process (or an agent using `Bash` against the temp path) could
  edit the session state to pre-exhaust block counters. Low value: doing
  so downgrades blocks to visible context, it doesn't hide findings.

## 6. Assumptions we make

- VS Code's `SecretStorage` is trustworthy for the OS on which it runs.
- The user's machine is not actively compromised by root-level malware.
- The user's VS Code install is genuine (signature-verified by their OS
  package manager or the marketplace).
- `https://api.anthropic.com`, `https://api.openai.com`, and
  `https://generativelanguage.googleapis.com` honour their documented
  contracts; we don't defend against a provider that silently exfiltrates
  every prompt.

## Change log

| Date | Change |
|---|---|
| 2026-04-21 | Initial version (v9.3.0) |
| 2026-08-03 | Agent-loop integration (v10.12.0): new assets (enforcement integrity, in-session execution), trust boundaries 6–9 (hook stdin, guardrail files, MCP tool args, plugin supply chain), adversary G (the coding agent) with mitigations, and fail-open / Bash-bypass / state-tampering residual risks. |
