# Caspian Security — User Guide

**Version 10.6.1** · Context-aware security scanning for VS Code **and** a standalone `caspian` CLI you can run anywhere.

Caspian Security detects vulnerabilities, insecure patterns, and security best-practice violations across **code and infrastructure** — 295+ rules over 14 categories, intra-file taint tracking, provider-prefix secret detection, and a git-history secret scanner. The same engine powers four surfaces:

| Surface | Use it when… |
|---|---|
| **VS Code extension** | You want inline squiggles, quick-fixes, and AI fixes while you code |
| **`caspian` CLI** | You want to scan from a terminal (PowerShell / cmd / bash), CI, or a script — no editor needed |
| **AI agents** | You want Claude Code / Cursor / Antigravity to run Caspian while working on a task |
| **CI/CD** | You want to gate merges on new findings (SARIF upload, exit codes) |

---

## Table of Contents

1. [Installation](#1-installation)
2. [Quick start](#2-quick-start)
3. [The `caspian` CLI](#3-the-caspian-cli)
4. [Using it in VS Code](#4-using-it-in-vs-code)
5. [AI agent integration](#5-ai-agent-integration)
6. [CI/CD integration](#6-cicd-integration)
7. [Configuration](#7-configuration)
8. [Output formats](#8-output-formats)
9. [Rule categories](#9-rule-categories)
10. [Severity & confidence](#10-severity--confidence)
11. [Troubleshooting & FAQ](#11-troubleshooting--faq)
12. [Command cheat sheet](#12-command-cheat-sheet)

---

## 1. Installation

Caspian ships on three registries — install whichever fits your workflow. They share one rule engine, so results are identical across channels.

### VS Code / Cursor / Windsurf / VSCodium

```
code --install-extension CaspianTools.caspian-security
```

Or search **"Caspian Security"** in the Extensions sidebar. Cursor/Windsurf/VSCodium users can also install from [Open VSX](https://open-vsx.org).

From a local `.vsix` file:

```
code --install-extension caspian-security-10.6.1.vsix
```

### Command line (npm)

```bash
# Zero install — runs the latest published version (any shell)
npx -y caspian-security scan .

# Or install once and get the `caspian` command everywhere
npm install -g caspian-security
caspian --version
```

> **Testing a local build?** From a clone of the repo, run `npm run compile` then `npm link` to expose a global `caspian` backed by your local build (undo with `npm rm -g caspian-security`). See [Troubleshooting](#11-troubleshooting--faq) if `npx` returns a 404.

### Verify the install

```bash
caspian --version      # → 10.6.1
caspian --help         # full command list
```

---

## 2. Quick start

Scan the current project and gate on errors:

```bash
caspian scan . --format json --fail-on error
```

- Prints findings as JSON to stdout.
- **Exit code** is `0` if clean, `1` if any finding is at/above the threshold, `2` if the scan failed.

Human-readable version:

```bash
caspian scan . --format text
```

Generate an instruction block to paste into an AI agent's rules:

```bash
caspian snippet --agent claude
```

Print an MCP config for a client:

```bash
caspian mcp-config --client cursor
```

---

## 3. The `caspian` CLI

One unified command fronts every capability. Run any subcommand with `--help` for its own flags.

```
caspian <command> [options]

  scan [path]           Run the security scanner (SARIF / JSON / text)
  git-history [path]    Walk git history for leaked secrets
  check-updates [path]  npm audit + stack version checks (--osv: OSV.dev multi-ecosystem)
  mcp                   Start the MCP server (stdio)
  snippet               Print a paste-ready AI-agent instruction block
  mcp-config            Print an MCP client config block
  help                  Show help
  --version, -v         Print the version
```

The original bins — `caspian-scan`, `caspian-git-history-scan`, `caspian-check-updates`, `caspian-mcp` — still work unchanged.

> **Windows:** a global install creates `caspian.cmd` (for cmd.exe) and `caspian.ps1` (for PowerShell), both on your PATH. Everything below works identically in PowerShell, cmd, and bash.

### 3.1 `caspian scan`

Scans every eligible file under `[path]` (defaults to the current directory).

```
caspian scan [path]
  --format sarif|json|text          output format (default: sarif)
  --fail-on error|warning|info|never  exit-code threshold (default: error)
  --output <file>                   write to a file instead of stdout
  --include <substr,substr,...>     extra path substrings to include
  --exclude <substr,substr,...>     directory names to skip
  --max-file-size <bytes>           skip files larger than this (default: 500000)
  --baseline <file>                 suppress known findings; only NEW ones gate
  --update-baseline                 regenerate <baseline>, then exit 0
  --changed-since <ref>             scan only files changed since <ref> (PR scope)
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Clean, or everything suppressed by the baseline |
| `1` | At least one finding at/above the `--fail-on` threshold |
| `2` | The scan failed to run (bad args, I/O error) |

**Examples**

```bash
# JSON to stdout, fail the build on any Error
caspian scan . --format json --fail-on error

# Write SARIF to a file for CI upload
caspian scan . --format sarif --output results.sarif

# Only scan TypeScript under src/, skip fixtures
caspian scan . --include src/ --exclude fixtures,mocks

# Never fail — just report (useful for dashboards)
caspian scan . --format json --fail-on never
```

> **Note:** the CLI prints findings at *every* severity; `--fail-on` controls only the exit code, not what's printed. To hide the informational "reminder" findings, adopt a [baseline](#34-baselines) or use the VS Code extension's interactive severity filter.

### 3.2 `caspian git-history`

The working-tree scan only sees current files. A secret that was committed and later "removed" is still in history — and in every clone. This command walks all commits and flags secret-shaped strings in added lines, with commit SHA, author, and date.

```
caspian git-history [path]
  --output <file>       write findings to file (default: stdout)
  --format json|text    output format (default: text)
  --max-commits <n>     stop after N commits (default: all)
  --rules secrets|all   rule set (default: secrets)
```

```bash
caspian git-history . --format json --output leaks.json
```

If it finds anything: **rotate the secret at the provider first**, then rewrite history (BFG / `git filter-repo`) and force-push.

### 3.3 `caspian check-updates`

Runs `npm audit` plus Node/TypeScript/stack version checks for the project at `[path]`.

```bash
caspian check-updates .
```

Add `--osv` to also check non-npm manifests against the [OSV.dev](https://osv.dev) vulnerability database (Google/GitHub-backed, aggregates the GitHub Advisory Database):

```bash
caspian check-updates . --osv
```

Supported manifests (project root): `requirements.txt` (Python), `go.mod` (Go), `Cargo.lock`/`Cargo.toml` (Rust — lockfile preferred), `pom.xml` (Java), `Gemfile.lock` (Ruby), `composer.lock` (PHP). High/critical OSV advisories trigger exit code `1`, same as `npm audit` findings. With `--osv`, the command works even in projects with no `package.json` (npm checks are skipped).

**Privacy:** only dependency names and versions are sent to `api.osv.dev` — never your code. The check is opt-in and off by default.

### 3.4 Baselines

Adopt Caspian into an existing codebase without a big-bang cleanup. A baseline records the *known* findings so only **new** ones gate the build.

```bash
# 1. Record the current state
caspian scan . --baseline .caspian-baseline.json --update-baseline

# 2. From now on, only NEW findings fail the build
caspian scan . --baseline .caspian-baseline.json --fail-on error
```

Commit `.caspian-baseline.json` to the repo. It's count-based (per file, per rule) so it stays readable and auto-tightens as you fix things.

### 3.5 PR-scope scanning (`--changed-since`)

On a big repo, don't scan everything on every PR — scan only what the branch changed:

```bash
caspian scan . --changed-since origin/main --fail-on error
```

Semantics match `git diff --name-only --diff-filter=d origin/main...HEAD` (three-dot: "everything this branch added since it diverged"). Deletions are excluded. Pairs naturally with `--baseline`.

---

## 4. Using it in VS Code

Once installed, Caspian activates automatically for supported languages.

### Real-time & on-save scanning

- **As you type** — findings appear as red/yellow squiggles (1-second debounce).
- **On save** — a full re-scan of the file.
- Toggle both in Settings (`caspianSecurity.autoCheck`, `caspianSecurity.checkOnSave`).

### Commands (Command Palette → `Ctrl+Shift+P`)

A selection of the most-used commands (44 total):

| Command | What it does |
|---|---|
| **Caspian Security: Check Current File** | Scan the active editor |
| **Caspian Security: Check Entire Workspace** | Scan all project files |
| **Caspian Security: Scan Branch Changes (PR Scope)** | Scan only files changed vs the base branch |
| **Caspian Security: Fix Issue with AI** | Generate an AI fix for a finding |
| **Caspian Security: Show Results Panel** | Open the interactive results browser |
| **Caspian Security: Export Results to SARIF / JSON / CSV** | Export findings |
| **Caspian Security: Copy AI Agent Instructions** | Copy a CLAUDE.md / Cursor / Antigravity block to the clipboard |
| **Caspian Security: Copy MCP Server Config** | Copy an MCP config for a chosen client |
| **Caspian Security: Show Learning Dashboard** | Rule effectiveness, hot zones, trends |

### One-click quick-fix lightbulb

Hover a finding and press `Ctrl+.` (or click the yellow lightbulb) for a deterministic one-click fix on the 18 most common mechanical remediations (e.g. Kubernetes `privileged: true → false`, Terraform `publicly_accessible = false`, weak hashes `md5/sha1 → sha256`, `http:// → https://`, Dockerfile `ADD → COPY`, adding `algorithms: ['RS256']` to `jwt.verify`). No AI round-trip; fully undoable.

### AI fixes

For ambiguous cases, **Fix Issue with AI** sends the enclosing function (minimal-context by default) to your configured provider (Claude / GPT-4 / Gemini), shows a diff, and applies it on confirmation. API keys are stored in VS Code SecretStorage (OS keychain), never in settings.

### `.caspianignore`

Suppress false positives, team-shared and version-controlled. See [Configuration](#72-caspianignore).

---

## 5. AI agent integration

The headline of 10.6.1: any AI coding agent can run Caspian **with zero setup inside the target repo**. Caspian runs via `npx`, and it **never writes files into a project it doesn't own** — you paste a small piece of text wherever *you* choose. There are two routes.

### Route 1 — one line in the agent's rules (any agent with a shell)

Generate the exact block to paste:

```bash
caspian snippet --agent claude   --mode after-edits   # → CLAUDE.md
caspian snippet --agent cursor                         # → Cursor Project Rules / .cursorrules
caspian snippet --agent antigravity                    # → Antigravity rules / memory
caspian snippet --agent generic  --mode pre-commit     # → any system prompt
```

`--mode` sets the trigger:

| Mode | Trigger | Command used |
|---|---|---|
| `request` | "When I ask you to run a security check…" | full scan |
| `after-edits` *(default)* | "After you finish editing code…" | full scan |
| `pre-commit` | "Before committing changes…" | `caspian scan . --changed-since origin/main` |

The pasted block instructs the agent to run the scan, **fix every `Error`-severity finding**, re-run to confirm it's clear, and summarize the rest. Example:

```markdown
## Security scanning — Caspian Security

Caspian Security is a standalone security scanner (295+ rules...). It needs no
configuration in this repository.

After you finish editing code in this project, run:

    npx -y caspian-security scan . --format json --fail-on error

Then read the JSON output and act on it:
- Fix every finding at "Error" severity, then re-run to confirm it is clear.
- Summarize any remaining Warning/Info findings for me.
- Do not consider the task done (or commit) while Error-severity findings remain.
```

In VS Code, **Caspian Security: Copy AI Agent Instructions** puts the same block on your clipboard.

### Route 2 — MCP server (gives the assistant real tools)

Caspian ships a Model Context Protocol (MCP) server exposing four tools: `scan`, `scan_git_history`, `list_rules`, `explain_rule`. The config shape is identical across clients; only the path differs. Print the right block with:

```bash
caspian mcp-config --client claude-code   # or claude-desktop | cursor | antigravity | cline
```

```json
{
  "mcpServers": {
    "caspian-security": {
      "command": "npx",
      "args": ["-y", "caspian-security", "mcp"]
    }
  }
}
```

| Client | Where the config lives |
|---|---|
| **Claude Code** | `.mcp.json` at the project root, or `claude mcp add caspian-security -- npx -y caspian-security mcp` |
| **Claude Desktop** | `%APPDATA%\Claude\claude_desktop_config.json` (Windows) · `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| **Cursor** | `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project) |
| **Antigravity** | Antigravity Settings → MCP / Plugins |
| **Cline** | Cline → MCP Servers → Configure |

Transport is stdio; no network port is opened; no telemetry; no persistent state. Example prompt once wired in: *"Use Caspian to scan this repo for security issues, focusing on Error-severity findings."*

### Which route?

- **Route 1 (snippet)** is simplest and most portable — works with any agent that can run a terminal command, needs nothing installed, and *you* decide the interval/event.
- **Route 2 (MCP)** gives the assistant structured tools (rule lookup, history scan) it can call directly — nice for interactive chat.

---

## 6. CI/CD integration

### GitHub Actions

```yaml
- uses: Caspian-Explorer/caspian-security/.github/actions/scan@v10.6.1
  with:
    path: .
    fail-on: error
    baseline: .caspian-baseline.json   # optional
```

Findings land in the GitHub Security tab automatically (SARIF upload).

### Any other CI (GitLab, Jenkins, CircleCI, Drone, BuildKite)

```bash
npx -y caspian-security scan . --format sarif --output results.sarif --fail-on error
```

The exit code gates the job: `0` passes, `1` fails on findings, `2` fails on a scan error.

### Git pre-commit hook (husky example)

```bash
# .husky/pre-commit
npx -y caspian-security scan . --changed-since origin/main --fail-on error
```

### Scheduled scans

Run `caspian scan` on a cron (Linux/macOS) or a Windows Task Scheduler task to catch drift, e.g. nightly `caspian git-history .` for leaked secrets.

---

## 7. Configuration

### 7.1 Settings (`caspianSecurity.*`)

Set in VS Code Settings (`Ctrl+,` → search "caspianSecurity") or workspace `.vscode/settings.json`:

```json
{
  "caspianSecurity.autoCheck": true,
  "caspianSecurity.checkOnSave": true,
  "caspianSecurity.severity": "warning",
  "caspianSecurity.showInformational": true,
  "caspianSecurity.reduceInternalPathSeverity": true,
  "caspianSecurity.aiProvider": "anthropic",
  "caspianSecurity.aiModel": "claude-sonnet-4-20250514",
  "caspianSecurity.aiFixMinimalContext": true,
  "caspianSecurity.enabledLanguages": [
    "javascript", "typescript", "python", "java",
    "csharp", "php", "go", "rust", "kotlin",
    "yaml", "terraform", "dockerfile"
  ]
}
```

There are 40+ settings, including a per-category toggle (`caspianSecurity.enable<Category>`) for each of the 14 categories.

Notable opt-in: `caspianSecurity.osvCheck` (default `false`) extends **Check Dependency Updates** with an [OSV.dev](https://osv.dev) query of non-npm manifests (`requirements.txt`, `go.mod`, `Cargo.lock`/`Cargo.toml`, `pom.xml`, `Gemfile.lock`, `composer.lock`). Only dependency names and versions are sent — never your code.

### 7.2 `.caspianignore`

Place at the workspace root. One suppression per line:

```
# RULE_CODE  file/path.ts:line   # optional reason
XSS001 src/app.ts:42 # false positive, sanitized upstream
CRED001 src/config.ts            # test credentials only
DB001 src/api/users.ts:100
```

Lines starting with `#` are comments. The line number is optional (omit it to suppress the rule for the whole file). Use **Caspian Security: Ignore Issue** to append entries interactively.

### 7.3 Baseline file

`.caspian-baseline.json` (see [3.4](#34-baselines)) — generated/updated with `--update-baseline`, consumed with `--baseline`. Count-based per file/rule; commit it to the repo.

---

## 8. Output formats

Select with `--format`.

### SARIF 2.1.0 (default)

Standard SAST format consumed by GitHub code scanning and most tooling. Includes tool metadata, a rules catalog, and results with file/line/column and severity levels.

```bash
caspian scan . --format sarif --output results.sarif
```

### JSON (flat, agent-friendly)

```json
{
  "issues": [
    {
      "file": "src/app.ts",
      "line": 42,
      "column": 15,
      "severity": "Error",
      "code": "CRED001",
      "category": "Secrets & Credentials",
      "message": "Hardcoded password or secret assignment",
      "suggestion": "Use environment variables or a secure secret manager...",
      "pattern": "password = \"...\""
    }
  ]
}
```

### Text (human-readable)

```
Caspian Security CLI — 15 finding(s) across 3 file(s)
--- src/app.ts (3 issue(s)) ---
  [Error] CRED001 (Line 42): Hardcoded password or secret assignment
    Suggestion: Use environment variables or a secure secret manager...
```

---

## 9. Rule categories

295+ rules across 14 categories, plus intra-file taint rules (`TAINT001`–`TAINT008`) and 28 provider-prefix secret detectors.

| Category | Example coverage |
|---|---|
| Authentication & Access Control | JWT secrets, session flags, weak passwords, missing rate limiting |
| Input Validation & XSS | `innerHTML`, `dangerouslySetInnerHTML`, template injection |
| CSRF Protection | Missing tokens, unsafe AJAX patterns |
| CORS Configuration | Wildcard origins, credentials with `*` |
| Encryption & Data Protection | Weak ciphers, disabled TLS verification, PII at rest, sensitive logging |
| API Security | Missing auth middleware, IDOR, key validation/expiry, rate-limit headers |
| Database Security | SQL/NoSQL injection, default credentials, auditing/backups |
| File Handling | Path traversal, public buckets, signed URLs, upload location |
| Secrets & Credentials | Hardcoded secrets, `.env` references, provider-prefixed tokens |
| Frontend Security | Unsafe `eval`, missing SRI on CDN resources |
| Business Logic & Payment | Client-side quota/premium checks, payment verification |
| Logging & Monitoring | Missing authz-failure logs, admin-op logs, export/API-key events |
| Dependencies & Supply Chain | Unpinned versions (`"*"`, `^`), audit findings |
| Infrastructure & Deployment | Dockerfile / Terraform / Kubernetes misconfig, test data in prod |

Look up any rule from the CLI or MCP:

```bash
# via MCP tools: list_rules, explain_rule
caspian mcp   # then ask the assistant to explain e.g. FILE009
```

Languages: **JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust, Kotlin** + Infrastructure-as-code (**Dockerfile, Terraform/HCL, Kubernetes YAML**) — infrastructure files are scanned both in the editor and by the CLI as of 10.8.

---

## 10. Severity & confidence

- **Severity** — `Error`, `Warning`, `Info`. `--fail-on` gates the exit code on a threshold (default `error`). Most "reminder"-style findings are `Info`.
- **Confidence (VS Code)** — findings are classified **Critical / Safe / Verify-Needed** based on variable-source analysis, shown as badges. Internal-path findings can be down-ranked (`reduceInternalPathSeverity`).
- **Taint tracking** — `TAINT*` rules follow user input through a function body to dangerous sinks (exec, eval, fs, etc.), catching real dataflow bugs rather than surface patterns.

---

## 11. Troubleshooting & FAQ

**`npx -y caspian-security …` returns `404 Not Found`.**
The package isn't published to your npm registry yet. Either publish it (`npm login` then `npm publish` from the repo), or for local use run `npm link` in the repo to get a global `caspian` from your local build, or invoke the build directly: `node path/to/out/cli/caspian.js scan .`.

**`caspian: command not found` after `npm install -g` / `npm link`.**
Open a **new** terminal so PATH picks up the npm global bin dir (Windows: `%AppData%\npm`). Confirm it's on PATH, or call the shim directly.

**Too many `Info` findings.**
Those are advisory "reminders". Gate CI with `--fail-on error` (they won't fail the build), adopt a `--baseline` to snapshot the current state, or filter interactively in the VS Code Results Panel.

**The scan exits `1` but I only see reminders.**
Something at/above your `--fail-on` threshold fired. Search the output for `"severity": "Error"` (or `Warning` if you lowered the threshold).

**Does Caspian send my code anywhere?**
No. The CLI, MCP server, and rule engine run entirely locally with no telemetry or network access. Only the optional **AI Fix** feature (opt-in, per-invocation consent) sends the minimal context you approve to your chosen provider.

**Will running it change my repo?**
No — scanning is read-only. The AI-agent integration only *emits* text/config for you to paste; it never writes into a project.

**Which path does `caspian scan` accept?**
A **directory** (defaults to the current directory). It walks the tree for supported file types; pointing it at a single file scans nothing.

---

## 12. Command cheat sheet

```bash
# Scan
caspian scan .                                   # SARIF to stdout
caspian scan . --format json --fail-on error     # JSON, gate on errors
caspian scan . --format text                      # human-readable
caspian scan . --changed-since origin/main        # PR scope
caspian scan . --baseline .caspian-baseline.json  # only new findings
caspian scan . --output results.sarif             # write to file

# History & deps
caspian git-history . --format json               # leaked secrets in history
caspian check-updates .                           # npm audit + stack checks
caspian check-updates . --osv                     # + OSV.dev check of non-npm manifests

# AI agents
caspian snippet --agent claude --mode after-edits # CLAUDE.md block
caspian mcp-config --client cursor                # MCP config block
caspian mcp                                        # start the MCP server

# Meta
caspian --version
caspian help
```

---

*Links:* [Marketplace](https://marketplace.visualstudio.com/items?itemName=CaspianTools.caspian-security) · [GitHub](https://github.com/CaspianTools/caspian-security) · [Wiki](https://github.com/CaspianTools/caspian-security/wiki) · [Releases](https://github.com/CaspianTools/caspian-security/releases)
