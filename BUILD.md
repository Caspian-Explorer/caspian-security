# Caspian Security - Build & Development Guide

## Prerequisites

- Node.js (v18 or higher)
- npm (v9 or higher)
- VS Code (v1.85 or higher)
- Git

## Setup

### 1. Install Dependencies

```bash
cd caspian-security
npm install
```

### 2. Compile TypeScript

```bash
npm run compile
```

Generates JavaScript files in `out/` from TypeScript sources in `src/`.

> The build emits plain `.js` only — `declaration` and `sourceMap` are off
> in `tsconfig.json` (this is an application, not a typed library, and the
> published VSIX shouldn't carry `.d.ts`/`.js.map` weight). Flip either flag
> on locally if you need declarations or step-debugging.

### 2b. Build the Claude Code plugin bundles

```
npm run build:plugin
```

Bundles `src/hooks/*.ts` (engine included, via esbuild) into self-contained
`plugin/hooks/*.js` files. **The bundles are committed** — `/plugin install`
clones this repo with no build step, so re-run this and commit the result
after any change to `src/hooks/`, `src/rules/`, or the engine.

### 3. Run in Development Mode

**Option A: VS Code debug mode**
```bash
code .
# Press F5 to launch debug mode
# Opens a new VS Code window with the extension loaded
```

**Option B: Watch mode**
```bash
npm run watch
```

Watches for TypeScript changes and recompiles automatically.

### 4. Run Dependency Checker (Standalone)

```bash
npm run check-updates
```

Compiles the project and runs the dependency checker CLI, reporting outdated packages, known vulnerabilities, and stack version updates. Run against another project:

```bash
node out/cli/checkUpdates.js /path/to/project
```

### 5. Verify

Open a file with a supported language and type insecure code:
```javascript
const password = "EXAMPLE_PASSWORD";  // CRED001: Hardcoded credential
```

You should see security warnings with confidence badges in the Problems panel (`Ctrl+Shift+M`).

---

## Project Structure

```
caspian-security/
├── src/
│   ├── extension.ts            # Main entry point, commands, scanning (~1230 lines)
│   ├── analyzer.ts             # Rule engine with context-aware analysis (~360 lines)
│   ├── diagnosticsManager.ts   # VS Code diagnostic integration (~60 lines)
│   ├── configManager.ts        # Configuration handling (~160 lines)
│   ├── resultsStore.ts         # Results storage + JSON/CSV/SARIF export (~180 lines)
│   ├── resultsPanel.ts         # Webview results panel (~810 lines)
│   ├── statusBarManager.ts     # Status bar integration (~85 lines)
│   ├── gitIntegration.ts       # Git SCM integration (~50 lines)
│   ├── aiFixService.ts         # AI provider abstraction (Claude/GPT-4/Gemini) (~280 lines)
│   ├── aiSettingsPanel.ts      # AI configuration webview (~300 lines)
│   ├── fixTracker.ts           # Issue status persistence (~150 lines)
│   ├── contextExtractor.ts     # Function scope + variable tracing for AI (~120 lines)
│   ├── confidenceAnalyzer.ts   # Confidence classification (~80 lines)
│   ├── caspianIgnore.ts        # .caspianignore file parsing (~80 lines)
│   ├── dependencyChecker.ts    # npm outdated/audit + stack checking (~200 lines)
│   ├── types.ts                # TypeScript type definitions
│   ├── rules/                  # 29 category rule files
│   │   ├── index.ts            # Rule registry -- imports and merges all categories
│   │   ├── authRules.ts        # AUTH001--AUTH007
│   │   ├── inputValidationRules.ts  # XSS001--XSS011
│   │   ├── csrfRules.ts        # CSRF001--CSRF007
│   │   ├── corsRules.ts        # CORS001--CORS006
│   │   ├── encryptionRules.ts  # ENC001--ENC012
│   │   ├── apiSecurityRules.ts # API001--API014
│   │   ├── databaseRules.ts    # DB001--DB012
│   │   ├── fileHandlingRules.ts # FILE001--FILE014
│   │   ├── secretsRules.ts     # CRED001--CRED009
│   │   ├── frontendRules.ts    # FE001--FE009
│   │   ├── businessLogicRules.ts # BIZ001--BIZ009
│   │   ├── loggingRules.ts     # LOG001--LOG009
│   │   ├── dependenciesRules.ts # DEP001--DEP006
│   │   └── infrastructureRules.ts # INFRA001--INFRA008
│   ├── agentLoop/              # Agent-loop scan pipeline (loop severity, baseline-filtered scans)
│   ├── hooks/                  # Claude Code hook sources (pre-write guard, post-write scan, stop gate)
│   └── cli/
│       └── checkUpdates.ts     # Standalone dependency checker CLI
├── plugin/                     # Claude Code plugin (manifest, hooks.json, committed hook bundles)
├── scripts/buildPlugin.js      # esbuild bundler: src/hooks/*.ts → plugin/hooks/*.js
├── out/                        # Compiled JavaScript (generated)
├── package.json                # Extension manifest and dependencies
├── tsconfig.json               # TypeScript configuration
├── .vscodeignore               # Files to exclude from package
├── icon.png                    # Extension icon
├── README.md                   # User documentation
├── BUILD.md                    # This file
├── QUICKSTART.md               # 5-minute setup
├── ARCHITECTURE.md             # System design
├── CHANGELOG.md                # Release history
└── START_HERE.md               # Documentation index
```

**Total: ~5300+ lines of TypeScript**

---

## Adding New Security Rules

Rules are organized by category in `src/rules/`. Each category file exports an array of `SecurityRule` objects.

### Step 1: Add the rule to the appropriate category file

For example, to add a new database rule, edit `src/rules/databaseRules.ts`:

```typescript
{
  code: 'DB013',
  message: 'Description of the security issue',
  severity: SecuritySeverity.Warning,
  patterns: [
    /regex pattern to match/i,
    'literal string to match',
  ],
  suggestion: 'How to fix this issue',
  category: SecurityCategory.Database,
  ruleType: RuleType.CodeDetectable,
}
```

### Step 2: Use advanced rule features as needed

```typescript
{
  code: 'DB013',
  message: 'Unsafe query construction',
  severity: SecuritySeverity.Warning,
  patterns: [/query\s*\+\s*\w+/i],
  suggestion: 'Use parameterized queries instead',
  category: SecurityCategory.Database,
  ruleType: RuleType.CodeDetectable,

  // Skip matches inside comments, string literals, or JSX text
  contextAware: true,

  // Suppress if any of these patterns appear on the same line
  negativePatterns: [
    /parameterized/i,
    /prepared/i,
  ],

  // Suppress if any of these patterns appear within ±3 lines
  suppressIfNearby: [
    /\.prepare\s*\(/i,
    /\?\s*,/,
  ],

  // File targeting
  filePatterns: {
    include: [/\.js$/, /\.ts$/],          // Only scan these files
    exclude: [/\.test\./i, /\.spec\./i],  // Skip test files
    reduceSeverityIn: [/scripts?\//i],     // Downgrade to Info in scripts/
  },
}
```

### Step 3: Register the rule

If you created a new category file, import and merge it in `src/rules/index.ts`. If you added to an existing category file, it's automatically included.

### Step 4: Recompile

```bash
npm run compile
```

### Rule Types

| Type | Behavior |
|------|----------|
| `CodeDetectable` | Fires on each matching line. Standard security finding. |
| `Informational` | Fires once per file on the best-matching line. Best-practice reminder. |
| `ProjectAdvisory` | Fires once per workspace scan. Project-level recommendation. |

### SecurityRule Interface

```typescript
interface SecurityRule {
  code: string;                           // e.g., 'DB013'
  message: string;                        // User-facing message
  severity: SecuritySeverity;             // Error (2), Warning (1), Info (0)
  patterns: (RegExp | string)[];          // Detection patterns
  suggestion: string;                     // Fix recommendation
  category: SecurityCategory;             // 1 of 14 categories
  ruleType: RuleType;                     // CodeDetectable, Informational, ProjectAdvisory
  contextAware?: boolean;                 // Skip matches in comments/strings/JSX
  negativePatterns?: (RegExp | string)[]; // Suppress if safe pattern on same line
  suppressIfNearby?: RegExp[];            // Suppress if safe pattern within ±3 lines
  filePatterns?: {
    include?: RegExp[];                   // Only match files matching these
    exclude?: RegExp[];                   // Skip files matching these
    reduceSeverityIn?: RegExp[];          // Downgrade to Info in these files
  };
}
```

---

## Debugging

### View Extension Logs

Logs appear in the Debug Console (`Ctrl+Shift+U`) and the "Caspian Security" Output Channel.

### Debug a Specific Rule

Add console.log in the relevant rule file or in `analyzer.ts`:
```typescript
console.log(`Match found for rule ${rule.code} on line ${lineNum}`);
```

### Debug AI Fix Generation

Check the "Caspian Security" Output Channel for AI request/response details. Verify API key is configured in the AI Settings panel.

---

## Building the Extension Package

### 1. Install vsce
```bash
npm install -g vsce
```

### 2. Update Version
Edit `package.json` and increment the `version` field.

### 3. Create VSIX Package
```bash
vsce package
```

Generates a `.vsix` file.

### 4. Install Locally
```bash
code --install-extension caspian-security-7.1.0.vsix
```

---

## Publishing

Caspian ships to **three** registries. Publish to all three for every release:

| Registry | Audience | Channel |
|---|---|---|
| VS Code Marketplace | VS Code users | VSIX extension |
| Open VSX | Cursor, Windsurf, VSCodium, other VS Code derivatives | VSIX extension |
| npm registry | Any CI pipeline, any OS, any editor | CLI via `npx` or global install |

### 1. VS Code Marketplace

1. Create an Azure DevOps account (required by the marketplace).
2. Generate a Personal Access Token with `Marketplace → Manage` scope.
3. Log in once: `vsce login Caspian-Explorer`
4. Publish: `npm run publish:vscode` (alias for `vsce publish`).

### 2. Open VSX

1. Sign in at <https://open-vsx.org> (GitHub OAuth).
2. Generate an access token in your Open VSX profile.
3. Export it: `export OVSX_PAT=<token>`
4. Publish: `npm run publish:openvsx` (alias for `ovsx publish`).

### 3. npm registry

The same repo is published to npm as a CLI package. Users can run `npx
caspian-scan .` anywhere — no cloning, no GitHub Action required.

1. Create an npm account at <https://www.npmjs.com> if you don't have one.
2. Log in once: `npm login` (expects your npm username + password + OTP).
3. Publish: `npm run publish:npm` (alias for `npm publish --access public`).
   The script compiles TypeScript first, then runs `npm publish`. Only the
   files listed under `"files"` in `package.json` are included (`out/`,
   icon, LICENSE, README, CHANGELOG, SECURITY, THREAT_MODEL) — no `src/`,
   no tests, no VSIX artefacts.

The npm package exposes three bin commands, matching the scripts in this
repo:

- `caspian-scan` — the main SARIF scanner.
- `caspian-git-history-scan` — secret scanner for git history.
- `caspian-check-updates` — dependency audit / CVE check.

After publishing, anyone can:

```bash
npx caspian-security scan .
# or, installed globally:
npm install -g caspian-security
caspian-scan .
caspian-git-history-scan .
```

All three distributions ship from the same compiled `out/` tree, so the
rule engine, taint engine, CLI flags, and baseline support are identical
across channels. Tag the git release once and push to all three
registries from there.

**Note on `require()`:** the npm package's `main` field points at the VS
Code extension entry, which imports `vscode`. Don't do `const caspian =
require('caspian-security')` in a Node script — it will fail to resolve
`vscode`. Use the bin commands or spawn them as subprocesses.

### 3. CLI mode and CI scanning

Caspian exposes a headless CLI (`out/cli/scan.js`) that runs the same rule
set as the extension and emits SARIF 2.1. Two npm entry points:

```bash
npm run scan -- /path/to/project --format sarif --output results.sarif
npm run self-scan        # runs the CLI against this repo
```

For GitHub Actions, a reusable composite action is bundled at
`.github/actions/scan`. Example usage in a downstream repo:

```yaml
- uses: Caspian-Explorer/caspian-security/.github/actions/scan@v10.1.0
  with:
    path: .
    fail-on: error
```

The action compiles Caspian on the runner and uploads SARIF to GitHub Code
Scanning automatically. A copy-pasteable workflow lives at
`.github/examples/caspian-scan.yml`.

### 3a. Adopting Caspian into an existing codebase: baselines

If your repo already has hundreds of findings, a big-bang remediation is
unrealistic. Caspian supports a **baseline file** that records the current
set of findings and gates the build only on NEW findings beyond that.

```bash
# One-time: generate the baseline from the current scan.
node out/cli/scan.js . --baseline .caspian-baseline.json --update-baseline

# Commit the baseline. Every subsequent scan suppresses those findings.
node out/cli/scan.js . --baseline .caspian-baseline.json --fail-on error
```

The baseline records per-file, per-rule counts. If a new `XSS001` appears
in a file that already had two `XSS001` findings on record, the scan exits
non-zero. If a team fixes one of the two, re-running `--update-baseline`
drops the count to one, and any new occurrence fails the build. The file
is plain JSON, diff-friendly, and gets reviewed like any other code
artefact.

In the GitHub Action:

```yaml
- uses: Caspian-Explorer/caspian-security/.github/actions/scan@v10.3.0
  with:
    path: .
    fail-on: error
    baseline: .caspian-baseline.json    # committed at repo root
```

### 3c. MCP server — use Caspian from Claude Code, Cursor, Antigravity, Claude Desktop, Cline

Caspian ships an MCP (Model Context Protocol) server so any MCP-aware
client can call scans directly from tool use. The server exposes four
tools: `scan`, `scan_git_history`, `list_rules`, `explain_rule`. No
configuration needed beyond pointing the client at the bin.

The config shape is identical across every client; only the file location
differs. `caspian mcp-config --client <name>` prints the block with the
right path:

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
| **Claude Code** | `.mcp.json` at the project root, or run `claude mcp add caspian-security -- npx -y caspian-security mcp` |
| **Claude Desktop** | `%APPDATA%\Claude\claude_desktop_config.json` (Windows) / `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| **Cursor** | `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project) |
| **Antigravity** | Antigravity Settings → MCP / Plugins (`mcp_config.json`) |
| **Cline** | Cline → MCP Servers → Configure (`cline_mcp_settings.json`) |

Transport is stdio; no network port is opened. The server has no telemetry
and no persistent state — it's a thin wrapper over the same `scanRunner`
the CLI uses. (`caspian-mcp` remains as a direct bin for backward compat.)

Example prompt once wired in: *"Use Caspian to scan /path/to/my/repo for
security issues, focusing on Error-severity findings."* The client calls
the `scan` tool with the appropriate arguments and receives JSON back.

### 3d. AI-agent integration — one line in CLAUDE.md / rules, zero repo setup

The MCP route (§3c) gives an assistant *tools*. The lighter-weight route
gives **any** agent that can run a shell command the ability to run Caspian
with nothing installed in the target repo: paste one plain-language line into
the agent's own config and Caspian runs via `npx`.

Generate the exact paste-ready block:

```bash
caspian snippet --agent claude   --mode after-edits   # → CLAUDE.md
caspian snippet --agent cursor                         # → Cursor Project Rules / .cursorrules
caspian snippet --agent antigravity                    # → Antigravity rules / memory
caspian snippet --agent generic  --mode pre-commit     # → any system prompt, pre-commit trigger
```

`--mode` controls the trigger sentence: `request` ("when I ask"),
`after-edits` (default), or `pre-commit` (which uses
`caspian scan . --changed-since origin/main`). The block tells the agent to
run the scan, fix `Error`-severity findings, re-run to confirm, and summarize
the rest.

In VS Code the same text is one click away — **"Caspian Security: Copy AI
Agent Instructions"** and **"Caspian Security: Copy MCP Server Config"**.
Caspian only ever copies text to your clipboard; it never writes into a repo
it doesn't own.

### 3b. PR-scope scanning with `--changed-since`

On a large monorepo, scanning everything on every PR is waste. Caspian
can restrict the scan to just the files this branch adds on top of main:

```bash
# Local: scan only what this branch adds since it forked from main
node out/cli/scan.js . --changed-since origin/main --fail-on error

# CI — the usual PR recipe
node out/cli/scan.js . --changed-since "$GITHUB_BASE_SHA" --fail-on error
```

Semantics match `git diff --name-only --diff-filter=d <ref>...HEAD`:
three-dot syntax means "everything on this branch since diverging from
<ref>", not "everything different from <ref> right now". Deletions are
excluded. Working-tree / untracked files are NOT included — this is the
PR-scope set, not the dirty-tree set.

Pairs naturally with `--baseline`: adopt Caspian with a baseline, then
flip PR CI to `--changed-since` so new findings are caught fast, while
the baseline takes care of the legacy backlog.

In the GitHub Action:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0                      # so the base ref resolves

- uses: Caspian-Explorer/caspian-security/.github/actions/scan@v10.3.0
  with:
    path: .
    fail-on: error
    baseline: .caspian-baseline.json
    changed-since: ${{ github.event.pull_request.base.sha }}
```

### 4. VSIX signing (planned)

VS Code Marketplace supports publisher signing. We track that work under
issue [#signing](https://github.com/Caspian-Explorer/caspian-security/issues)
— once a certificate is provisioned, publishing will gain a
`--sign-package` flag. In the interim, consumers can verify a published
VSIX by diffing its SHA-256 against the asset checksum attached to the
corresponding GitHub Release.

---

## Extending the Extension

### Add Support for More Languages

In `package.json`, add to `activationEvents`:
```json
"onLanguage:kotlin",
"onLanguage:swift"
```

Also update `configManager.ts` default enabled languages.

### Add Custom Rules from External Source

Create `src/customRules.ts`:
```typescript
import { SecurityRule } from './types';

export function loadCustomRules(): SecurityRule[] {
  // Load from files, API, or define inline
  return [];
}
```

Import and merge in `src/rules/index.ts`.

---

## Performance Notes

| Aspect | Detail |
|--------|--------|
| Debounce | 1-second delay prevents lag during typing |
| Language filtering | Only analyzes files in `enabledLanguages` |
| Lazy initialization | Rules created once at startup |
| Regex compilation | Patterns compiled once |
| Early exit | Skips untitled and non-file documents |
| Batch scanning | Workspace scans in batches of 50 files |
| Event loop yielding | Every 10 files during workspace scan |
| Informational dedup | Informational rules collect candidates, fire once per file |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Cannot find module vscode" | Run `npm install` |
| Extension not appearing | Reload VS Code or restart debug |
| Patterns not matching | Test at regex101.com, check enabledLanguages, verify contextAware isn't filtering |
| Performance degradation | Increase debounce, disable unused categories, limit languages |
| AI fix fails | Check API key, verify provider connectivity, check Output Channel |
| .caspianignore not working | Verify file in workspace root, format: `RULE_CODE path:line # reason` |

---

## Continuous Integration

Releases are automated by [`.github/workflows/release.yml`](.github/workflows/release.yml), triggered manually (Actions → Release → Run workflow, or `gh workflow run release.yml`) or by pushing a `release/**` branch (e.g. `git push origin main:release/v10.7.1`). It runs the full gate (lint, compile, test), packages the VSIX, creates the `vX.Y.Z` tag + GitHub Release with the VSIX attached, and publishes to the VS Code Marketplace / Open VSX when the `VSCE_PAT` / `OVSX_PAT` repository secrets are configured. Publish steps skip with a notice when a secret is absent, and the release step is idempotent, so the workflow can safely be re-run after adding secrets. The version released is whatever `package.json` says on `main` — bump it before dispatching.

---

For full documentation see [README.md](README.md). For system architecture see [ARCHITECTURE.md](ARCHITECTURE.md).
