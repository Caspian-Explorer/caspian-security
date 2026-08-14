# Caspian Security - Architecture & Design

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    VS Code Extension API                     │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │
                    ┌─────────┴──────────┐
                    │                    │
            ┌───────▼────────┐   ┌──────▼──────────┐
            │  Document      │   │   Commands      │
            │  Events        │   │   (Palette)     │
            └────────┬───────┘   └──────┬──────────┘
                     │                  │
                     └──────────┬───────┘
                                │
                    ┌───────────▼────────────┐
                    │   Extension Main       │
                    │   (extension.ts)       │
                    └───────────┬────────────┘
                                │
    ┌──────────┬────────────────┼──────────────────┬──────────────┐
    │          │                │                  │              │
┌───▼────┐ ┌──▼───────────┐ ┌──▼──────────┐ ┌───▼────────┐ ┌───▼──────────┐
│AI Fix  │ │  Analyzer    │ │Diagnostics  │ │  Config    │ │ Results      │
│Service │ │(analyzer.ts) │ │  Manager    │ │  Manager   │ │ Store        │
│        │ │              │ │             │ │            │ │              │
│- Claude│ │- Rule engine │ │- Create     │ │- Settings  │ │- File results│
│- OpenAI│ │- Pattern     │ │- Publish    │ │- Categories│ │- JSON/CSV    │
│- Gemini│ │  matching    │ │- Severity   │ │- Languages │ │- SARIF export│
└───┬────┘ │- Context     │ └─────────────┘ └────────────┘ └──────────────┘
    │      │  awareness   │
    │      └──────┬───────┘
    │             │
    │    ┌────────▼──────────────────────────────────────────────────────┐
    │    │              Learning Intelligence Layer                      │
    │    │                                                              │
    │    │ ┌─────────────┐ ┌──────────────┐ ┌────────────────────────┐ │
    │    │ │   Rule      │ │  Adaptive    │ │  Fix Pattern Memory    │ │
    │    │ │Intelligence │ │ Confidence   │ │  (instant fix replay)  │ │
    │    │ └──────┬──────┘ └──────────────┘ └────────────────────────┘ │
    │    │        │                                                     │
    │    │ ┌──────▼──────┐ ┌──────────────┐ ┌────────────────────────┐ │
    │    │ │  Codebase   │ │    Scan      │ │  Telemetry Service     │ │
    │    │ │  Profile    │ │  Insights    │ │  (opt-in, anonymized)  │ │
    │    │ └─────────────┘ └──────────────┘ └────────────────────────┘ │
    │    └──────────────────────────────────────────────────────────────┘
    │
                  │
    ┌─────────────┼─────────────────┬──────────────────┐
    │             │                 │                  │
┌───▼──────┐ ┌───▼──────────┐ ┌───▼──────────┐ ┌────▼─────────┐
│ Rules    │ │ Confidence   │ │ Context      │ │ .caspian     │
│ (15 rule │ │ Analyzer     │ │ Extractor    │ │ ignore       │
│ files)   │ │              │ │              │ │              │
│          │ │- Critical    │ │- Function    │ │- Parse file  │
│- 309     │ │- Safe        │ │  scope       │ │- Watch       │
│  rules   │ │- Verify      │ │- Variable    │ │- Match rules │
│- Patterns│ │  needed      │ │  definitions │ │- Persist     │
└──────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

## Analysis Pipeline

```
Document text
       │
       ▼
Split into lines
       │
       ▼
For each line × each rule:
  1. File pattern filtering (include/exclude/reduceSeverityIn)
  2. Pattern matching (regex or string)
  3. Context-aware filtering (skip comments, strings, JSX text)
  4. Negative pattern check (skip if safe pattern on same line)
  5. Suppress-if-nearby check (skip if safe pattern within ±3 lines)
  6. Learned safe pattern suppression (codebase profile)
  7. Effective severity calculation (file-path reduction)
  8. Internal-path severity reduction (admin/scripts/seed paths)
  9. Adaptive confidence classification (Bayesian-updated from learned priors)
 10. Informational candidate collection (deferred, best-line scoring)
       │
       ▼
Filter: .caspianignore entries
Filter: showInformational setting
Filter: reduceInternalPathSeverity setting
       │
       ▼
DiagnosticsManager → VS Code squiggles
ResultsStore → Results panel + SARIF/JSON/CSV export
```

## Component Details

### extension.ts (Main Controller)
- Extension lifecycle (activate/deactivate)
- Event registration with 1-second debounce
- Command registration (34 commands)
- AI fix workflow (generate, diff preview, apply, verify)
- Fix pattern memory check before AI API calls (offers cached fixes)
- Learning event emission at every user action (fix, ignore, FP, verify, fix-failed)
- `.caspianignore` loading and file watching
- Informational filtering and internal-path severity reduction
- Workspace scanning with batched progress
- Git uncommitted file scanning and branch-scoped scanning
- Dependency checking integration
- Telemetry service and learning dashboard initialization
- Welcome panel (first-run onboarding) and security score display
- Triage session (guided walkthrough of pending issues)
- Bulk ignore and rule explanation commands

### analyzer.ts (Security Engine)
- Line-by-line pattern matching against 291 rules (plus 8 taint-tracking rules), shared with the CLI and MCP server via scanRunner.ts
- Context-aware filtering (comments, strings, JSX text)
- Negative pattern and suppress-if-nearby logic
- Learned safe pattern suppression via codebase profile
- File pattern include/exclude/reduceSeverityIn
- Informational rule candidate scoring (picks best line)
- Adaptive confidence classification (Bayesian-updated, falls back to static heuristics)
- Project advisory collection

### rules/ (14 Category Files)
Each file exports an array of `SecurityRule` objects:

| File | Category | Rules |
|------|----------|-------|
| `authRules.ts` | Authentication & Access Control | AUTH001--AUTH007 |
| `inputValidationRules.ts` | Input Validation & XSS | XSS001--XSS011 |
| `csrfRules.ts` | CSRF Protection | CSRF001--CSRF007 |
| `corsRules.ts` | CORS Configuration | CORS001--CORS006 |
| `encryptionRules.ts` | Encryption & Data Protection | ENC001--ENC012 |
| `apiSecurityRules.ts` | API Security | API001--API014 |
| `databaseRules.ts` | Database Security | DB001--DB012 |
| `fileHandlingRules.ts` | File Handling | FILE001--FILE014 |
| `secretsRules.ts` | Secrets & Credentials | CRED001--CRED009 |
| `frontendRules.ts` | Frontend Security | FE001--FE009 |
| `businessLogicRules.ts` | Business Logic & Payment | BIZ001--BIZ009 |
| `loggingRules.ts` | Logging & Monitoring | LOG001--LOG009 |
| `dependenciesRules.ts` | Dependencies & Supply Chain | DEP001--DEP006 |
| `infrastructureRules.ts` | Infrastructure & Deployment | INFRA001--INFRA008 |
| `deployConfigRules.ts` | Deploy config (spans Infra / Secrets / API) | DEPLOY001--DEPLOY010 |

**Total: 309 rules** — 301 pattern rules (225 code-detectable + 65 informational + 11 project advisories) + 8 taint-tracking rules

### Agent-loop layer (10.12.0)

The engine is also a participant in AI-agent coding loops. Pure-Node modules with no VS Code dependency:

- **`agentLoop/severity.ts`** — derives a 4-level loop severity from the engine's 3-level severity × confidence: `Error`+`critical` → **critical** (always blocks), `Error` → **high** (blocks by default), `Warning` → **medium** (context), `Info` → **low** (never surfaced). Also owns the in-loop report format (max 5 findings, 8 kB cap, findings phrased as facts — never as instructions to the model).
- **`agentLoop/scanForLoop.ts`** — the shared single-file/changed-set pipeline: engine scan → drop Info → `.caspianignore` → `caspian.config.json` ignoreRules → baseline (`.caspian/baseline.json`, only NEW findings survive). Used by `caspian scan-file`, the `security_scan_file`/`security_scan_changes` MCP tools, and the plugin hooks — one implementation, no drift.
- **`fileConfig.ts`** — `caspian.config.json` loader (blockOn / ignoreRules / ignorePaths / maxFindingsInLoop). Can relax reporting; cannot disable the critical-finding block.
- **`gitWorkingTree.ts`** — working-tree + untracked changed-file resolution (the complement of `gitDiff.ts`, which is committed-diff only).
- **`hooks/`** — Claude Code hook sources: `preWriteGuard` (denies live credentials / wide-open platform rules / committable `.env`; asks on guardrail-file edits), `postWriteScan` (block-or-context feedback with a per-session loop guard), `stopGate` (blocks stopping on unresolved criticals, once per finding set). Bundled by esbuild into `plugin/hooks/` (committed) via `npm run build:plugin`. Every hook fails open.
- **`plugin/`** — the Claude Code plugin: manifest, `hooks/hooks.json`, bundled hooks, `.mcp.json` (spawns `caspian mcp` via npx), `/caspian-security:ship-check` command, and a `ship-check` skill.

### Security Rule Structure

```typescript
interface SecurityRule {
  code: string;                           // e.g., 'DB011'
  message: string;                        // User-facing message
  severity: SecuritySeverity;             // Error (2), Warning (1), Info (0)
  patterns: (RegExp | string)[];          // Detection patterns
  suggestion: string;                     // Fix recommendation
  category: SecurityCategory;             // 1 of 14 categories
  ruleType: RuleType;                     // CodeDetectable, Informational, ProjectAdvisory
  contextAware?: boolean;                 // Skip matches in comments/strings/JSX
  skipComments?: boolean;                 // Skip comments only — strings stay matchable
  confidence?: ConfidenceLevel;           // Author-declared base confidence
  suppressNearbyWindow?: number;          // ± lines scanned by suppressIfNearby (default 3)
  negativePatterns?: (RegExp | string)[]; // Suppress if safe pattern on same line
  suppressIfNearby?: RegExp[];            // Suppress if safe pattern within ±3 lines
  filePatterns?: {
    include?: RegExp[];                   // Only match files matching these
    exclude?: RegExp[];                   // Skip files matching these
    reduceSeverityIn?: RegExp[];          // Downgrade to Info in these files
  };
}
```

### confidenceAnalyzer.ts
- Classifies issues as `critical`, `safe`, or `verify-needed`
- Analyzes whether matched values are hardcoded literals vs. env references
- Applied to secret rules (CRED, AUTH001) and query rules (DB001, DB002)
- Used as the static prior by AdaptiveConfidenceEngine

### contextExtractor.ts
- Extracts enclosing function scope via VS Code DocumentSymbolProvider
- Traces variable definitions referenced in the vulnerable line
- Provides rich context for AI fix generation

### caspianIgnore.ts
- Parses `.caspianignore` files (format: `RULE_CODE filepath:line # reason`)
- Rule-specific, line-specific, and file-wide ignores
- File watcher for live reloading

### aiFixService.ts
- Provider abstraction for Anthropic Claude, OpenAI GPT-4, Google Gemini
- Secure API key storage via VS Code SecretStorage (OS keychain)
- Prompt engineering with function-scope context
- Response parsing with structured delimiters

### fixTracker.ts
- Tracks per-issue status: pending, fixed, ignored, verified, fix-failed
- Persists across VS Code restarts via workspaceState
- Summary statistics for progress bar display

### autoVerifier.ts
- Subscribes to ResultsStore.onWillUpdateFile to detect resolved findings
- Compares old vs new scan results and auto-marks resolved findings as verified
- Watches package.json and package-lock.json for changes, triggering quiet background dependency re-checks
- Line-drift guard prevents false verification when code findings shift lines
- Configurable via `caspianSecurity.autoVerify` setting

### resultsStore.ts
- Stores scan results per file with issues, language, and timestamps
- Fires onWillUpdateFile event before overwriting results (used by AutoVerifier)
- JSON, CSV, and SARIF v2.1.0 export
- Project advisory storage
- Scan metadata (duration, scan type)

### diagnosticsManager.ts
- Converts SecurityIssues to VS Code Diagnostic objects
- Maps severity levels (Error/Warning/Info)
- Attaches confidence prefixes and category labels

### configManager.ts
- Reads all `caspianSecurity.*` settings
- Category enable/disable toggles
- Language filtering
- AI provider and model configuration
- Informational toggle and internal-path severity settings

### statusBarManager.ts
- Scanning progress display
- Issue count summary with fix/ignore counts

### gitIntegration.ts
- Detects git repository
- Lists uncommitted files for targeted scanning

### dependencyChecker.ts
- Runs `npm outdated` and `npm audit`
- Checks Node.js, TypeScript, and VS Code engine versions
- Standalone CLI mode via `src/cli/checkUpdates.ts` (`--osv` flag)
- Opt-in OSV.dev multi-ecosystem check via `osvScanner.ts` (`caspianSecurity.osvCheck` / `--osv`); with OSV enabled, `package.json` is no longer required — npm checks are skipped and the OSV check still runs

### osvScanner.ts
- `vscode`-free (shared by extension and CLI)
- Parses root-level manifests: `requirements.txt` (PyPI), `go.mod` (Go), `Cargo.lock`/`Cargo.toml` (crates.io, lockfile preferred), `pom.xml` (Maven, simple `${property}` resolution), `Gemfile.lock` (RubyGems), `composer.lock` (Packagist)
- Batch-queries `api.osv.dev/v1/querybatch` (500 per batch), then fetches advisory details (`/v1/vulns/{id}`, capped at 60, 8 concurrent) for severity, summary, and fixed version
- Privacy: sends only dependency names/versions/ecosystems — never code; opt-in everywhere it is exposed
- Never throws: network and parse failures are collected into the result's `errors`

### Command-line & AI-agent integration (src/cli/, src/integration/)
- **scanRunner.ts** -- `vscode`-free workspace scan core (`runWorkspaceScan`) shared by every CLI and the MCP server, so terminal, CI, and agent runs use the exact same rule engine as the extension
- **cli/caspian.ts** -- unified `caspian` command; parses a subcommand (`scan`, `git-history`, `check-updates`, `mcp`, `snippet`, `mcp-config`, `help`, `--version`) and delegates to the exported entry of each specialised CLI. Each CLI exports an `argv`-taking function guarded by `if (require.main === module)` so both the standalone bin and the dispatcher reuse one implementation
- **cli/scan.ts / gitHistoryScan.ts / mcpServer.ts / checkUpdates.ts** -- the specialised CLIs / MCP server (stdio; four tools: `scan`, `scan_git_history`, `list_rules`, `explain_rule`)
- **integration/agentSnippets.ts** -- pure (no `vscode`/`fs`) generators for the paste-ready AI-agent instruction block and per-client MCP config; single source of truth imported by both `cli/caspian.ts` and `extension.ts`. Caspian only emits this text — it never writes into a target repo

### Task Management (taskTypes.ts, taskCatalog.ts, taskStore.ts, taskManager.ts, taskTreeProvider.ts, taskCommands.ts, taskDetailPanel.ts)
- **taskTypes.ts** -- Enums (TaskInterval, TaskStatus, AutoCompleteTrigger) and interfaces (SecurityTaskDefinition, TaskInstance)
- **taskCatalog.ts** -- 23 predefined recurring security tasks across all 14 categories with configurable intervals and auto-completion triggers
- **taskStore.ts** -- Per-project persistence via PersistenceManager to `security-tasks.json`; manages task state (complete, snooze, dismiss, interval override)
- **taskManager.ts** -- 15-minute scheduler for overdue detection and notifications; auto-completes tasks on workspace scan and dependency check events
- **taskTreeProvider.ts** -- `WebviewViewProvider` for the Security Tasks checklist; groups by status (Overdue, Pending, Completed, Snoozed, Dismissed), sorted by priority. Renders into **two surfaces** from one shared HTML template — the activity-bar sidebar view and, via `openTab()`, a full editor tab (`caspianSecurityTaskDashboard`, ViewColumn.One, singleton with reveal-if-open). A `data-surface` body attribute switches the tab to a wider, non-truncating layout; `sendData()` broadcasts task updates to every live surface so both stay in sync
- **taskCommands.ts** -- Registers 5 commands: taskAction, showTaskDetail, showTaskDashboard (opens the editor tab), refreshTasks, completeAllOverdue
- **taskDetailPanel.ts** -- Webview panel for detailed task view with interactive actions (complete, snooze, change interval, dismiss, reinstate); auto-refreshes on task store changes

### Learning Intelligence System (ruleIntelligence.ts, adaptiveConfidence.ts, fixPatternMemory.ts, codebaseProfile.ts, scanInsights.ts, telemetryService.ts, learningPanel.ts)
- **ruleIntelligence.ts** -- Per-rule effectiveness tracking: detections, FP rates, fix rates, AI fix success rates, resolution times, broken down by language and file pattern. Persists to `rule-intelligence.json` (2000ms debounce). Provides `getLikelyRealScore()` for ranking issues by real-world likelihood
- **adaptiveConfidence.ts** -- Bayesian confidence engine that uses static `classifyConfidence()` as prior and adjusts based on learned data. Downgrades rules with >70% FP rate, upgrades rules with >80% fix rate. Applies file-path context (test files reduce confidence, source files with high fix rates boost confidence)
- **fixPatternMemory.ts** -- Caches successful AI fixes as normalized patterns (variable names → `$VAR1`, strings → `$STRING`). Offers instant replay for similar issues without API calls. Max 500 patterns with LRU eviction. Persists to `fix-patterns.json` (3000ms debounce)
- **codebaseProfile.ts** -- Project-specific intelligence: learns safe functions from AI fixes and FP dismissals (e.g., `DOMPurify.sanitize` neutralizes XSS rules), tracks hot zones by directory risk density, monitors security posture trend, detects regressions. Persists to `codebase-profile.json` (5000ms debounce)
- **scanInsights.ts** -- On-demand insight generation: trend analysis, noisy rule detection, regression alerts, hot zone identification, fix pattern availability, AI fix effectiveness, category completion celebrations. Computed from all learning stores, not persisted
- **telemetryService.ts** -- Opt-in anonymized rule stats sent daily to developer endpoint (no code, paths, or project names). User can preview exact payload. First-run prompt with "View What's Shared" option. Fire-and-forget HTTPS POST
- **learningPanel.ts** -- Webview dashboard: overview stats, sortable rule effectiveness table, fix pattern library, hot zones, security trend visualization, active insights with action buttons, reset/export controls

## Configuration Schema

```json
{
  "caspianSecurity.autoCheck": true,
  "caspianSecurity.checkOnSave": true,
  "caspianSecurity.severity": "warning",
  "caspianSecurity.enabledLanguages": ["javascript", "typescript", "python", "java", "csharp", "php", "go", "rust"],
  "caspianSecurity.includeDependencyCheck": true,
  "caspianSecurity.showInformational": true,
  "caspianSecurity.reduceInternalPathSeverity": true,
  "caspianSecurity.aiProvider": "anthropic",
  "caspianSecurity.aiModel": "",
  "caspianSecurity.enable<Category>": true,
  "caspianSecurity.enableTaskManagement": true,
  "caspianSecurity.taskReminders": true,
  "caspianSecurity.enableTelemetry": false
}
```

## Performance

- **Debouncing**: 1-second delay prevents lag during typing
- **Language filtering**: Only analyzes supported languages
- **Lazy initialization**: Rules created once at startup
- **Regex compilation**: Patterns compiled once
- **Early exit**: Skips untitled and non-file documents
- **Batch scanning**: Workspace scans grouped by language in batches of 50
- **Event loop yielding**: Between every file during workspace scan to keep UI responsive
- **Generated/minified file skip**: Path-based detection (`.min.*`, `.bundle.*`, `/dist/`, etc.) and content heuristics (avg line length, generation markers)
- **File size limit**: Configurable `maxFileSize` (default 500KB) skips oversized files before analysis
- **Line length guard**: Lines over 2,000 characters are skipped to prevent regex backtracking on minified code
- **Per-file timeout**: Analysis is capped at 3 seconds per file to prevent any single file from freezing VS Code
- **Informational dedup**: Informational rules collect up to 10 candidates, fire once per file

## File Sizes

| File | Lines | Purpose |
|------|-------|---------|
| `extension.ts` | ~2400 | Main entry, commands, scanning, AI fix workflow, learning integration |
| `resultsPanel.ts` | ~810 | Webview results panel |
| `analyzer.ts` | ~405 | Rule engine with context-aware analysis + adaptive confidence |
| `aiFixService.ts` | ~280 | AI provider abstraction |
| `aiSettingsPanel.ts` | ~300 | AI configuration webview |
| `resultsStore.ts` | ~180 | Results storage + SARIF export |
| `configManager.ts` | ~160 | Configuration management |
| `fixTracker.ts` | ~150 | Issue status persistence |
| `contextExtractor.ts` | ~120 | Function scope + variable tracing |
| `confidenceAnalyzer.ts` | ~80 | Confidence classification |
| `caspianIgnore.ts` | ~80 | Ignore file parsing |
| `statusBarManager.ts` | ~85 | Status bar integration |
| `diagnosticsManager.ts` | ~60 | VS Code diagnostics |
| `gitIntegration.ts` | ~50 | Git SCM integration |
| `dependencyChecker.ts` | ~250 | Dependency + stack checking |
| `osvScanner.ts` | ~400 | OSV.dev multi-ecosystem dependency check |
| `taskTypes.ts` | ~75 | Task data models and enums |
| `taskCatalog.ts` | ~210 | 23 predefined security task definitions |
| `taskStore.ts` | ~180 | Task persistence via PersistenceManager |
| `taskManager.ts` | ~165 | Scheduler, auto-completion, quick pick UI |
| `taskTreeProvider.ts` | ~420 | Task checklist webview -- sidebar view + editor tab |
| `taskCommands.ts` | ~55 | Task command registration |
| `taskDetailPanel.ts` | ~470 | Webview panel for task details and actions |
| `ruleIntelligence.ts` | ~280 | Per-rule effectiveness tracking |
| `adaptiveConfidence.ts` | ~100 | Bayesian confidence with learned priors |
| `fixPatternMemory.ts` | ~300 | Cached AI fix patterns for instant replay |
| `codebaseProfile.ts` | ~345 | Project-specific learned patterns |
| `scanInsights.ts` | ~230 | Actionable intelligence generation |
| `telemetryService.ts` | ~240 | Opt-in anonymized rule stats |
| `learningPanel.ts` | ~300 | Learning dashboard webview |
| `rules/` (14 files) | ~1200 | 309 security rule definitions (301 pattern + 8 taint) |
| **Total** | **~7950+** | |

**Memory usage**: ~5-10 MB
**Analysis time**: ~50-200ms per file
