# Changelog

All notable changes to the Caspian Security extension are documented in this file.

---

## [10.13.0] - 2026-08-14

The Security Tasks checklist now opens in the main editor window. Previously it existed only in the narrow activity-bar column, where task titles and dates were truncated and there was no way to open it anywhere else.

### Added

- **"Open Security Tasks in Editor" title-bar button** on the Security Tasks view — the `$(preview)` icon next to Refresh opens the checklist as a full editor tab, matching the affordance in Caspian Taskmaster and Caspian Notes. Clicking it again reveals the existing tab rather than opening a duplicate.
- **Editor-tab layout** for the checklist: task titles and metadata wrap instead of being cut off with an ellipsis, groups get roomier spacing, and the content is centred in a readable column. The sidebar rendering is unchanged.
- Both surfaces render from one shared template and stay live-synced from the same `TaskStore` — completing or refreshing tasks updates the sidebar and the editor tab at once.

### Changed

- **`Caspian Security: Show Security Tasks` is now `Caspian Security: Open Security Tasks in Editor`** and opens the editor tab instead of re-focusing the sidebar. This also upgrades the two places that already linked to it: the tasks link in the Results panel, and the **Show Tasks** button on the overdue-task notification.
- Security Tasks title-bar buttons now use explicit ordering (`navigation@1` Refresh, `navigation@2` Open in Editor) so their order is deterministic.

### Fixed

- `TaskChecklistViewProvider` no longer carried a private copy of `getNonce()` — it now uses the shared helper in `webviewUtils.ts`.

---

## [10.12.1] - 2026-08-03

Security-documentation catch-up for the agent-loop release — no behaviour change. THREAT_MODEL.md's own rule says design changes update it in the same PR; 10.12.0 missed that, this closes the gap.

### Changed

- **[THREAT_MODEL.md](THREAT_MODEL.md)** — modeled the agent-loop surface added in 10.12.0: two new assets (enforcement integrity, execution inside subscribers' agent sessions), trust boundaries 6–9 (hook stdin, agent-writable guardrail files, MCP tool arguments, the plugin's repo-as-supply-chain distribution), a new adversary class **G — the coding agent in the loop** (misaligned by incentive, includes prompt-injected agents) with its mitigations, and three honestly-stated residual risks: hooks fail open by design, Bash writes bypass the Write/Edit hooks (stop gate partially compensates), and loop-guard state is only as private as the OS temp dir.
- **[SECURITY.md](SECURITY.md)** — scope now includes the MCP server, the plugin hook bundles, and the agent-loop CLI commands (`scan-file`, `ship-check`, `baseline accept`, `init`); clarified that agent-driven enforcement bypasses are security bugs, not rule false-negatives.

---

## [10.12.0] - 2026-08-03

Agent-loop integration: Caspian now runs INSIDE AI-agent coding loops (Claude Code, Cursor, and any MCP client), so vulnerabilities in AI-generated code are caught and fixed by the agent before a human ever sees them.

### Added

- **Claude Code plugin** (`plugin/`, installable from this repo) with three hooks:
  - `pre-write-guard` (PreToolUse) — denies a write outright when it contains a live provider credential, a wide-open Firebase/Supabase rule, or would commit a non-gitignored `.env` file; **asks** before the agent edits Caspian's own guardrail files (`.caspian/baseline.json`, `caspian.config.json`, `.caspianignore`).
  - `post-write-scan` (PostToolUse) — scans every file the agent writes; critical/high findings block (exit 2) and feed back to the model for same-turn self-correction, medium findings arrive as non-blocking context, clean files stay silent. A loop guard downgrades any finding that has already blocked twice, caps blocking at 20 events per session, and every failure mode fails open.
  - `stop-gate` (Stop) — final gate when the agent says "done": unresolved **critical** findings in the working tree block the stop, once per finding set per session.
  - Hooks ship as committed esbuild bundles (`npm run build:plugin`) — cold start measured at 55–110 ms, no npx in the hook path.
- **Deploy-config rule pack** (`DEPLOY001`–`DEPLOY010`, 10 new rules — total now 309): open Firestore/Storage rules (`allow write: if true`), world-readable rules, Supabase `disable row level security` and `using (true)` no-op policies, service-role keys and secrets behind client-bundled env prefixes (`NEXT_PUBLIC_`, `VITE_`, …), AI/LLM endpoints with no rate limit, and open Realtime Database rules. `.rules`, `.sql`, and `database.rules.json` files are now scanned by default.
- **Three new MCP tools** (total now seven): `security_scan_file` (single file, only NEW findings beyond the baseline), `security_scan_changes` (working tree + optional `base` ref, only NEW findings), and `check_deployment_security` (the pre-deploy gate — pre-existing issues included on purpose). Deliberately absent: any tool that suppresses findings or edits scanner config — the agent cannot turn the scanner off.
- **New CLI commands**: `caspian scan-file <file>` (agent-loop twin of the hook), `caspian ship-check` (deploy check + git-tracked credential files), `caspian baseline accept` (CLI-only baseline acceptance at `.caspian/baseline.json`), and `caspian init` (one-command setup: merges `.mcp.json`, writes idempotent marker-delimited rules blocks into CLAUDE.md/AGENTS.md/.cursorrules, runs the initial baseline scan).
- **`caspian.config.json`** — headless config shared by hooks, CLI, and MCP: `blockOn`, `ignoreRules`, `ignorePaths`, `maxFindingsInLoop`. It can relax reporting but can never disable the critical-finding block.
- **Derived 4-level loop severity** (critical/high/medium/low) mapped from the engine's severity × confidence, shared by hooks, `scan-file`, `ship-check`, and the new MCP tools.
- `explain_rule` now reports `has_mechanical_fix` for the 17 rules with registered auto-fixes.

### Fixed

- **`.caspianignore` was only honoured by the VS Code extension** — the CLI (`caspian scan`) and the MCP `scan` tool now apply it too, so CI and agents agree with the editor about dismissed findings.

---

## [10.11.1] - 2026-08-03

Documentation accuracy pass ahead of the Marketplace release — no behaviour change.

### Fixed

- **Marketplace listing understated the rule count** — the `package.json` `description` (the blurb shown on the VS Code Marketplace and Open VSX) advertised "295+ rules" and "28 provider-prefix secret detectors". Verified actuals: **299 rules** (291 pattern + 8 taint) and **29** provider-prefix detectors. Corrected in the description, `README.md`, `docs/USER_GUIDE.md` and `docs/user-guide.html`.
- **User guides were pinned to v10.6.1** — five releases stale. Version badges, `--version` sample output, and the `code --install-extension caspian-security-<v>.vsix` example now reflect the current release.
- **Copy-paste GitHub Action snippets pinned to old tags** — `README.md` pinned `@v10.2.0` and `.github/examples/caspian-scan.yml` pinned `@v9.3.0`. Both now point at the current release tag, so a user copying the snippet gets this version's engine.

---

## [10.11.0] - 2026-08-02

False-positive cleanup driven by dogfooding: every fix below came from running Caspian against its own source and triaging what it flagged. Measured effect on that self-scan: **197 → 165 findings (32 fewer false positives, ~16% less noise)** with no loss of true detections.

### Added

- **`skipComments` rule option** — suppresses matches inside comments while **still matching string literals**. This is deliberately narrower than the existing `contextAware`, which also suppresses strings and would silently break rules that must match string content (DEP001 exists to find `"^1.2.3"` inside `package.json`). Commented-out code isn't running code, so it shouldn't raise behavioural findings.
- **Applied by default to Informational rules** at the registry (**[src/rules/index.ts](src/rules/index.ts)**), so new reminder rules inherit it automatically — 65 rules in total. **Provider-token detectors are explicitly exempt**: a credential pasted into a comment is still a leaked credential, and a regression test asserts that a token in a `//` comment is still reported.
- `falsePositiveTuning.test.ts` — 15 regression tests pinning every case below, including the "secret in a comment is still found" guarantee and the "string literals stay matchable" distinction.

### Fixed

- **`CRED007` matched property access, not just filenames** — the pattern `\.env\b` matched `process.env.API_KEY` and `vscode.env.clipboard`, so it fired in virtually every Node/TypeScript project. Now requires `.env` to begin a path segment: `.env`, `./.env` and `".env.local"` still match; `process.env` no longer does.
- **`LOG009` matched the `export` keyword** — its `(export|download).*(data|report|csv|pdf)` pattern meant ordinary TypeScript declarations like `export function scanFileBatch(data: …)` were flagged as data-export operations, firing in **22% of Caspian's own source files**. Retargeted at genuine export *operations* (`exportData()`, `/api/export` routes) rather than the language keyword.
- **`DEP001` / `DEP002` were ungated** — dependency-manifest rules (looking for `"^1.2.3"`, `"dependencies":`, `require(`) ran against every source file, so DEP001 flagged the `'*'` literals inside a glob parser and DEP002 flagged every `require()` call. Both are now restricted via `filePatterns` to actual manifests (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, `Gemfile`, `composer.json`, …).
- **`HDR005`, `API010`, `CRED007`, `BIZ007` fired on code comments** — e.g. the prose `res.json(token)` and `req.params.id` inside explanatory comments. Resolved by the `skipComments` default above.

---

## [10.10.1] - 2026-08-01

Fixes a silent detection failure on Windows, found by the `windows-latest` CI leg added in 10.9.0 on its very first run.

### Fixed

- **CRLF files silently lost findings** — Git on Windows checks files out with CRLF by default, and the scan engine split on `\n`, leaving a trailing `\r` on every line. Any rule pattern anchored to end-of-line (`$`) then failed to match. On the vulnerable corpus this silently dropped `TAINT001`, `TAINT003`, `TAINT006` and `TAINT007` and produced a spurious `TAINT008` — i.e. Windows users with CRLF line endings were getting materially different, wrong results with no indication anything was missed. A new shared `normaliseLineEndings` helper (**[src/scanContext.ts](src/scanContext.ts)**) is now applied at every scan entry point: `scanFile`, `buildLineStates`, `runTaintAnalysis`, the analyzer's project-advisory pass, and the git-history secret scanner's diff-line reader. Only `\r\n` is rewritten — never a lone `\r` — so line counts and column offsets are preserved exactly and diagnostics still point at the right place.
- New `lineEndings.test.ts` asserts that every vulnerable- and clean-corpus fixture produces **identical findings at identical line and column** under CRLF, plus unit coverage for the helper, `buildLineStates`, and the taint engine. Windows CI deliberately keeps its CRLF checkout, so this path is exercised on every run.
- **AI-fix path on CRLF files** — the same normalisation now applies where **[src/extension.ts](src/extension.ts)** extracts the offending line from a document. A trailing `\r` there leaked into the AI fix prompt and into the fix-pattern-memory cache key, which meant a fix learned in an LF file would never replay in a CRLF file (and vice versa).

---

## [10.10.0] - 2026-08-01

Phase B, final batch: much wider rule test coverage, parallel CLI scanning for large repos, and a slimmer VSIX.

### Added

- **Parallel CLI scanning** — `caspian scan` now scans across worker threads on large file sets, with a new `--concurrency <n>` flag (defaults to the CPU count; small scans still run inline to avoid thread overhead). Output is byte-for-byte identical to the single-threaded scan (results are sorted by path). New shared `scanFileList` helper backs the sync scan, the worker, and the CLI so all three filter files identically.
- **Rule behaviour coverage 44 → 109 codes** — three new vulnerable-corpus fixtures (`flask-service.py` for Python injection/deserialization/SSRF/XXE/LDAP/crypto, `webapp.js` for auth/CORS/CSRF/API/frontend, `MainActivity.kt` for the Android `KT-*` family) plus direct assertions for 9 provider-token (`TOKEN*`) shapes, all with confidence checks. Synthetic tokens are assembled at runtime so no token-shaped literal is committed.

### Changed

- **Smaller VSIX** — `tsconfig.json` no longer emits `.d.ts` declarations or `.js.map` source maps (this package is an app, not a typed library). The packaged extension dropped from 330 files / ~625 KB to 118 files / ~432 KB. Neither is needed by the extension host or the CLI at runtime; flip the flags on locally for debugging.

---

## [10.9.0] - 2026-08-01

Phase B of the trust roadmap: every finding now carries a confidence rating (previously ~2 of 291 rules produced one on a fresh install), five new one-click fixes (13 → 18), CI now tests on Windows with a coverage gate, and the results panel stays responsive on scans with tens of thousands of findings.

### Added

- **Confidence on every finding** — confidence now resolves as: per-match variable-source heuristics → the rule's author-declared base confidence (new optional `confidence` field on `SecurityRule`) → a default by rule type (code detections → `verify-needed`, informational reminders → `safe`). All 29 provider-prefix TOKEN rules and every code-detectable Kubernetes/Terraform/Dockerfile rule carry base confidence `critical` — their patterns are essentially never accidental. The CLI's `--format json` exposes it as `confidence`. Covered by a new `confidence.test.ts` suite.
- **Five new one-click quick fixes** (18 total): `ENC001` weak hash (`createHash('md5'|'sha1') → 'sha256'`, `hashlib.md5/sha1 → hashlib.sha256`), `ENC003` `http:// → https://` (never touches localhost), `TF002` S3 public-access-block flags (`block_public_acls = false → true` and friends), `DOCKER005` `ADD → COPY` for local paths (never URLs), `DOCKER006` `apt-get install` gains `--no-install-recommends` / `apk add` gains `--no-cache`.
- **CI hardening** — the test matrix now includes `windows-latest` (the codebase has Windows path-normalisation logic that was only ever exercised on Linux) and Node 22, and runs `npm run test:coverage` with a coverage ratchet in `jest.config.js` (60% statements / 52% branches to start — raise as coverage grows, never lower).

### Changed

- **Results panel scales to huge scans** — the findings table renders 500 rows initially with a "Show more" row (rendering everything froze the webview on 10k+ findings), and all row/button clicks go through one delegated listener instead of thousands of per-element listeners re-attached on every refresh.

---

## [10.8.0] - 2026-08-01

Trust release: fixes a bug that silently reported unchanged files as clean after every VS Code restart, stops learning data from being lost on shutdown, makes the advertised Dockerfile/Terraform/Kubernetes rules actually run inside the editor, and consolidates the three divergent copies of the scan engine into one shared implementation covered by a greatly expanded test suite (1,134 tests, up from 1,046).

### Fixed

- **Silent false negatives after restart** — **[src/fileStateTracker.ts](src/fileStateTracker.ts)**, **[src/extension.ts](src/extension.ts)**: cached issues are never persisted (by design, to avoid writing matched secrets to disk), but entries restored from a previous session still answered the cache lookup with an empty issue list. On the first workspace scan after any VS Code restart, every unchanged file was therefore reported as having zero issues without being scanned. Restored entries now force a real re-scan; covered by a restart-simulation regression test.
- **Learning data lost on shutdown** — **[src/persistenceManager.ts](src/persistenceManager.ts)**: `dispose()` cancelled pending debounced writes instead of flushing them, dropping up to 2s of rule intelligence, false-positive dismissals, and file-state cache on every extension shutdown. Pending writes are now flushed synchronously on dispose (`ruleIntelligence.ts` likewise writes through instead of scheduling a timer that never fires).
- **Infrastructure rules never ran in the editor** — **[src/configManager.ts](src/configManager.ts)**, **[src/extension.ts](src/extension.ts)**: the extension's language list had no yaml/terraform/dockerfile entries, so the 26 Dockerfile, Terraform, and Kubernetes rules only worked in the CLI. The editor now scans `.yaml`/`.yml`, `.tf`/`.tfvars`/`.hcl`, and `Dockerfile`/`Containerfile` files (workspace scans and on-type/on-save), with path-based language resolution so `.tf` files work even without the HashiCorp extension. Kotlin was also added to the default `enabledLanguages`, and `.mts`/`.cts` to the CLI's extension map.
- **Broken rules that always (or never) fired** — TF005's multi-line lookahead could never see the resource body in a line-scoped engine, so it flagged every S3 bucket and RDS instance regardless of encryption settings; it now uses nearby-line suppression (and the S3 pattern was dropped — S3 has been encrypted-at-rest by default since 2023). DOCKER002, HDR001–004, XSS006, and XSS012 looked for their suppressing line (e.g. `USER app`, `helmet()`, `express.json()`) within ±3 lines when it legitimately lives far away; rules can now declare a wider `suppressNearbyWindow`.
- **Taint-engine false positives** — **[src/taint.ts](src/taint.ts)**: a sanitizer applied in the same assignment (`const id = Number.parseInt(req.params.id, 10)`) no longer taints the variable, and `process.env`/`os.environ` are no longer treated as attacker-controlled sources (env vars are trusted deployment config; they made `jwt.sign(..., process.env.KEY)` → `res.json(token)` flows light up as XSS).
- **Generated-file detector skipped real source files** — **[src/generatedFileDetector.ts](src/generatedFileDetector.ts)**: a bare `/webpack/i` (and `rollup`/`parcel`) content marker skipped ANY file mentioning a bundler in its first 500 characters — including `webpack.config.js` and files importing the bundler. Detection now matches actual bundler output artifacts (`webpackBootstrap`, `__webpack_require__`).
- **Typing in one file cancelled another file's pending scan** — **[src/extension.ts](src/extension.ts)**: the 1s as-you-type debounce used a single shared timer; it is now per-document.
- **SARIF tool version stuck at 7.0.0** — the extension's SARIF export hardcoded `version: '7.0.0'`; both exporters now share one writer (**[src/sarif.ts](src/sarif.ts)**) that reads the real package version, with the O(n²) `ruleIndex` lookup fixed.
- **`--include` glob support** — **[src/scanRunner.ts](src/scanRunner.ts)**: the CLI documented `--include <glob>` but implemented a substring match, so `--include *.proto` matched nothing. Real glob matching (`*`, `**`, `?`) is now supported; plain substrings still work.

### Changed

- **One scan engine instead of three** — **[src/scanRunner.ts](src/scanRunner.ts)** is now the single scan implementation. `src/cli/scan.ts` deletes its private ~270-line copy of the walk/scan loop and imports the shared engine; **[src/analyzer.ts](src/analyzer.ts)** delegates its matching loop to the same `scanFile` (wiring in adaptive confidence, learned suppression, and config gates as hooks). Editor, CLI, and MCP server can no longer drift apart — and CLI/MCP findings now carry the same JSX-awareness and `confidenceLevel` as the editor (exposed as `confidence` in `--format json`).
- **Faster scans** — file-level rule filters (`ruleType`, `filePatterns`) are applied once per file instead of once per line×rule (hundreds of thousands of redundant path-regex evaluations removed on large files); string patterns are lower-cased once at rule preparation instead of per line; project advisories are collected during the main scan pass instead of a second full re-scan of every file; the file-state store snapshots once per debounced write instead of deep-cloning per scanned file (O(N²) → O(N)); scanned text is hashed from the already-loaded document instead of re-reading every file from disk; the workspace loop yields with `setImmediate` instead of a ~1ms-clamped `setTimeout(0)` per file; the taint pass budget now covers function-range discovery, skips nested (already-walked) ranges, and caches identifier regexes.
- **CLI default excludes** now also skip `.venv`, `venv`, `bower_components`, and `.terraform`.
- **`enablePersistentCache`** now gates loading the change-detection cache itself; the dead "restore cached results" path (which could never restore anything, since issues are not persisted) was removed.

### Added

- **Clean-corpus false-positive guard** — `src/__tests__/fixtures/clean-corpus/` holds idiomatic secure Express/Python/Terraform/Kubernetes/Dockerfile fixtures that must produce zero Error/Warning findings; this suite caught 9 real false positives on its first run (all fixed above).
- **Engine test suite** — `scanRunner.test.ts` (walk, language resolution, include globs, scan semantics, advisory collection, confidence/suppression hooks), `cliScan.test.ts` (argument parsing, severity gating, exit-threshold logic, formatters), `sarif.test.ts` (SARIF 2.1.0 shape, level mapping, ruleIndex consistency, real tool version), `persistence.test.ts` (dispose-flush and the restart-simulation regression), `generatedFileDetector.test.ts`. The vulnerable-corpus suite now exercises the real shared engine instead of a hand-copied reimplementation.
- **ReDoS guard at real line length** — adversarial inputs in `redosGuard.test.ts` grew from 200 to 2,000 characters (the scanner's actual per-line cap), so polynomial backtracking that only shows at real-world lengths is caught at build time.
- **`suppressNearbyWindow`** on `SecurityRule` — rules with whole-file suppression semantics (Dockerfile USER, helmet middleware, body-parser registration) can widen the `suppressIfNearby` scan window beyond the default ±3 lines.

---

## [10.7.3] - 2026-07-15

Makes the advertised one-command AI-agent integration actually run. Every documented zero-install command used the shape `npx -y caspian-security caspian <sub>`, but npx could not resolve it: the package ships five bins and none was named `caspian-security`, so npx errored with *"could not determine executable to run"*. This adds a `caspian-security` bin (aliasing the unified CLI) so `npx -y caspian-security <sub>` — and `claude mcp add caspian-security -- npx -y caspian-security mcp` — work directly, with no `-p` flag or `add-json` workaround needed.

### Added

- **[package.json](package.json)** — new `caspian-security` bin (→ `out/cli/caspian.js`, the unified dispatcher) so npx resolves the package name to a runnable command. `npx -y caspian-security scan .` / `… mcp` / `… git-history` now work zero-install, matching the package's "one-command" promise.

### Fixed

- **[src/integration/agentSnippets.ts](src/integration/agentSnippets.ts)** — the copy-paste command generator (single source of truth for the `caspian` CLI and the VS Code **Copy AI Agent Instructions** command) dropped the redundant `caspian` token from `SCAN_COMMAND`, `PR_SCAN_COMMAND`, the emitted MCP `.mcp.json` args (now `["-y", "caspian-security", "mcp"]`), and the `claude mcp add` note.
- **Docs** — README, USER_GUIDE (Markdown + HTML), QUICKSTART, SETUP_GUIDE, and BUILD now use the working `npx -y caspian-security <sub>` form everywhere.

### Changed

- **[src/cli/caspian.ts](src/cli/caspian.ts)** — the dispatcher strips a redundant leading `caspian` token, so any command copied from pre-10.7.3 docs (`npx -y caspian-security caspian mcp`) keeps working. Covered by a new dispatcher test.

---

## [10.7.2] - 2026-07-15

npm packaging fix so the standalone CLI actually ships. npm 11's publish-time normalization silently strips `bin` entries whose paths start with `./`, which meant the `caspian` CLI commands were dropped from the published npm package. Paths are now bare-relative so the five console commands install correctly via `npm install -g caspian-security`.

### Fixed

- **[package.json](package.json)** — `bin` paths changed from `./out/cli/*.js` to `out/cli/*.js`. npm 11's publish normalization rejected the `./`-prefixed values (`"bin[caspian]" script name ... was invalid and removed`), which would have published the package without any of its `caspian`, `caspian-scan`, `caspian-git-history-scan`, `caspian-check-updates`, or `caspian-mcp` executables.

---

## [10.7.1] - 2026-07-12

First automated release. Ships everything in 10.7.0 (the OSV.dev multi-ecosystem dependency check — see below) plus the release pipeline itself.

### Added

- **[.github/workflows/release.yml](.github/workflows/release.yml)** — release workflow (manual dispatch or `release/**` branch push): runs lint/compile/test, packages the VSIX, creates the `vX.Y.Z` tag and GitHub Release with the VSIX attached, and publishes to the VS Code Marketplace / Open VSX when the `VSCE_PAT` / `OVSX_PAT` repository secrets are configured (publish steps skip with a notice otherwise; the release step is idempotent so the workflow can be re-run after adding secrets).

---

## [10.7.0] - 2026-07-12

Multi-ecosystem dependency scanning via OSV.dev. The dependency check is no longer npm-only: opt in and Caspian also checks Python, Go, Rust, Java, Ruby, and PHP manifests against the OSV.dev vulnerability database (Google/GitHub-backed, aggregates the GitHub Advisory Database). Privacy-first: only dependency names and versions are sent — never code — and the check is off by default.

### Added

- **[src/osvScanner.ts](src/osvScanner.ts)** — OSV.dev scanner: parses `requirements.txt` (PyPI), `go.mod` (Go), `Cargo.lock`/`Cargo.toml` (crates.io, lockfile preferred), `pom.xml` (Maven, with simple `${property}` resolution), `Gemfile.lock` (RubyGems), and `composer.lock` (Packagist) from the project root, batch-queries `api.osv.dev/v1/querybatch`, fetches advisory details (severity, summary, fixed version), and never throws — network failures land in `errors`.
- **`caspian check-updates --osv`** — CLI flag enabling the OSV.dev check; `check-updates` also gained `--help`. High/critical OSV advisories now contribute to the exit-code-1 gate alongside `npm audit`.
- **`caspianSecurity.osvCheck`** VS Code setting (default `false`) — enables the OSV.dev check during **Check Dependency Updates**. Findings appear in the Output panel report and as `DEP-OSV` issues attached to the manifest they came from.
- **Non-npm projects supported** — with the OSV check enabled, the dependency check no longer requires a `package.json`; npm-specific checks are skipped and the OSV.dev check still runs.

### Changed

- `checkDependencies()` accepts a `DependencyCheckOptions` object (`{ includeOsv }`) and returns an optional `osv` result block; the text report gained an "OSV.DEV MULTI-ECOSYSTEM CHECK" section and a summary line.

---

## [10.6.1] - 2026-07-01

Documentation release — a comprehensive user guide and a standing rule to keep docs in sync.

### Added

- **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** — comprehensive user guide covering installation, the standalone `caspian` CLI (every subcommand, flags, exit codes, baselines, PR-scope), VS Code usage, AI-agent integration (CLAUDE.md snippet + MCP for Claude Code / Cursor / Antigravity / Claude Desktop / Cline), CI/CD, configuration, output formats, rule categories, severity/confidence, troubleshooting, and a command cheat sheet.
- **[docs/user-guide.html](docs/user-guide.html)** — self-contained, styled HTML version of the same guide (no external dependencies).
- **GitHub Wiki "User Guide" page** mirroring `docs/USER_GUIDE.md`, linked from the sidebar and Home.
- Discoverability pointers to the guide from `README.md` and `START_HERE.md`.

### Changed

- **CLAUDE.md** — added a Global Rule: any update must trigger a documentation update when relevant, keeping `docs/USER_GUIDE.md`, `docs/user-guide.html`, and the wiki User Guide in sync. Updated the wiki clone URL to the moved `CaspianTools/caspian-security` location.

---

## [10.6.0] - 2026-07-01

Caspian goes anywhere. One unified `caspian` command turns the scanner into a robust standalone tool you can run from a normal PowerShell / cmd / bash terminal — no VS Code required — and makes it a one-line integration for any AI coding agent (Claude Code, Cursor, Antigravity, Claude Desktop, Cline). Nothing is ever written into your repositories; Caspian only emits text and config you choose to paste.

### Added

- **[src/cli/caspian.ts](src/cli/caspian.ts)** — new unified `caspian` command (bin) that fronts every capability: `caspian scan | git-history | check-updates | mcp | snippet | mcp-config | help | --version`. Install globally (`npm i -g caspian-security` → `caspian scan .`) or zero-install (`npx -y caspian-security caspian scan .`). Works in PowerShell, cmd, and bash.
- **[src/integration/agentSnippets.ts](src/integration/agentSnippets.ts)** — single source of truth for AI-agent integration text, shared by the CLI and the extension (no `vscode`/`fs` dependency). `buildAgentInstructions()` produces a plain-language block to paste into `CLAUDE.md` / Cursor Project Rules / Antigravity rules; `buildMcpConfig()` / `formatMcpConfigForDisplay()` produce per-client MCP config.
- **`caspian snippet [--agent claude|cursor|antigravity|generic] [--mode request|after-edits|pre-commit]`** — prints a ready-to-paste instruction block so any agent can run Caspian mid-task via `npx`, with zero setup in the target repo.
- **`caspian mcp-config [--client claude-code|claude-desktop|cursor|antigravity|cline]`** — prints the MCP server config with the correct file path for that client.
- **Two VS Code commands** — *"Caspian Security: Copy AI Agent Instructions"* and *"Caspian Security: Copy MCP Server Config"*. Both copy-to-clipboard only; they never write into a repo.
- **Unit tests** — [src/__tests__/agentSnippets.test.ts](src/__tests__/agentSnippets.test.ts) and [src/__tests__/caspian.test.ts](src/__tests__/caspian.test.ts) cover snippet/config generation and dispatcher routing/validation.

### Changed

- CLI entry points (`scan.ts`, `gitHistoryScan.ts`, `checkUpdates.ts`, `mcpServer.ts`) now export an `argv`-taking function (`runScanCli` / `runGitHistoryCli` / `runCheckUpdatesCli` / `startMcpServer`) guarded by `if (require.main === module)`, so the unified dispatcher reuses the exact same implementation with no duplication. The original `caspian-scan` / `caspian-git-history-scan` / `caspian-check-updates` / `caspian-mcp` bins are unchanged.
- MCP documentation now covers Claude Code (`.mcp.json` / `claude mcp add`) and Antigravity in addition to Claude Desktop / Cursor / Cline; the recommended command shape is `npx -y caspian-security caspian mcp`.
- `package.json` `description` updated to reflect the standalone CLI and AI-agent integration.

---

## [10.5.1] - 2026-05-07

Maintenance release — marketplace re-publish with refreshed `package-lock.json`. No functional changes from 10.5.0.

### Changed

- `package-lock.json` regenerated against current `npm install` to keep the lockfile aligned with the published version.

---

## [10.5.0] - 2026-04-21

The lightbulb release. Hover on a Caspian finding, press Ctrl+. (or click the yellow lightbulb), and get a deterministic one-click fix for the 13 most common mechanical remediations — no AI round-trip, no waiting on a consent dialog, no spend on provider tokens.

### Added

- **[src/codeActionFixes.ts](src/codeActionFixes.ts)** — pure-function fix registry. Each entry takes a minimal `DocumentView` + the issue's line/column and returns a `FixResult` (edits + title). No `vscode` import, fully unit-testable.
- **[src/codeActionProvider.ts](src/codeActionProvider.ts)** — thin `vscode.CodeActionProvider` wrapper that converts `FixResult`s into `vscode.CodeAction` quick-fixes. Registered for every enabled language plus `dockerfile`, `yaml`, `terraform`, and glob patterns for `**/Dockerfile` / `**/*.tf` / `**/*.tfvars` / `**/*.hcl` / `**/*.yaml`.
- **13 mechanical fixes** across every major rule family:
  - **Kubernetes** — `K8S001` flip `privileged: true→false`, `K8S002` remove `hostNetwork: true` line, `K8S003` remove `hostPID`/`hostIPC: true` line, `K8S004` fix `runAsUser: 0` → `runAsUser: 1000` OR `allowPrivilegeEscalation: true→false`.
  - **Terraform** — `TF002` flip `acl = "public-read"` to `"private"`, `TF004` flip `publicly_accessible = true→false`.
  - **JWT** — `JWT002` insert `{ algorithms: ['RS256'] }` as third arg to `jwt.verify(token, key)`, `JWT006` remove `ignoreExpiration: true` or flip `verify_exp=False→True`.
  - **Python deserialisation** — `DESER003` rename `yaml.unsafe_load → yaml.safe_load`, `DESER004` rename `yaml.load( → yaml.safe_load(` (skips if `SafeLoader` already specified).
  - **TLS** — `ENC004` flip `rejectUnauthorized: false→true`.
  - **Dockerfile** — `DOCKER008` comment-out `HEALTHCHECK NONE` (recoverable; doesn't delete).
  - **CORS** — `CORS001` replace `origin: '*'` with `origin: false` (reject by default; user adds allow-list after).
- **21 unit tests** ([src/__tests__/codeActionFixes.test.ts](src/__tests__/codeActionFixes.test.ts)) exercising every fix — happy path, shape-mismatch returns null, out-of-bounds tolerance, "already-safe" suppression.

### Why deterministic text-only fixes

The existing `Caspian Security: Fix Issue with AI` command handles the ambiguous cases (which DOMPurify call? what's the right Zod schema?) and has a consent dialog for good reason. These 13 fixes are the cases where the right answer is unambiguous — `privileged: true` has exactly one correct remediation, and it's `privileged: false`. Showing a lightbulb cuts the friction to a single keystroke for the 80% of findings that don't need judgment.

### How it shows up in VS Code

1. Scan runs, diagnostic appears with the usual `[Category] RULE_CODE: message` format.
2. VS Code displays a yellow lightbulb in the gutter; clicking it (or `Ctrl+.`) lists the fix with a concrete title (`Set privileged: false`, `Remove hostNetwork: true`, etc.).
3. Applying triggers a `WorkspaceEdit` — instant, reversible via undo.
4. The fix is marked `isPreferred`, so "Apply quick fix" / `Ctrl+.` → Enter selects it by default.

### Changed

- Test suite: **989 → 1010** (+21). Rules unchanged at 295+.
- [src/extension.ts](src/extension.ts) activates the provider once via `registerCaspianCodeActionProvider(context, enabledLanguages)`.

### Notes

- The provider is **conservative**: every fix returns null if the matched line's shape doesn't exactly fit the expected pattern. False "auto-fix" is worse than no auto-fix.
- The AI-fix path is untouched. Users still get `Caspian Security: Fix Issue with AI` for everything these mechanical fixes don't cover.

## [10.4.0] - 2026-04-21

Caspian is now a Model Context Protocol server. Any MCP client — Claude Desktop, Cursor, Zed, Cline — can call scans directly from tool use. "Use Caspian to scan this repo" goes from four-step manual flow to one-line prompt.

### Added

- **MCP server** ([src/cli/mcpServer.ts](src/cli/mcpServer.ts)) exposing four tools over stdio:
  - `scan` — workspace scan with optional severity filter and max-findings truncation; returns categorised summary + findings as JSON.
  - `scan_git_history` — spawns the existing git-history scanner and parses its JSON output.
  - `list_rules` — rule catalogue with optional category filter.
  - `explain_rule` — full description + suggestion + context-awareness / file-pattern metadata for a given rule code.
- **New bin entry** `caspian-mcp` alongside the existing `caspian-scan`, `caspian-git-history-scan`, `caspian-check-updates`. Launched via `npx caspian-security caspian-mcp` or globally.
- **[src/scanRunner.ts](src/scanRunner.ts)** — workspace-scan logic extracted so both the CLI and the MCP server share one implementation. `walkFiles()`, `resolveLanguage()`, `scanFile()`, and a new `runWorkspaceScan()` wrapper. No I/O concerns beyond `fs.readFileSync` — caller chooses the output format.
- **12 new unit tests** ([src/__tests__/mcpServer.test.ts](src/__tests__/mcpServer.test.ts)) exercising the four handlers + the dispatch layer directly. Smoke-verified end-to-end: `initialize` + `tools/list` over real stdio returns the tool catalogue.
- **Runtime dep: `@modelcontextprotocol/sdk` ^1.29.0.** First non-devDependency runtime dep on the project, but the SDK ships both ESM and CJS entries so it threads cleanly into our CommonJS build.

### Changed

- **[BUILD.md](BUILD.md) §3c** — Claude Desktop + Cursor wiring instructions with copy-pasteable `mcpServers` config.
- **[README.md](README.md) Install section** — adds the MCP block alongside VS Code, npm, and GitHub Actions paths.
- Test suite: **977 → 989** (+12 MCP handler tests). Rules unchanged at 295+.

### Security notes

- The MCP server is **stdio-only** — no network port, no auth tokens, no telemetry.
- Each tool call validates the `path` argument exists and is a directory before scanning.
- The `scan_git_history` tool is guarded by a `.git` directory check and respects the same 100 ms/file taint deadline and 3 s/file rule deadline as every other scan path.

## [10.3.0] - 2026-04-21

PR-scope scanning. Pair it with v10.1's baseline and your monorepo PR CI stops being a full-repo scan.

### Added

- **`--changed-since <ref>` CLI flag.** Restricts the scan to files that differ from the ref in a `<ref>...HEAD` diff. Three-dot semantics means "everything this branch adds since diverging from <ref>", not "everything different from <ref> right now" — so newer commits on the base branch don't pollute the set. `--diff-filter=d` excludes deletions (nothing to scan).
- **[src/gitDiff.ts](src/gitDiff.ts)** — `getChangedFilesSince(workspace, ref)` shells out to `git` via `spawnSync` and returns a Set of absolute paths. Clear error messages for missing ref, non-git repo, or git-not-installed.
- **GitHub Action `changed-since` input** — threads through to the CLI. Paired with `actions/checkout@v4 fetch-depth: 0` so the base ref resolves.
- **4 new unit tests** ([src/__tests__/gitDiff.test.ts](src/__tests__/gitDiff.test.ts)) covering: empty diff, absolute-path output, non-existent ref error, non-git-directory error. Shallow-clone tolerant.

### Why three-dot diff

`--changed-since origin/main` under two-dot semantics (`origin/main..HEAD`) would give the same files as three-dot in the common case — but if `origin/main` has moved forward since this branch diverged, two-dot includes files on `origin/main` that this branch never touched. Three-dot (`origin/main...HEAD`) uses the merge-base, which is what PR review UIs show. Caspian follows the PR-review convention.

### Example — monorepo CI workflow

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- uses: Caspian-Explorer/caspian-security/.github/actions/scan@v10.3.0
  with:
    baseline: .caspian-baseline.json
    changed-since: ${{ github.event.pull_request.base.sha }}
    fail-on: error
```

Result: full-repo scans measured in minutes collapse to seconds on typical PRs. The baseline handles the legacy backlog; `--changed-since` handles the review velocity.

### Changed

- CLI `--help` text documents `--changed-since`.
- [BUILD.md](BUILD.md) gains Section 3b — "PR-scope scanning with `--changed-since`".
- Test suite: **973 → 977** (+4 gitDiff). Rules unchanged at 295+.

## [10.2.0] - 2026-04-21

Caspian is now installable from **three** registries: VS Code Marketplace, Open VSX, and **npm**. The same rule engine reaches every developer — IDE, CLI, CI — through the channel most natural for their workflow.

### Added

- **npm distribution.** Same package, same name (`caspian-security`), same source tree. `npm install -g caspian-security` / `npx caspian-security caspian-scan .` / `npm install --save-dev caspian-security`. No more "clone the repo first" friction for non-GitHub CI pipelines (GitLab, CircleCI, Jenkins, Drone, BuildKite all work out of the box).
- **Three `bin` commands** — `caspian-scan` (main SARIF scanner), `caspian-git-history-scan` (secret scanner for git log), `caspian-check-updates` (dependency audit). All three read the CLI shebang that's already present in source.
- **`files` field** scoped tightly — only `out/`, LICENSE, README, CHANGELOG, SECURITY, THREAT_MODEL, and icon ship to npm. No source tree, no tests, no `.vsix` artefacts.
- **`npm run publish:npm`** script (runs `npm run compile` first, then `npm publish --access public`). Matches the existing `publish:vscode` + `publish:openvsx` pattern so all three registries publish from the same compiled bits.

### Changed

- **[BUILD.md](BUILD.md) publishing section** — rewritten around a three-registry table. Each channel gets its own auth / publish walkthrough. Documents that `require('caspian-security')` isn't supported (the `main` field points at the VS Code extension entry which needs `vscode`); use the bin commands instead.
- **[README.md](README.md)** — new "Install" section near the top covers VS Code / Open VSX / npm / GitHub Actions side by side. Overview copy updated to reflect the current scope (295+ rules, IaC + code, taint tracking, per-invocation consent default).

### Notes

- **Same rule engine, same SARIF, same baseline format** across all three channels. The extension's diagnostics, the CLI's SARIF output, and the Action's uploaded results are indistinguishable once you've stripped the UI chrome.
- Publishing to npm requires a maintainer `npm login` + OTP. The script is in place; actually pushing to the registry is a one-time action the owner runs when ready.

## [10.1.0] - 2026-04-21

The adoption-killer feature: **baseline / suppression file support**. Drop Caspian into any existing codebase without a big-bang remediation.

### Added

- **Baseline file support.** `caspian-scan --baseline .caspian-baseline.json` loads a per-file, per-rule count of known findings and suppresses them from the exit-code gate. Only NEW findings above the baseline counts fail the build. `--update-baseline` regenerates the file from the current scan.
- **`src/baseline.ts`** — `loadBaseline`, `buildBaseline`, `writeBaseline`, `applyBaseline`, `normalisePath`. Counts-based matching (no fingerprinting) so diffs are human-readable and the baseline auto-tightens as issues get fixed. Path-normalised so baselines survive Windows ↔ Linux CI.
- **GitHub Action `baseline` input.** Drop `baseline: .caspian-baseline.json` into your workflow; `.github/actions/scan/action.yml` threads it through to the CLI.
- **12 new unit tests** under `src/__tests__/baseline.test.ts` covering build, apply, normalisation, round-trip, and three flavours of load-error.

### Why counts, not fingerprints

Fingerprints either need a line number (fragile; breaks on every edit) or a normalised-context hash (fragile for different reasons and opaque in diffs). Per-file / per-rule counts are human-readable, git-diff-friendly, and auto-tighten: fix one of three findings, the count drops on `--update-baseline`, and adding a new one fails the build.

### Example

```bash
node out/cli/scan.js . --baseline .caspian-baseline.json --update-baseline
# (review + commit .caspian-baseline.json)
node out/cli/scan.js . --baseline .caspian-baseline.json --fail-on error
# → 0 new findings, exit 0
```

### Changed

- CLI help text documents `--baseline` and `--update-baseline`.
- [BUILD.md](BUILD.md) gains a "Section 3a — adopting Caspian into an existing codebase" with the full workflow.
- Rule totals unchanged at **295+**. Test suite: **961 → 973** (+12 baseline tests).

## [10.0.0] - 2026-04-21

**Caspian graduates from "code scanner" to "code + infrastructure scanner"** — and earns its major-version bump.

The major-version marker reflects a new scanning domain. Everything Caspian did before is preserved and improved; we added a parallel surface (Dockerfile, Terraform/HCL, Kubernetes YAML) that's as thorough as the existing 9.x code rules.

### Added — Infrastructure-as-code

- **Dockerfile rules (`DOCKER001`–`DOCKER008`).** `:latest` / unpinned base images, missing non-root `USER`, secrets baked into `ENV` / `ARG` / `RUN`, `ADD` from a URL, `curl | sh`, package-install without `--no-install-recommends` / pinned versions, `HEALTHCHECK NONE`. Fires on `Dockerfile`, `Containerfile`, `*.dockerfile`.
- **Terraform / HCL rules (`TF001`–`TF010`).** `0.0.0.0/0` ingress, public S3 ACLs / missing public-access blocks, wildcard IAM `Action` / `Resource` (HCL lowercase and JSON forms), `publicly_accessible = true` RDS, missing at-rest encryption on S3 / EBS / RDS, hardcoded `master_password`, disabled CloudTrail, `AdministratorAccess` attached to task/function roles, HTTP-without-HTTPS-redirect load balancers, KMS `kms:*` to account root. Fires on `.tf`, `.tfvars`, `.hcl`.
- **Kubernetes manifest rules (`K8S001`–`K8S008`).** `privileged: true`, `hostNetwork` / `hostPID` / `hostIPC: true`, `runAsUser: 0` / `allowPrivilegeEscalation: true`, `hostPath` volumes, dangerous Linux capabilities (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `BPF`), wildcard RBAC verbs / resources, `LoadBalancer` without `loadBalancerSourceRanges`. Fires on `*.yaml` / `*.yml`; excludes GitHub Actions workflows and `docker-compose.yaml`.

### Added — Quality gate

- **Vulnerable-corpus regression suite** (`src/__tests__/vulnerableCorpus.test.ts` + `src/__tests__/fixtures/vulnerable-corpus/`). Small synthetic fixture tree containing intentional vulnerabilities across every rule family. Each fixture has a minimum set of rule codes it MUST detect — any rule that stops firing breaks the build. Ratchet-style (new detections are fine; removed detections fail). No external repo downloads, CI-viable.
- Caught two real regressions during development: `JWT002` regex rejected string-literal secrets; `TF003` regex missed HCL's lowercase `actions` / `resources`. Both fixed in the same commit that added the test.

### Changed — CLI / file walker

- The CLI now scans `*.yaml`, `*.yml`, `*.tf`, `*.tfvars`, `*.hcl` by default, and special-cases filenames `Dockerfile`, `Containerfile`, `dockerfile`. Rules use `filePatterns.include` to scope per file type — Dockerfile rules don't fire on `.tf`, etc.
- New `resolveLanguage()` helper maps filename + extension to Caspian's `languageId` for downstream file-gated rules.

### Stats

- **Rule totals: 270+ → 295+.** Test suite: **880 → 961** (+81). Two new test suites (`vulnerableCorpus`, plus the 26 new rules contribute to `redosGuard`).
- Lint clean, compile clean, self-scan strict-mode clean.

### Upgrade notes

- No setting changes. No rule renames. Old code rules fire identically; new IaC rules only activate on matching file types.
- Users who keep `caspianSecurity.enabledLanguages` locked to code-only languages won't see IaC findings inside VS Code — the CLI still scans them in CI.

## [9.5.0] - 2026-04-21

Phase 3 of the roadmap. Caspian gains its first dataflow-aware analysis (intra-file taint tracking), a multi-line context fix that unblocks strict CI gating, and four new vulnerability-class families. The single biggest detection-quality jump since v8.0.

### Added — taint tracking (the moat)

- **Intra-file taint engine ([src/taint.ts](src/taint.ts))** — Caspian's first dataflow-aware analysis. Tracks user-input sources (`req.body / query / params / headers`, Flask `request.*`, PHP `$_GET / $_POST`, `process.argv / env`, Python `sys.argv / os.environ`) through simple variable assignments forward to dangerous sinks within the **same function**. Findings are emitted as 8 new rule codes:
  - `TAINT001` command injection (`exec / spawn`)
  - `TAINT002` eval / `new Function` / `vm.runInNewContext`
  - `TAINT003` filesystem path (path traversal)
  - `TAINT004` SQL sinks (`.query / .execute / .raw`)
  - `TAINT005` open redirect (`res.redirect / sendRedirect`)
  - `TAINT006` reflected XSS (`res.send / .innerHTML / document.write`)
  - `TAINT007` SSRF *with provenance* (`fetch / axios / requests` with tainted URL)
  - `TAINT008` prototype pollution via `Object.assign / _.merge / jQuery.extend`

  Sanitiser-aware: drops taint when the value passes through `validator.*`, `DOMPurify.sanitize`, `escape*`, `Number / parseInt`, Zod / Joi `.parse`, `new URL(...)`, `path.resolve(...)+startsWith`, `express-validator`. Performance-bounded: 200 lines / function, 50 in-flight tainted vars, 100 ms / file deadline. New setting `caspianSecurity.enableTaintTracking` (default `true`) gates the pass.
- **Limits documented openly** in the rule messages: no cross-function, no cross-file, no aliasing through arrays / objects / destructuring. Catches the 60–70 % of vulns that happen in a single controller; the rest needs a real taint analyser (Semgrep / CodeQL).

### Added — vulnerability coverage

- **OAuth hygiene (`OAUTH001`–`OAUTH006`)** — callback handles `code` without `state` verification (CSRF), authorize URL missing `state`, code exchange without PKCE, open-redirect via `redirect_uri`, deprecated implicit flow, wildcard `scope`. Slotted into AuthAccessControl.
- **LDAP injection (`LDAP001`–`LDAP003`)** — filter built via concatenation / template literal / Python f-string; Java `DirContext.search` without `LdapEncoder.filterEncode`; Python `python-ldap.search_s` without `escape_filter_chars`. Slotted into AuthAccessControl.
- **Command injection (`CMD001`–`CMD007`)** — Node `exec` with concatenated input, `spawn({shell:true})`, Python `os.system / subprocess(shell=True)`, PHP `shell_exec / passthru` with `$_GET / $_POST`, Ruby string-form `system / backticks / IO.popen`, Java `Runtime.exec / ProcessBuilder` with concatenation. Slotted into APISecurity.
- **Prototype pollution expansion (`FE007a` / `FE007b` / `FE007c`)** — `Object.assign({}, req.body)`, lodash `_.merge / _.defaultsDeep` with untrusted source, `{...req.body}` spread without schema validation. Original `FE007` (`__proto__` literal) gains `contextAware: true`.

### Fixed — F11 multi-line context awareness

- New shared module **[src/scanContext.ts](src/scanContext.ts)** with `buildLineStates(text)` — one-pass char-by-char walker that records per-line state (inside template literal, inside block comment, inside `${}` expression). Handles JS regex literals correctly, including character classes (`/[...]/`), so `/\`/g` no longer cascades the walker into a phantom template-literal state for the rest of the file.
- Both **`analyzer.ts`** (extension host) and **`cli/scan.ts`** consume it. `contextAware` rules now correctly skip matches inside multi-line template literals, JSDoc blocks, and across `${...}` expressions. Removes ~70 lines of duplicated context logic.
- **`XSS001` / `XSS002` / `CRED001`** marked `contextAware: true` so doc examples and webview-generation template literals stop false-positiving in projects that emit HTML to webviews.
- **Self-scan CI flipped back to `--fail-on error`** (was softened in v9.3.0). Caspian's own source now passes the strict gate.

### Changed

- **Rule totals: 240+ → 270+.** Test suite: **812 → 880**. Two new test suites (`scanContext.test.ts`, `taint.test.ts`).
- `.github/workflows/self-scan.yml` excludes `__tests__`, `rules`, `cli` (rationale documented in the workflow file — each is its own intentional design).

## [9.4.0] - 2026-04-21

Phase 2 of the roadmap — five new vulnerability-class families and a git-history secret scanner. All-additive release; no behaviour change to existing rules or workflows.

### Added — vulnerability coverage

- **SSRF (`SSRF001`–`SSRF009`).** Server-side fetch / axios / http / requests / urllib / RestTemplate / HttpClient / curl_exec / `http.Get` called with `req.*`, `request.*`, `params.*`, `body.*`, or a url-shaped user-input variable. Each rule has a shared `suppressIfNearby` allow-list so code that already validates URLs (`new URL(...) + isAllowedHost`, `sanitizeUrl`, SSRF-guard helpers) does not re-flag. Slotted into category APISecurity.
- **Insecure deserialization (`DESER001`–`DESER009`).** `pickle.loads`, `marshal.loads`, `yaml.load` (without `SafeLoader`), `yaml.unsafe_load`, Java `ObjectInputStream.readObject`, .NET `BinaryFormatter` / `SoapFormatter` / `NetDataContractSerializer`, PHP `unserialize($_GET|$_POST|$_REQUEST|$_COOKIE)`, Node `eval`/`Function`/`vm.runInNewContext` on `req.*`, Ruby `YAML.load` / `Marshal.load` on `params`. Slotted into InputValidationXSS.
- **SSTI / template injection (`SSTI001`–`SSTI008`).** Flask `render_template_string`, Jinja2 `Template(user_input)` / `env.from_string(user_input)`, EJS, Handlebars, Pug, Ruby ERB, Java Velocity + Freemarker, PHP Twig + Smarty — all anchored on "compile a template from a user-supplied string".
- **XXE (`XXE001`–`XXE009`).** Java `DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory` without the three canonical hardening feature flags. Python `lxml.etree.*` without a safe parser. Python stdlib `xml.etree.ElementTree` / `xml.sax` / `xml.dom.minidom` (recommends `defusedxml`). .NET `XmlDocument` / `XmlTextReader` without `XmlResolver = null`. `.NET DtdProcessing = DtdProcessing.Parse`. PHP `simplexml_load_*` / `DOMDocument` without `libxml_disable_entity_loader`. Node `libxmljs.parseXml({ noent: true })`.
- **JWT misuse (`JWT001`–`JWT007`).** `alg: none` accepted; `jwt.verify(token, key)` without explicit `algorithms` list (algorithm-confusion risk); `jwt.decode()` used where `jwt.verify()` is required; PyJWT `decode` without `algorithms=`; Java `Jwts.parser().setSigningKey(...)` without `.requireAlgorithm(...)`; `ignoreExpiration: true` / `verify_exp=False`; missing `iss` / `aud` checks. Slotted into AuthAccessControl.

### Added — tooling

- **Git-history secret scanner CLI (`out/cli/gitHistoryScan.js`).** Walks every commit reachable from `--all` via `git log -p`, runs the provider-prefix secret rules against every ADDED line, and reports each historical leak with commit SHA, author, ISO date, file, and line number. Grouped-by-commit text output leads with "Next steps: rotate the secret at the provider NOW, then rewrite history with BFG / git-filter-repo, then wire up the CI Action so it cannot happen again". JSON output also available.
- New npm script `npm run scan-git-history`. `--rules secrets|all`, `--max-commits N`, `--format json|text`, `--output FILE` flags.

### Changed

- `package.json` description refreshed to reflect the new scope.
- Rule totals: **192 → 240+**. Test suite: **691 → 812**. Every new pattern passes the ReDoS guard (<200 ms on every adversarial input).

## [9.3.0] - 2026-04-21

Phase 1 improvements: CI-native workflow, provider-prefix secret detection, trust-signal documentation. No behaviour change to the VS Code extension itself beyond 28 new rules; big additions live off the extension (CLI, Action, docs).

### Added

- **28 provider-prefix secret rules (`TOKEN001`–`TOKEN028`).** Each pattern matches a specific vendor's token shape — Anthropic, OpenAI, Slack, Google API/OAuth, Stripe, Twilio, SendGrid, Mailgun, npm, Docker Hub, Shopify, Notion, Linear, Figma, Databricks, Hugging Face, Discord (bot + webhook), Bitbucket, Atlassian, DigitalOcean, Sentry, Postman, Pulumi, Square, GitLab runner, and HTTP basic-auth credentials embedded in URLs. Stripe live vs test, Discord bot vs webhook are split so severity matches impact. Every pattern is ReDoS-safe (build-time verified).
- **CLI scanner (`out/cli/scan.js`).** Runs the same rule set headlessly; emits SARIF 2.1, JSON, or plain text. Supports `--fail-on error|warning|info|never`, `--include`, `--exclude`, `--max-file-size`, `--output`. Mirrors the extension's Informational-cap and context-aware semantics. Exit codes are CI-friendly (0 = clean, 1 = threshold hit, 2 = scan crashed).
- **npm scripts:** `npm run scan`, `npm run self-scan`, `npm run publish:vscode`, `npm run publish:openvsx`.
- **Reusable GitHub Action** at [`.github/actions/scan/action.yml`](.github/actions/scan/action.yml). Consumers add `uses: Caspian-Explorer/caspian-security/.github/actions/scan@v9.3.0` and get a full SARIF-upload pipeline with no extra boilerplate. Copy-pasteable downstream example at [`.github/examples/caspian-scan.yml`](.github/examples/caspian-scan.yml).
- **Self-scan CI workflow** at [`.github/workflows/self-scan.yml`](.github/workflows/self-scan.yml). Caspian runs the CLI against its own source on every push / PR and uploads SARIF to the Security tab. Build fails on any Error-severity regression.
- **[SECURITY.md](SECURITY.md)** — coordinated-disclosure policy with GitHub Private Vulnerability Reporting link, triage SLAs per severity, in-scope / out-of-scope lists.
- **[THREAT_MODEL.md](THREAT_MODEL.md)** — assets, trust boundaries, adversaries (hostile workspace / supply chain / local process / network / compromised LLM / malicious webview), mitigations tied to file:line references, and known residual risks.
- **Open VSX publishing path.** `ovsx` devDependency installed; `npm run publish:openvsx` publishes from the same VSIX that goes to the VS Code Marketplace, reaching Cursor / Windsurf / VSCodium users.

### Changed

- `package.json` `description` refreshed to reflect the new rule count (192) and the CI / CLI / Open VSX story.
- [BUILD.md](BUILD.md) publishing section rewritten: VS Code Marketplace + Open VSX side-by-side, CLI usage, Action usage, and a placeholder for upcoming VSIX publisher signing.

## [9.2.0] - 2026-04-20

Security-hardening release. This version fixes nine self-audit findings affecting the extension's own data-flow, webview, and storage surface. No new scan rules; no functional regressions expected. All changes are defence-in-depth; no known in-the-wild exploitation.

### Security — Critical

- **AI fix provider: Gemini API key moved out of URL path.** Gemini calls now pass the key in the `x-goog-api-key` header instead of the `?key=...` query string, preventing key leakage via proxy logs, CDN edge logs, and `Referer` headers.
- **AI fix: explicit per-invocation consent.** A modal dialog now appears *before* any code is sent to the provider, showing which file, which provider, and how much code will be transmitted. Cancel is the default. Gated by the new `caspianSecurity.aiFixRequireConsent` setting (default `true`).
- **AI fix: minimal-context mode, on by default.** New setting `caspianSecurity.aiFixMinimalContext` (default `true`) sends only ~20 lines around the finding to the provider instead of the whole file. Old behaviour — sending `fullFileContent`, `functionScope`, and `variableDefinitions` — is now opt-in. The response is spliced back into the file locally.
- **Learning Dashboard: CSP + nonce added.** `learningPanel` previously had no Content-Security-Policy and used inline `onclick` handlers with string-concatenated command names. Replaced with a strict CSP (`default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-<nonce>';`), nonce-scoped `<script>`, and event-delegated `data-cmd` attributes validated against an allow-list.
- **Webview command bridge: allow-list enforced.** `resultsPanel`, `taskDetailPanel`, and `learningPanel` now reject any `runCommand` / `runCheck` message whose command ID isn't in a central allow-list (`src/webviewUtils.ts`). Previously a webview could invoke any registered VS Code command.

### Security — High

- **All webview panels now set `localResourceRoots: [extensionUri]`.** `resultsPanel`, `aiSettingsPanel`, `learningPanel`, `welcomePanel`, `taskDetailPanel`, and the `taskTreeProvider` webview view can no longer request files outside the extension directory via `vscode-webview-resource://` URIs.
- **Prompt-injection hardening.** `buildFixPrompt` now escapes triple-backtick fences in user-supplied code (`surroundingCode`, `fullFileContent`, `functionScope`, `variableDefinitions`, `originalLineText`) so a file containing ``` in a comment cannot break out of the markdown code block. The system prompt now explicitly flags user sections as untrusted data.
- **Telemetry: workspace-scoped opt-in.** Previously, clicking "Enable" on the telemetry prompt flipped `enableTelemetry` globally (every workspace, every project). Opt-in now writes to `ConfigurationTarget.Workspace`. The opt-in copy is also more truthful: it explicitly lists the full payload (rule codes, language IDs, AI provider name, session UUID), making clear that `aiProvider` is included.
- **Telemetry endpoint is now configurable + https-validated.** New `caspianSecurity.telemetryEndpoint` setting. The resolver ignores any value that doesn't start with `https://`, so a malformed or downgraded setting cannot redirect the payload.
- **Cached issue patterns no longer persisted.** `fileStateTracker.ts` used to serialise the full `cachedIssues` array to `file-state.json`, including `pattern` (the raw matched text from the source — e.g. `password = "hunter2"`). Cached issues are now dropped on save; the change-detection cache (hash / mtime / size) — the only part that actually drives the skip-unchanged optimisation — is kept. On restart, issues repopulate as each file is scanned this session.

### Security — Medium

- **Tightened analyzer timeout budget.** Per-file scan budget reduced from 10s to 3s, deadline polled every 25 lines instead of every 100, and the per-line length cap dropped from 5000 to 2000 characters. Real scans are unaffected; adversarial inputs are bounded sooner.
- **New `redosGuard` test.** Every `RegExp` on every rule is exercised against a library of catastrophic-backtracking inputs; the build fails if any pattern takes >200 ms.

### Added

- `caspianSecurity.aiFixMinimalContext` (boolean, default `true`)
- `caspianSecurity.aiFixRequireConsent` (boolean, default `true`)
- `caspianSecurity.telemetryEndpoint` (string, default `https://telemetry.caspiansecurity.dev/v1/report`)
- New shared module `src/webviewUtils.ts` exposing `ALLOWED_WEBVIEW_COMMANDS`, `isAllowedWebviewCommand()`, and `getNonce()`
- New tests: `src/__tests__/redosGuard.test.ts`, `src/__tests__/webviewUtils.test.ts`, `src/__tests__/aiFixPrompt.test.ts`

## [9.1.1] - 2026-04-20

### Fixed

- Declare `caspian-security.ignoreAllByRule` and `caspian-security.explainRule` in the `contributes.commands` manifest section to silence two VS Code menu-item validation warnings emitted during `vsce package`. Both commands were already registered at runtime and wired to the results panel webview — only their manifest declarations were missing.

## [9.1.0] - 2026-03-28

### Added

- Auto-verification of resolved findings — the system now watches scan results and automatically marks findings as verified when they disappear, eliminating the need to click Verify manually
- File system watchers for `package.json` and `package-lock.json` — dependency findings (DEP-OUTDATED, DEP-AUDIT) are automatically re-checked when packages change
- New `caspianSecurity.autoVerify` setting (default: true) to toggle auto-verification
- Quiet mode for background dependency re-checks triggered by file watchers
- Line-drift guard prevents false auto-verification when code findings shift lines
- Concurrency guard prevents overlapping dependency checks

## [9.0.8] - 2026-03-20

### Changed

- Add "Tasks" text label to the Tasks toolbar button

## [9.0.7] - 2026-03-20

### Changed

- Convert AI Settings button from primary (blue) labeled button to an icon-only gear button, moved to the far right of the toolbar
- Add Security Tasks icon button (checklist icon) to the Results panel toolbar for quick access to the task dashboard

## [9.0.6] - 2026-03-20

### Changed

- Redesign Results panel filter bar: collapse severity checkboxes into a single multi-select dropdown ("All Severities" / partial list), remove external labels from Category/File/Status/Search controls (first option or placeholder serves as label), move search to the same row, and apply a consistent subtle border with 4px rounded corners to all filter controls

## [9.0.5] - 2026-03-20

### Changed

- Switch Run toolbar icon from filled (`play-fill`) to outlined (`play`) Phosphor SVG, matching the visual weight of Copy and Export icons

## [9.0.4] - 2026-03-20

### Changed

- Replace Unicode icon characters on Run, Copy, and Export toolbar dropdown buttons with Phosphor SVG icons (`play`, `copy`, `download-simple`, `caret-down`), inlined directly to respect webview CSP

## [9.0.3] - 2026-03-20

### Changed

- Consolidate toolbar buttons into three dropdown menus: **Run** (Run Security Check, Check Current File, Check Entire Workspace, Scan Uncommitted Files), **Copy** (Copy All, Copy Errors, Copy Warnings, Copy Info), and **Export** (Export CSV, Export JSON, Export SARIF) — each with icon and chevron

## [9.0.2] - 2026-03-19

### Fixed

- Replace `"admin123"` example password with `"EXAMPLE_PASSWORD"` across all documentation, source comments, and test fixtures to resolve Open VSX secret-scanner false positive blocking extension publication

## [9.0.1] - 2026-03-12

### Changed

- Rename display name from "Caspian Security Extension" to "Caspian Security" across package.json, docs, and source code

## [9.0.0] - 2026-03-12

### Added

- **Welcome Experience** — first-run onboarding webview panel that shows on install with workspace scan, security posture overview, feature highlights, and quick start guide
- **Security Score** — real-time 0-100 security score in the status bar with grade (A-F), severity-weighted calculation, and click-for-details interaction
- **Triage Session** — guided walkthrough command that navigates to each pending issue one by one with AI Fix / Ignore / False Positive / Skip options
- **Bulk Ignore** — "Ignore All [RULE]" button on every finding in the Results Panel to bulk-ignore all instances of a rule code
- **Rule Explanation** — "Why?" button on every finding that shows the rule details, category, severity, and remediation guidance in a modal dialog
- **PR-Scoped Scanning** — "Scan Branch Changes" command that scans only files changed on the current branch vs main/master, with branch name in scan metadata
- **Test Suite** — 230 unit tests across 3 test suites: rule structure validation (211 tests for all 164 rules), caspianIgnore parsing/matching tests, and SecurityScore calculation tests
- **CI Pipeline** — GitHub Actions workflow (`ci.yml`) with lint, compile, test on Node 18/20, and VSIX packaging
- **Jest + ts-jest** testing infrastructure with vscode module mock

### Changed

- Results Panel actions cell now includes "Ignore All [CODE]" and "Why?" buttons for every pending issue
- Status bar now shows two items: the main Caspian status and the security score badge
- `package.json` adds 6 new commands: Welcome, Security Score, Triage Session, Scan Branch Changes, Ignore All By Rule, Explain Rule
- Git integration gains `getBranchChangedFiles()` and `getCurrentBranch()` methods for PR-scoped scanning

## [8.3.0] - 2026-03-11

### Added

- 31 new security rules (133 → 164 total) across web application and Android categories
- **Security Headers** (5 rules): HDR001–HDR005 — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Cache-Control for sensitive responses
- **Input Validation** (5 rules): XSS012–XSS016 — Content-Type validation, server-side validation library reminders, HTML encoding, innerHTML sanitization, and template output encoding
- **Frontend Security** (4 rules): FE010–FE013 — window.open with user URLs, sensitive data in web storage, DOM-based XSS source-to-sink detection, and open redirect prevention
- **CSRF Protection** (2 rules): CSRF008–CSRF009 — double-submit cookie pattern and custom header AJAX protection reminders
- **Database Security** (1 rule): DB013 — parameterized query reminder
- **API Security** (2 rules): API015–API016 — server technology header leakage and Helmet middleware reminder
- **Android/Kotlin** (12 rules): KT-AUTH004–006 (receiver export, implicit intents, tapjacking), KT-XSS002–004 (WebView content access, mixed content, SSL error bypass), KT-ENC003–006 (hardcoded keys, weak crypto, cleartext traffic, certificate pinning), KT-CRED001 (hardcoded API keys), KT-LOG002 (clipboard data leakage)
- New `securityHeadersRules.ts` rule file for HTTP security header checks

## [8.2.0] - 2026-03-08

### Changed

- Replace task checklist TreeView with a custom WebviewView for the sidebar
- Task items now show two lines: title on line 1, due date and metadata on line 2
- Group headers (Overdue, Pending, etc.) render proper icons instead of literal `$(icon)` text
- Collapsible status groups with chevron indicators

## [8.1.4] - 2026-03-08

### Fixed

- Fix "No active editor found" error when clicking Run Check from the task detail panel
- Category-specific check commands now fall back to a workspace scan filtered by that category when no editor is open

## [8.1.3] - 2026-03-06

### Fixed

- Fix task detail panel buttons (Run Check, Mark Complete, Snooze, etc.) not responding to clicks
- Replace inline onclick handlers with addEventListener to comply with webview Content Security Policy

## [8.1.2] - 2026-03-06

### Fixed

- Fix high CPU / unresponsive extension when scanning large minified files (e.g. `pdf.worker.min.mjs`)
- Expand minified file path detection to cover `.min.mjs`, `.min.cjs`, and all `.min.*` extensions
- Reorder generated-file check before line splitting to avoid unnecessary work on skipped files
- Add line length limit (5000 chars) to skip minified lines that cause regex backtracking
- Add per-file analysis timeout (10 seconds) to prevent any single file from freezing VS Code
- Improve event loop yielding to run between every file instead of every 10 files

### Added

- New `caspianSecurity.maxFileSize` setting (default: 500KB) to skip oversized files automatically

---

## [8.1.1] - 2026-03-05

### Fixed

- Wire up "Run Check" button in task detail panel — clicking it now executes the task's associated scan command
- Add `runCheck` message handler and webview function for task-specific scans

### Changed

- Add post-task global rules to CLAUDE.md (version bump, docs, wiki, VSIX build, commit, notify)

---

## [8.1.0] - 2026-02-25

### Added

- **Task Detail Panel** — dedicated webview panel for viewing and managing security tasks with rich UI
- Interactive task actions: mark complete, snooze (1hr/4hrs/1day/3days/1week), change interval, dismiss, and reinstate
- Task metadata display: status badge, priority, interval, category, dates, completion count, and related rules
- `showTaskDetail` command for opening task details from the tree view
- Responsive design using VS Code theme variables with Content Security Policy

### Changed

- Tree view click now opens the detail panel instead of a quick-pick action menu
- `taskAction` command redirected to show the detail panel

---

## [8.0.5] - 2026-02-25

### Changed

- Remove Marketplace publish step from pre-commit checklist (now 11 steps)
- Add `.claude/` directory to `.gitignore`

---

## [8.0.4] - 2026-02-25

### Added

- **Git tag, GitHub Release, and Marketplace publish steps** in the pre-commit checklist (steps 8–11)
- **Global rule** prohibiting `Co-Authored-By` trailers in commit messages
- **Restored `.eslintrc.json`** — ESLint config is now tracked in git

### Changed

- Pre-commit checklist renumbered from 8 steps to 12 steps
- GitHub Discussions post moved from step 8 to step 12

---

## [8.0.3] - 2026-02-24

### Added

- **Kotlin/Android support** — `.kt` and `.kts` files are now scanned. All existing rules (secrets, weak crypto, HTTP URLs, SQL injection, etc.) apply automatically.
- **10 Android/Jetpack-specific security rules** scoped to Kotlin files:
  - `KT-AUTH001` — WebView JavaScript enabled (`setJavaScriptEnabled(true)`)
  - `KT-AUTH002` — WebView JavaScript interface exposed (`addJavascriptInterface`)
  - `KT-AUTH003` — Broadcast sent without receiver permission
  - `KT-XSS001` — WebView file access enabled (`setAllowFileAccess(true)`)
  - `KT-ENC001` — Insecure random number generator (`java.util.Random` instead of `SecureRandom`)
  - `KT-ENC002` — Unencrypted SharedPreferences (should use `EncryptedSharedPreferences`)
  - `KT-FILE001` — World-readable/writable file mode (`MODE_WORLD_READABLE`, `MODE_WORLD_WRITEABLE`)
  - `KT-FILE002` — Unsafe external storage access (`getExternalStorageDirectory`)
  - `KT-DB001` — Room `@RawQuery` annotation (potential SQL injection)
  - `KT-LOG001` — Android log statements that may leak sensitive data in production

---

## [8.0.2] - 2026-02-22

### Changed

- GitHub Discussion posts now link to the VS Code Marketplace instead of the GitHub repo

---

## [8.0.1] - 2026-02-22

### Changed

- Pre-commit standing instructions now require GitHub Wiki updates (clone, edit, push) instead of just flagging changes
- Pre-commit standing instructions now require posting a social-media-ready GitHub Discussion after every commit

---

## [8.0.0] - 2026-02-22

### Added

- **Learning Intelligence System** — the extension now learns from every scan, fix, ignore, false positive, and verification to get smarter over time
  - **Rule Intelligence Store** (`ruleIntelligence.ts`) — tracks per-rule effectiveness metrics: detection counts, false positive rates, fix rates, AI fix success rates, resolution times, broken down by language and file pattern
  - **Adaptive Confidence Engine** (`adaptiveConfidence.ts`) — replaces static heuristics with Bayesian-updated confidence scoring that adjusts based on accumulated user behavior (rules with high FP rates get downgraded, highly-acted-on rules get upgraded)
  - **Fix Pattern Memory** (`fixPatternMemory.ts`) — remembers successful AI fixes and offers instant replay for similar issues without an API call; normalizes code patterns for matching, tracks success rates, supports up to 500 patterns with LRU eviction
  - **Codebase Profile** (`codebaseProfile.ts`) — builds a project-specific intelligence profile: learns safe functions from AI fixes and FP dismissals (e.g., DOMPurify.sanitize neutralizes XSS rules), tracks hot zones by directory risk density, monitors security posture trends, detects regressions when previously fixed issues reappear
  - **Scan Insights Engine** (`scanInsights.ts`) — generates actionable insights: trend analysis (improving/degrading), noisy rule detection, regression alerts, hot zone identification, fix pattern availability, AI fix effectiveness, and category completion celebrations
  - **Opt-in Telemetry Service** (`telemetryService.ts`) — anonymized rule effectiveness statistics sent to developer endpoint (off by default, no code/paths/project names, user can preview exact payload before enabling)
  - **Learning Dashboard** (`learningPanel.ts`) — dedicated webview panel with overview stats, sortable rule effectiveness table, fix pattern library, codebase hot zones, security trend visualization, active insights with action buttons, and reset/export controls
- **New commands**: `Show Learning Dashboard`, `Reset All Learning Data`, `Export Learning Data`, `Preview Telemetry Data`
- **New setting**: `enableTelemetry` — opt-in anonymous rule statistics sharing (default: off)
- Learned safe pattern suppression in the scan engine — automatically suppresses findings when learned sanitizer functions are nearby
- Fix pattern memory check before AI API calls — offers instant cached fixes with success rate display

---

## [7.3.0] - 2026-02-22

### Added

- **Security Task Management system** — recurring security task tracking with per-project persistence, interval-based reminders, and auto-completion
  - 23 predefined security tasks across all 14 categories (dependencies, secrets, encryption, logging, infrastructure, auth, CORS, input validation, CSRF, API, database, file handling, frontend, business logic)
  - Configurable intervals: daily, weekly, biweekly, monthly, quarterly
  - Auto-completes tasks when relevant extension actions run (workspace scans, dependency checks)
  - 15-minute scheduler checks for overdue tasks and shows notification reminders
  - Snooze options (1 hour, 4 hours, 1 day, 3 days, 1 week) and dismiss/reinstate per task
  - Per-task interval override without affecting other tasks
- **Activity bar sidebar** — dedicated Caspian Security icon in the VS Code activity bar with Security Tasks tree view
  - Tasks grouped by status: Overdue, Pending, Completed, Snoozed, Dismissed
  - Sorted by priority within each group
  - Click any task to open quick pick with Complete/Snooze/Change Interval/Dismiss actions
  - Refresh button and "Complete All Overdue" action in title bar
- **New commands**: `Show Security Tasks`, `Refresh Security Tasks`, `Complete All Overdue Tasks`
- **New settings**: `enableTaskManagement` (master toggle), `taskReminders` (notification popups)
- **Task persistence** — task state stored in `security-tasks.json` via PersistenceManager, survives VS Code restarts

---

## [7.2.1] - 2026-02-21

### Added

- **Version bump step in CLAUDE.md** — pre-commit checklist now includes automatic version increment (patch by default) with `package.json`, `CHANGELOG.md`, and `package-lock.json` sync

---

## [7.2.0] - 2026-02-15

### Added

- **CLAUDE.md standing instructions** — pre-commit checklist enforcing lint, compile, code review, documentation updates, and packaging verification for every commit via Claude Code

- **Generated file detection** -- new `caspianSecurity.skipGeneratedFiles` setting (default: true) automatically skips scanning of auto-generated and minified files
  - Detects by path patterns (`.min.js`, `.bundle.js`, `workbox-*.js`, `sw.js`, `/dist/`, `/build/`, `/__generated__/`, etc.)
  - Detects by content markers (`@generated`, `@auto-generated`, `do not edit`, `code generator`, etc.)
  - Detects minified code via heuristic analysis (average line length > 300 characters)
- **ConfigManager singleton pattern** -- centralized configuration management with getInstance() for consistent access across the extension

### Changed

- **CRED005** (High-Entropy Strings) -- major false positive reduction:
  - Added `contextAware: true` to skip matches in comments
  - Added 8 negative patterns to exclude translation function calls (`t()`, `i18n()`, `translate()`, `__()`), route paths, URLs with multiple dots, UUIDs with dashes, long constant names, and test/mock data
  - Strengthened pattern matching to require actual base64 characteristics (padding `=` or special chars `+/`) instead of matching any 40+ character string
- **ENC010** (PII Logging Without Masking) -- made detection more precise:
  - Patterns now require object property access (`user.email`, `data.phone`) or PII-prefixed variables (`userEmail`, `customerPhone`)
  - Added 9 negative patterns to exclude false positives: `filename`, `filepath`, `pathname`, `dirname`, `basename`, `classname`, `typename`, `tagname`, `nodename`, `elementname`, `username`, `hostname`, `servername`, `databasename`, `languagename`, `frameworkname`, `packagename`, `displayname`, `appname`, `sitename`, email configuration references, and schema/type definitions
- **ENC003** (HTTP in Comments) -- now context-aware:
  - Added `contextAware: true` to skip HTTP URLs in documentation comments
  - Added negative patterns for example domains (`example.com`, `example.org`, `example.net`) and markdown links
- **FE003** (Missing rel="noopener noreferrer") -- fixed suppression logic:
  - Fixed `suppressIfNearby` check to include the current line (was incorrectly skipping it)
  - Added JSX/React-style patterns to detect `rel={...}` in addition to `rel="..."`

### Fixed

- CRED005 false positives on translation keys like `t('compareYourSpendingAgainstBudgetByCategory')` (30-40% of reported false positives)
- ENC010 false positives on non-PII variables like `console.log('filename:', filename)` and `logger.info('languageName:', 'en')` (15-20% of reported false positives)
- FE003 false positives on links that already have `rel="noopener noreferrer"` on the same line as `target="_blank"` (10-15% of reported false positives)
- ENC003 false positives on HTTP URLs in documentation comments like `// @see http://example.com/docs` (5-10% of reported false positives)
- Generated files being scanned (workbox bundles, service workers, minified JS) causing false positives (10-15% of reported false positives)

**Impact:** Based on production testing feedback, these changes reduce the overall false positive rate from ~70% to <20%.

---

## [7.1.0] - 2026-02-09

### Added

- **Show Informational toggle** -- new `caspianSecurity.showInformational` setting (default: true) lets users hide best-practice reminders and see only actionable security findings
- **Internal path severity reduction** -- new `caspianSecurity.reduceInternalPathSeverity` setting automatically downgrades severity for files in `/admin/`, `/scripts/`, `/internal/`, `/seed/`, `/migrations/`, `/fixtures/`, and `/tools/` directories
- **Informational rule line targeting** -- informational rules now collect multiple candidate matches and pick the most relevant line (preferring function bodies over imports and declarations) instead of firing on the first match

### Changed

- **DB011** (Default Credentials) -- fixed regex that incorrectly matched empty password initialization (`let password = ""`); added negative patterns for password generation contexts (`crypto.randomBytes`, `generatePassword`, etc.)
- **LOG005** (Password in Logs) -- rewritten patterns to require password as a variable reference, not just the word appearing inside a string literal; no longer flags instruction strings like "Users have been created with temporary passwords"
- **ENC010** (PII Logged Without Masking) -- now detects masking functions (`mask*()`, `redact*()`, `anonymize*()`) and suppresses when PII is already wrapped in protection; also checks nearby lines for masking patterns
- **ENC007** (Sensitive Data Logged) -- added same masking detection and instruction-string suppression as ENC010
- **BIZ007** (Client-side Quota) -- added negative patterns for database pagination terms (`limitCount`, `pageSize`, `.limit()`, `OFFSET`, `pagination`) to stop flagging Firestore/SQL query limits
- **BIZ004** (Trial Period Logic) -- now excludes seed, fixture, migration, and mock files entirely; reduces severity in scripts/admin/tools directories
- **FILE009** (Public Storage Bucket) -- replaced broad `/allUsers/i` pattern with context-specific patterns requiring cloud/IAM keywords on the same line; added negative patterns for JSX UI elements (`<SelectItem>`, `<MenuItem>`, etc.)
- **XSS004** (dangerouslySetInnerHTML) -- now suppresses when `JSON.stringify`, `DOMPurify`, or sanitization functions are present on the same line or nearby; also suppresses near `application/ld+json` script tags

### Fixed

- DB011 false positive on empty password variable initialization in password generation functions
- LOG005 false positive on instruction strings containing the word "password"
- ENC010 false positive on PII already wrapped in masking functions like `maskEmail()`
- BIZ007 false positive on Firestore `limitCount` pagination parameters
- BIZ004 false positive on admin seed utilities populating trial-plan reference data
- FILE009 false positive on `<SelectItem value="allUsers">` UI dropdown components
- XSS004 false positive on `dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}` for JSON-LD metadata

---

## [7.0.0] - 2026-02-07

### Added

- **Smart Context AI Fixes** -- AI fix prompts now include the entire enclosing function scope and traced variable definitions, extracted via VS Code's DocumentSymbolProvider. The AI sees the full function body instead of just 20 surrounding lines, producing significantly more accurate fixes for complex code.
- **Confidence Scoring (Deep Verify)** -- each detected issue now receives a confidence classification based on lightweight variable-source analysis:
  - **Critical** (red badge) -- hardcoded secret detected as a string literal (e.g., `password = "EXAMPLE_PASSWORD"`)
  - **Safe** (green badge) -- static string with no dynamic components (e.g., `query = "SELECT * FROM users"`)
  - **Verify Needed** (orange badge) -- dynamic value via concatenation or template interpolation (e.g., `query = "SELECT * FROM " + input`)
  - Confidence badges appear in the results panel next to the Verify button and in VS Code diagnostics
- **`.caspianignore` File** -- clicking "Ignore" now persists the decision to a `.caspianignore` file in the workspace root. Format: `RULE_CODE file/path.ts:line # optional reason`. The file is loaded on startup and watched for live changes, so teams can commit it to version control and share ignore decisions across machines.
- **SARIF v2.1.0 Export** -- new "Export SARIF" button in the results panel header. Generates a standards-compliant SARIF file that can be uploaded directly to GitHub Security Alerts (Security tab > Code scanning > Upload SARIF). Includes rule definitions, severity mapping, and physical source locations.
- New command: "Caspian Security: Export Results to SARIF"
- New files: `src/contextExtractor.ts`, `src/confidenceAnalyzer.ts`, `src/caspianIgnore.ts`

### Changed

- AI fix prompt now uses a security-expert instruction when function scope is available: "Fix the issue within the function scope shown above without breaking the surrounding logic"
- Ignore command now shows an optional input box for providing a reason before writing to `.caspianignore`
- Diagnostics now display confidence prefix when available (e.g., `[Critical] [Secrets] CRED001: ...`)
- Scanner filters out issues matching `.caspianignore` entries before publishing diagnostics

---

## [6.1.0] - 2026-02-03

### Added

- **Verify Button** -- manually verify if an issue has been resolved by re-scanning just that file
- **Verified Status** -- new fix status that confirms an issue is truly resolved (distinct from AI-fixed)
- Verify button appears on both Pending and Fixed issues in the results panel
- Progress bar now includes verified count in resolved total (e.g., "40/120 resolved (28 fixed, 5 verified, 7 ignored)")
- New command: "Caspian Security: Verify Issue Resolution"

### Changed

- Status filter dropdown now includes "Verified" option

---

## [6.0.0] - 2026-02-03

### Added

- **Context-Aware Analysis** -- rules can now detect if matches are inside comments, string literals, or JSX text and suppress false positives
- **Project Advisories** -- informational rules converted to project-level advisories that fire once per scan instead of per-line
- **Negative Patterns** -- rules can specify patterns that suppress matches (e.g., DB001 won't fire if parameterized queries are nearby)
- **Suppress-If-Nearby** -- rules can be suppressed when related safe patterns exist within N lines
- **File Pattern Filtering** -- rules can target specific file patterns (e.g., BIZ001 only fires in payment-related files)
- **.gitignore Check** -- CRED007a advisory warns if .env and other sensitive files aren't in .gitignore
- New `RuleType` enum: `CodeDetectable`, `Informational`, `ProjectAdvisory`
- New rule properties: `contextAware`, `negativePatterns`, `suppressIfNearby`, `filePatterns`

### Changed

- **DB001** (SQL Injection) -- now context-aware, won't flag string concatenation inside comments or when parameterized queries are nearby
- **FE001** (innerHTML) -- now context-aware, suppresses when DOMPurify.sanitize is nearby
- **FE003** (postMessage origin) -- now context-aware, won't flag inside comments
- **ENC005** (Weak Randomness) -- severity reduced from Error to Warning, more appropriate for non-cryptographic uses
- **BIZ001** (Premium Bypass) -- now only fires in payment/subscription-related files
- **CRED007** (.env Detection) -- split into code detection and project advisory for .gitignore check
- **DEP003-DEP006**, **ENC008** -- converted from per-line informational to project advisories
- **LOG004-LOG009** -- converted to project advisories (fire once per scan, not per file)

### Fixed

- False positives from SQL keywords in comments or documentation strings
- False positives from innerHTML in JSX text content
- Generic reminders appearing on arbitrary lines throughout codebase

---

## [5.0.0] - 2026-01-30

### Added

- **AI-Powered Fix Generation** -- click "AI Fix" on any security issue to generate and apply a fix using Claude, GPT-4, or Gemini
- **Issue Status Tracking** -- mark issues as fixed, ignored, or pending; status persists across VS Code restarts via workspaceState
- **Fix Progress Bar** -- results panel shows resolved count (e.g., "35/120 resolved (28 fixed, 7 ignored)")
- **Diff Preview** -- review AI-generated fixes side-by-side before applying; confirm or cancel
- **Post-Fix Verification** -- after applying a fix, the file is re-scanned to verify the issue is resolved
- **AI Settings Panel** -- dedicated webview to configure AI provider, model, and API key with connection testing
- **Secure API Key Storage** -- keys stored in VS Code SecretStorage (OS keychain), never in settings.json
- **3 AI Provider Support** -- Anthropic Claude, OpenAI GPT-4, and Google Gemini with provider-specific API handling
- **Fix Status Filter** -- filter results panel by status: All, Pending, Fixed, Ignored, Fix Failed
- **Status Bar Fix Info** -- status bar shows fix/ignore counts alongside issue count
- New commands: "Configure AI Fix Provider", "Fix Issue with AI", "Ignore Issue", "Reset Fix Tracker"
- New settings: `caspianSecurity.aiProvider` (anthropic/openai/gemini), `caspianSecurity.aiModel` (optional override)
- New files: `src/aiFixService.ts`, `src/fixTracker.ts`, `src/aiSettingsPanel.ts`

### Changed

- "Show Fix Suggestion" command upgraded to "Fix Issue (AI or Suggestion)" -- now attempts AI fix when configured, falls back to text suggestion
- Results panel table now includes an Actions column with per-issue AI Fix/Ignore buttons
- Fixed and ignored issues are visually dimmed in the results table
- Results panel header now includes "AI Settings" button

---

## [4.3.0] - 2026-01-29

### Added

- Dependency & stack update checker -- runs `npm outdated`, `npm audit`, and checks Node.js, TypeScript, and VS Code engine versions against latest releases
- New command: "Caspian Security: Check Dependency & Stack Updates" for on-demand dependency checking from the Command Palette
- Standalone CLI tool: `npm run check-updates` runs the dependency checker from the terminal without VS Code
- Dependency checks automatically included in workspace scans when the Dependencies & Supply Chain category is enabled
- New setting: `caspianSecurity.includeDependencyCheck` (default: true) to control whether workspace scans include dependency checking
- Dedicated "Caspian Security: Dependencies" Output Channel for detailed update and vulnerability reports
- Audit vulnerabilities and outdated packages surfaced as SecurityIssues in the Results Panel under the Dependencies & Supply Chain category
- New files: `src/dependencyChecker.ts` (core logic) and `src/cli/checkUpdates.ts` (standalone CLI entry point)

---

## [4.2.0] - 2026-01-29

### Added

- Pre-scan estimate with confirmation -- workspace scans now show file counts by language and total batches before scanning, with Start Scan/Cancel buttons
- Smart batch scanning -- files are grouped by language and split into batches of 50, with Continue/Stop prompts between each batch showing progress and what's next
- `.next/` directory excluded from workspace scans (Next.js build output)

### Fixed

- VS Code freezing during large workspace scans -- added event loop yielding every 10 files to keep the UI responsive
- Excessive UI updates during scanning -- debounced results store change events (300ms) to prevent thousands of webview re-renders

---

## [3.0.0] - 2025-01-29

### Added

- 133 security rules across 14 categories (up from 16 rules in v1.0)
- 14 security categories with dedicated per-category commands
- Per-category enable/disable toggle settings
- Full workspace scanning -- discovers and scans all project files on disk
- Cancellable workspace scans with file-level progress reporting
- Business Logic & Payment Security category (BIZ001--BIZ009)
- Logging & Monitoring category (LOG001--LOG009)
- Dependencies & Supply Chain category (DEP001--DEP006)
- Infrastructure & Deployment category (INFRA001--INFRA008)
- Informational rule type for process and policy reminders
- Category-scoped diagnostics that preserve other categories' results

### Changed

- Rule codes reorganized by category: AUTH, XSS, CSRF, CORS, ENC, API, DB, FILE, CRED, FE, BIZ, LOG, DEP, INFRA
- Workspace scan uses `findFiles()` to scan all files, not just open tabs
- Full Scan command falls back to workspace scan when no file is open
- Configuration uses individual boolean toggles per category instead of a single array

---

## [1.0.0] - Initial Release

### Added

- 16 security rules (SEC001--SEC016)
- Real-time analysis as you type with 1-second debounce
- Check on save
- 8 language support (JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust)
- Configurable severity levels
- Workspace-wide scanning for open documents
