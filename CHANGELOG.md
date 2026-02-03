# Changelog

All notable changes to the Caspian Security extension are documented in this file.

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
