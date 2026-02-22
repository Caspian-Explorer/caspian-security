# Changelog

All notable changes to the Caspian Security extension are documented in this file.

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
  - **Critical** (red badge) -- hardcoded secret detected as a string literal (e.g., `password = "admin123"`)
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
