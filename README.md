# Caspian Security

Context-aware security analysis for Visual Studio Code.

---

## Overview

Caspian Security is a VS Code extension that detects vulnerabilities, insecure coding patterns, and security best practice violations as you write code. It provides **133 security rules** across **14 categories**, covering SQL injection, XSS, hardcoded secrets, business logic flaws, and more.

What sets it apart: **context-aware intelligence**. The scanner classifies detected issues with confidence scores (Critical, Safe, or Verify Needed) based on variable-source analysis. AI-powered fixes understand the full function scope and variable definitions -- not just the error line. Teams can share ignore decisions via `.caspianignore`, and scan results export to **SARIF v2.1.0** for direct upload to GitHub Security Alerts.

---

## Key Capabilities

- **Context-aware analysis** -- classifies issues by variable source (hardcoded, static, or dynamic) with confidence badges
- **AI fixes with function-level understanding** -- sends the entire enclosing function and traced variable definitions to the AI, not just 20 lines of context
- **133 security rules** across 14 categories with actionable fix suggestions
- **Real-time analysis** -- checks code as you type with a 1-second debounce to avoid lag
- **Full workspace scanning** -- scans all project files on disk, not just open tabs
- **8 languages supported** -- JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust
- **Team-shareable `.caspianignore`** -- persist ignore decisions to a version-controlled file with optional reasons
- **SARIF v2.1.0 export** -- upload scan results directly to GitHub Security Alerts
- **Per-category toggles** -- enable or disable each security category independently
- **3 AI providers** -- Anthropic Claude, OpenAI GPT-4, and Google Gemini for fix generation
- **Cancellable scans** -- workspace scans show progress and can be cancelled mid-run
- **Configurable severity** -- filter diagnostics by error, warning, or info thresholds
- **False positive controls** -- context-aware rules, generated file detection, masking function detection, internal-path severity reduction, pagination-aware rules, and a toggle to hide informational reminders
- **Learning Intelligence** -- the extension learns from every scan, fix, ignore, and false positive to improve accuracy over time: adaptive confidence scoring, fix pattern memory for instant replays, codebase-specific safe pattern learning, regression detection, and actionable insights
- **Security Task Management** -- 23 recurring security tasks across all 14 categories with configurable intervals, overdue reminders, auto-completion on scans, per-project persistence, and a dedicated detail panel for viewing and managing tasks

---

## Supported Languages

| Language   | File Extensions              |
|------------|------------------------------|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs`|
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts`|
| Python     | `.py`                        |
| Java       | `.java`                      |
| C#         | `.cs`                        |
| PHP        | `.php`                       |
| Go         | `.go`                        |
| Rust       | `.rs`                        |

---

## Security Categories

| Category                          | Rules | Codes            | Covers                                                        |
|-----------------------------------|-------|------------------|---------------------------------------------------------------|
| Authentication & Access Control   | 7     | AUTH001--AUTH007  | JWT secrets, session flags, password comparison, rate limiting |
| Input Validation & XSS            | 11    | XSS001--XSS011   | innerHTML, document.write, template injection, CSP            |
| CSRF Protection                   | 7     | CSRF001--CSRF007 | Token validation, SameSite cookies, GET state changes          |
| CORS Configuration                | 6     | CORS001--CORS006 | Wildcard origins, reflected origins, preflight caching         |
| Encryption & Data Protection      | 12    | ENC001--ENC012   | Weak crypto, hardcoded keys, HSTS, PII masking, GDPR          |
| API Security                      | 14    | API001--API014   | Auth middleware, IDOR, rate limiting, GraphQL, error exposure  |
| Database Security                 | 12    | DB001--DB012     | SQL injection, NoSQL injection, least privilege, default creds |
| File Handling                     | 14    | FILE001--FILE014 | Path traversal, upload validation, cloud storage, magic bytes  |
| Secrets & Credentials             | 9     | CRED001--CRED009 | Hardcoded passwords, AWS keys, private keys, GitHub tokens     |
| Frontend Security                 | 9     | FE001--FE009     | eval(), postMessage, iframe sandbox, prototype pollution       |
| Business Logic & Payment Security | 9     | BIZ001--BIZ009   | Premium checks, payment verification, refunds, quotas          |
| Logging & Monitoring              | 9     | LOG001--LOG009   | Auth logging, sensitive data in logs, log encryption           |
| Dependencies & Supply Chain       | 6     | DEP001--DEP006   | Version pinning, patching SLA, auditing, transitive deps       |
| Infrastructure & Deployment       | 8     | INFRA001--INFRA008 | Env separation, debug mode, Docker secrets, source maps      |

**Total: 133 rules** (74 code-detectable + 59 informational)

---

## Installation

### From VSIX File

1. Download the `.vsix` file from the [Releases](https://github.com/Caspian-Explorer/caspian-security/releases) page
2. Open VS Code
3. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
4. Search for **"Extensions: Install from VSIX"**
5. Select the downloaded file

### From VS Code Marketplace

1. Open the Extensions view (`Ctrl+Shift+X`)
2. Search for **"Caspian Security"**
3. Click **Install**

---

## Usage

### Commands

Open the Command Palette (`Ctrl+Shift+P`) and search for any of the following:

| Command                                              | Description                                   |
|------------------------------------------------------|-----------------------------------------------|
| Caspian Security: Check Current File                 | Scan the active file                          |
| Caspian Security: Check Entire Workspace             | Scan all supported files in the project       |
| Caspian Security: Run Full Security Scan             | Scan all categories (file or workspace)       |
| Caspian Security: Fix Issue with AI                  | Generate and apply an AI-powered security fix |
| Caspian Security: Configure AI Fix Provider          | Set up API key for Claude, GPT-4, or Gemini  |
| Caspian Security: Verify Issue Resolution            | Re-scan a file to confirm an issue is resolved|
| Caspian Security: Ignore Issue                       | Mark issue as ignored and write to `.caspianignore` |
| Caspian Security: Show Results Panel                 | Open the interactive results panel            |
| Caspian Security: Export Results to JSON             | Export scan results as JSON                   |
| Caspian Security: Export Results to CSV              | Export scan results as CSV                    |
| Caspian Security: Export Results to SARIF            | Export SARIF v2.1.0 for GitHub Security Alerts|
| Caspian Security: Check Dependency & Stack Updates   | Check for outdated packages and vulnerabilities|
| Caspian Security: Scan Uncommitted Files             | Scan only git-modified files                  |
| Caspian Security: Check Authentication & Access Control | Scan for AUTH rules only                   |
| Caspian Security: Check Input Validation & XSS       | Scan for XSS rules only                      |
| Caspian Security: Check CSRF Protection              | Scan for CSRF rules only                     |
| Caspian Security: Check CORS Configuration           | Scan for CORS rules only                     |
| Caspian Security: Check Encryption & Data Protection | Scan for ENC rules only                      |
| Caspian Security: Check API Security                 | Scan for API rules only                      |
| Caspian Security: Check Database Security            | Scan for DB rules only                       |
| Caspian Security: Check File Handling                | Scan for FILE rules only                     |
| Caspian Security: Check Secrets & Credentials        | Scan for CRED rules only                     |
| Caspian Security: Check Frontend Security            | Scan for FE rules only                       |
| Caspian Security: Check Business Logic & Payment     | Scan for BIZ rules only                      |
| Caspian Security: Check Logging & Monitoring         | Scan for LOG rules only                      |
| Caspian Security: Check Dependencies & Supply Chain  | Scan for DEP rules only                      |
| Caspian Security: Check Infrastructure & Deployment  | Scan for INFRA rules only                    |
| Caspian Security: Show Learning Dashboard            | Open the learning intelligence dashboard     |
| Caspian Security: Reset All Learning Data            | Clear all learned data (with confirmation)   |
| Caspian Security: Export Learning Data               | Export learning data as JSON                 |
| Caspian Security: Preview Telemetry Data             | View exact telemetry payload before enabling |

### Scan Modes

**Auto Check** (enabled by default)
Runs security analysis as you type. Results appear in real-time as diagnostic squiggles in the editor. Uses a 1-second debounce to minimize CPU usage.

**Check on Save** (enabled by default)
Runs a full check whenever a file is saved.

**Manual Scan**
Run any command from the Command Palette to scan the current file or a specific category.

**Workspace Scan**
Discovers all supported files in your project (excluding `node_modules`) and scans them with a progress indicator. The scan can be cancelled at any time.

**Dependency Check**
Checks for outdated npm packages, known vulnerabilities (`npm audit`), and stack component updates (Node.js, TypeScript, VS Code engine). Can be run standalone from the Command Palette or automatically as part of a workspace scan. Also available as a CLI tool via `npm run check-updates`.

---

## AI Fix with Smart Context

When you click **AI Fix** on a detected issue, the extension extracts the full enclosing function using VS Code's built-in symbol provider and traces variable definitions referenced in the vulnerable line. The AI receives:

1. **The complete function body** -- not just 20 lines, but the entire function scope
2. **Variable definitions** -- where each relevant variable was declared or assigned
3. **Security-expert instruction** -- "Fix the issue on line N within the function scope without breaking the surrounding logic"

This produces significantly better fixes for issues buried deep inside complex functions. If no symbol provider is available (e.g., plain text files), the extension falls back to the standard 20-line surrounding context.

**Supported AI providers:** Anthropic Claude, OpenAI GPT-4, Google Gemini. Configure via the **AI Settings** button in the results panel.

---

## Confidence Scoring

Each detected issue is analyzed for a **confidence level** based on lightweight variable-source heuristics:

| Level | Badge | Meaning | Example |
|-------|-------|---------|---------|
| Critical | Red | Hardcoded secret as a string literal | `const password = "admin123"` |
| Safe | Green | Static string with no dynamic input | `const query = "SELECT * FROM users"` |
| Verify Needed | Orange | Dynamic value via concatenation or interpolation | `const query = "SELECT * FROM " + userInput` |

Confidence badges appear:
- In the **Results Panel** next to the Verify button
- In **VS Code diagnostics** as a prefix (e.g., `[Critical] [Secrets] CRED001: ...`)

Confidence is only shown when the heuristic is confident in its classification. Issues without a clear signal show no badge.

---

## Learning Intelligence

Caspian Security learns from every scan, fix, ignore, and false positive to improve accuracy over time. All learning is per-workspace and persists across VS Code restarts.

### What it learns

- **Rule effectiveness** -- tracks detection counts, false positive rates, fix rates, and AI fix success rates per rule, broken down by language and file pattern
- **Adaptive confidence** -- shifts confidence levels based on accumulated behavior (rules with high FP rates get downgraded, highly-acted-on rules get upgraded)
- **Fix patterns** -- remembers successful AI fixes and offers instant replay for similar issues without an API call
- **Safe patterns** -- learns which sanitizer/validator functions neutralize which rules (from AI fixes and FP dismissals)
- **Hot zones** -- identifies directories with the highest confirmed issue density
- **Regressions** -- detects when previously fixed issues reappear

### Learning Dashboard

Run **"Caspian Security: Show Learning Dashboard"** to see:
- Overview stats (total observations, scans, learning events)
- Sortable rule effectiveness table with FP rates and fix rates
- Fix pattern library with success rates
- Codebase hot zones ranked by risk
- Active insights with action buttons

### Opt-in Telemetry

Help improve Caspian Security by sharing anonymized rule effectiveness statistics. **Off by default.** No code, file paths, or project names are ever sent -- only rule codes and numeric counts. Run **"Preview Telemetry Data"** to see the exact payload before enabling. Enable via `caspianSecurity.enableTelemetry` in settings.

---

## .caspianignore

When you click **Ignore** on an issue, the decision is written to a `.caspianignore` file in the workspace root. This file can be committed to version control so the entire team shares the same ignore list.

### Format

```
# Caspian Security Ignore File
# Format: RULE_CODE file/path.ts:line # optional reason

XSS001 src/app.ts:42 # False positive, sanitized upstream
CRED001 src/config.ts # Test credentials only
```

### Behavior

- **On ignore click:** an optional input box prompts for a reason, then the entry is appended
- **On startup:** the file is loaded and cached
- **On file change:** a file watcher reloads the ignore list automatically
- **Matching:** rule code and file path must match. If a line number is specified, it must match too. Omitting the line ignores all instances of that rule in that file.

---

## Export Formats

The results panel header includes buttons to export scan results in three formats:

| Format | Button | Use Case |
|--------|--------|----------|
| **JSON** | Export JSON | Custom integrations, dashboards, CI/CD pipelines |
| **CSV** | Export CSV | Spreadsheets, tabular analysis, reporting |
| **SARIF v2.1.0** | Export SARIF | GitHub Security Alerts, standard SAST tooling |

The SARIF export follows the [OASIS SARIF v2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and includes rule definitions, severity mapping (Error/Warning/Info to error/warning/note), and physical source locations with 1-based line numbers. Upload it to **GitHub > Security > Code scanning > Upload SARIF** to see results in your repository's security dashboard.

---

## Configuration

Open VS Code Settings (`Ctrl+,`) and search for **"Caspian Security"** to configure the extension.

### General Settings

| Setting                             | Type     | Default   | Description                                 |
|-------------------------------------|----------|-----------|---------------------------------------------|
| `caspianSecurity.autoCheck`         | boolean  | `true`    | Automatically run checks as you type        |
| `caspianSecurity.checkOnSave`       | boolean  | `true`    | Run checks when files are saved             |
| `caspianSecurity.severity`          | string   | `warning` | Minimum severity level (`error`, `warning`, `info`) |
| `caspianSecurity.enabledLanguages`  | array    | All 8     | Languages to include in security checks     |
| `caspianSecurity.includeDependencyCheck` | boolean | `true` | Include dependency update and vulnerability checks during workspace scans |
| `caspianSecurity.showInformational`      | boolean  | `true`    | Show informational reminders alongside security findings. Disable to see only actionable issues |
| `caspianSecurity.reduceInternalPathSeverity` | boolean | `true` | Reduce severity for files in admin, scripts, internal, seed, and migration directories |
| `caspianSecurity.enableTelemetry`            | boolean  | `false`   | Share anonymized rule effectiveness statistics (no code or file data) |

### AI Settings

| Setting                             | Type     | Default      | Description                                 |
|-------------------------------------|----------|--------------|---------------------------------------------|
| `caspianSecurity.aiProvider`        | string   | `anthropic`  | AI provider for fix generation (`anthropic`, `openai`, `gemini`) |
| `caspianSecurity.aiModel`           | string   | `""`         | Optional model override (leave empty for provider default) |

API keys are stored securely in the OS keychain via VS Code's SecretStorage API -- they never appear in `settings.json`.

### Category Toggles

Each security category can be independently enabled or disabled:

| Setting                                          | Default | Category                          |
|--------------------------------------------------|---------|-----------------------------------|
| `caspianSecurity.enableAuthAccessControl`        | `true`  | Authentication & Access Control   |
| `caspianSecurity.enableInputValidationXss`       | `true`  | Input Validation & XSS            |
| `caspianSecurity.enableCsrfProtection`           | `true`  | CSRF Protection                   |
| `caspianSecurity.enableCorsConfiguration`        | `true`  | CORS Configuration                |
| `caspianSecurity.enableEncryptionDataProtection` | `true`  | Encryption & Data Protection      |
| `caspianSecurity.enableApiSecurity`              | `true`  | API Security                      |
| `caspianSecurity.enableDatabaseSecurity`         | `true`  | Database Security                 |
| `caspianSecurity.enableFileHandling`             | `true`  | File Handling                     |
| `caspianSecurity.enableSecretsCredentials`       | `true`  | Secrets & Credentials             |
| `caspianSecurity.enableFrontendSecurity`         | `true`  | Frontend Security                 |
| `caspianSecurity.enableBusinessLogicPayment`     | `true`  | Business Logic & Payment Security |
| `caspianSecurity.enableLoggingMonitoring`        | `true`  | Logging & Monitoring              |
| `caspianSecurity.enableDependenciesSupplyChain`  | `true`  | Dependencies & Supply Chain       |
| `caspianSecurity.enableInfrastructureDeployment` | `true`  | Infrastructure & Deployment       |

### Example Configuration

```json
{
  "caspianSecurity.autoCheck": true,
  "caspianSecurity.checkOnSave": true,
  "caspianSecurity.severity": "warning",
  "caspianSecurity.enabledLanguages": ["javascript", "typescript", "python"],
  "caspianSecurity.aiProvider": "anthropic",
  "caspianSecurity.enableCsrfProtection": false,
  "caspianSecurity.enableLoggingMonitoring": false
}
```

---

## Rule Reference

Each rule has a **severity** (Error, Warning, or Info) and a **type**: code-detectable rules use pattern matching to find issues in your source code, while informational rules fire as reminders when related code is detected.

### Authentication & Access Control (7 rules)

| Code    | Rule                                              | Severity | Type |
|---------|---------------------------------------------------|----------|------|
| AUTH001 | Hardcoded JWT secret detected                     | Error    | Code |
| AUTH002 | Session configured without secure flags            | Warning  | Code |
| AUTH003 | Passwords compared with equality instead of constant-time | Error | Code |
| AUTH004 | Authentication bypass: permissive access control   | Warning  | Code |
| AUTH005 | Weak password policy: minimum length too short     | Warning  | Code |
| AUTH006 | Apply rate limiting to authentication endpoints    | Info     | Info |
| AUTH007 | Token stored in localStorage is vulnerable to XSS  | Warning  | Code |

### Input Validation & XSS (11 rules)

| Code    | Rule                                              | Severity | Type |
|---------|---------------------------------------------------|----------|------|
| XSS001  | Use of innerHTML can lead to XSS                  | Error    | Code |
| XSS002  | Dangerous use of document.write()                 | Error    | Code |
| XSS003  | Unsanitized user input in HTML string concatenation | Warning | Code |
| XSS004  | Use of dangerouslySetInnerHTML in React            | Warning  | Code |
| XSS005  | Unescaped output in template engine               | Warning  | Code |
| XSS006  | Request parameters used without validation         | Warning  | Info |
| XSS007  | Angular security bypass function used              | Warning  | Code |
| XSS008  | Implement Content Security Policy headers          | Info     | Info |
| XSS009  | User input used without length validation          | Warning  | Info |
| XSS010  | User input in inline script context without encoding | Error  | Code |
| XSS011  | User input in URL without encoding                 | Warning  | Code |

### CSRF Protection (7 rules)

| Code     | Rule                                              | Severity | Type |
|----------|---------------------------------------------------|----------|------|
| CSRF001  | Form without CSRF token                           | Warning  | Info |
| CSRF002  | CSRF protection explicitly disabled               | Error    | Code |
| CSRF003  | Cookie SameSite set to None                       | Warning  | Code |
| CSRF004  | State-changing operation using GET method          | Warning  | Code |
| CSRF005  | Verify CSRF tokens on all state-changing endpoints | Info    | Info |
| CSRF006  | CSRF token may not be cryptographically random     | Warning  | Code |
| CSRF007  | Ensure CSRF tokens expire and rotate per session   | Info     | Info |

### CORS Configuration (6 rules)

| Code     | Rule                                              | Severity | Type |
|----------|---------------------------------------------------|----------|------|
| CORS001  | CORS allows all origins (wildcard)                | Error    | Code |
| CORS002  | CORS credentials with permissive origin            | Warning  | Info |
| CORS003  | CORS origin reflected from request without validation | Error | Code |
| CORS004  | Overly permissive CORS methods                    | Warning  | Code |
| CORS005  | Review CORS headers for least privilege            | Info     | Info |
| CORS006  | CORS preflight cache set too long                 | Warning  | Code |

### Encryption & Data Protection (12 rules)

| Code    | Rule                                              | Severity | Type |
|---------|---------------------------------------------------|----------|------|
| ENC001  | Weak or deprecated cryptographic algorithm         | Error    | Code |
| ENC002  | Hardcoded encryption key or IV                     | Error    | Code |
| ENC003  | HTTP used instead of HTTPS for external URL        | Warning  | Code |
| ENC004  | TLS/SSL certificate verification disabled          | Error    | Code |
| ENC005  | Weak random number generation for security purpose | Warning  | Code |
| ENC006  | ECB mode detected (insecure block cipher mode)     | Error    | Code |
| ENC007  | Sensitive data logged or printed                   | Warning  | Code |
| ENC008  | Ensure PII and sensitive fields are encrypted at rest | Info  | Info |
| ENC009  | Missing or misconfigured HSTS header               | Warning  | Info |
| ENC010  | PII field logged without masking                   | Warning  | Code |
| ENC011  | Ensure database backups are encrypted              | Info     | Info |
| ENC012  | Ensure GDPR data export and deletion capabilities  | Info     | Info |

### API Security (14 rules)

| Code    | Rule                                              | Severity | Type |
|---------|---------------------------------------------------|----------|------|
| API001  | Ensure authentication middleware on API endpoints  | Warning  | Info |
| API002  | GraphQL introspection may be enabled in production | Warning  | Code |
| API003  | Apply rate limiting to API routes                  | Info     | Info |
| API004  | Verbose error details exposed to client            | Warning  | Code |
| API005  | Missing request body size limit                    | Warning  | Code |
| API006  | Debug or development mode enabled                  | Warning  | Code |
| API007  | Error stack trace exposed                          | Warning  | Code |
| API008  | Validate API keys/tokens before processing         | Info     | Info |
| API009  | Ensure API keys have expiration and rotation       | Info     | Info |
| API010  | Possible IDOR: resource accessed without authz check | Warning | Info |
| API011  | Overly permissive or wildcard permissions           | Warning  | Code |
| API012  | Configure burst limits and rate limit headers      | Info     | Info |
| API013  | Differentiate rate limits for authed vs anonymous  | Info     | Info |
| API014  | Ensure DDoS protection is in place                 | Info     | Info |

### Database Security (12 rules)

| Code   | Rule                                              | Severity | Type |
|--------|---------------------------------------------------|----------|------|
| DB001  | Potential SQL injection via string concatenation   | Error    | Code |
| DB002  | NoSQL injection: unsanitized input in query object | Error    | Code |
| DB003  | Database connection string with embedded credentials | Error  | Code |
| DB004  | ORM raw query with potential injection             | Warning  | Code |
| DB005  | Command injection in system/exec call              | Error    | Code |
| DB006  | SELECT * may over-fetch sensitive columns          | Info     | Info |
| DB007  | Review destructive SQL operations carefully        | Info     | Info |
| DB008  | Ensure database user has least-privilege access    | Info     | Info |
| DB009  | Test database backups regularly                    | Info     | Info |
| DB010  | Enable database access logging and auditing        | Info     | Info |
| DB011  | Possible default or common database credentials    | Error    | Code |
| DB012  | Restrict database network access to app servers    | Info     | Info |

### File Handling (14 rules)

| Code     | Rule                                              | Severity | Type |
|----------|---------------------------------------------------|----------|------|
| FILE001  | Path traversal: user input in file path            | Error    | Code |
| FILE002  | Validate file uploads for type, size, and content  | Warning  | Info |
| FILE003  | Temporary file with insecure permissions            | Warning  | Code |
| FILE004  | Symlink following may lead to path traversal       | Warning  | Code |
| FILE005  | World-writable file permissions                    | Warning  | Code |
| FILE006  | File path constructed from user input              | Error    | Code |
| FILE007  | Store uploaded files outside the web root          | Info     | Info |
| FILE008  | File upload without virus/malware scanning         | Warning  | Info |
| FILE009  | Cloud storage bucket may be publicly accessible    | Error    | Code |
| FILE010  | Serve files through signed/pre-signed URLs         | Info     | Info |
| FILE011  | Restrict storage access to authenticated users     | Info     | Info |
| FILE012  | Executable file extension allowed in upload        | Error    | Code |
| FILE013  | Enable access logs for file storage                | Info     | Info |
| FILE014  | File type validated by extension only, not magic bytes | Warning | Code |

### Secrets & Credentials (9 rules)

| Code     | Rule                                              | Severity | Type |
|----------|---------------------------------------------------|----------|------|
| CRED001  | Hardcoded password or secret assignment            | Error    | Code |
| CRED002  | AWS access key pattern detected                    | Error    | Code |
| CRED003  | Private key content detected in source code        | Error    | Code |
| CRED004  | GitHub/GitLab personal access token pattern        | Error    | Code |
| CRED005  | Generic high-entropy secret in string literal      | Warning  | Code |
| CRED006  | Environment variable with sensitive default fallback | Warning | Code |
| CRED007  | Sensitive file reference -- ensure it is in .gitignore | Warning | Info |
| CRED008  | Rotate secrets regularly and audit access          | Info     | Info |
| CRED009  | Scan git history for leaked secrets                | Info     | Info |

### Frontend Security (9 rules)

| Code   | Rule                                              | Severity | Type |
|--------|---------------------------------------------------|----------|------|
| FE001  | Unsafe eval() allows arbitrary code execution      | Error    | Code |
| FE002  | postMessage without origin validation              | Warning  | Code |
| FE003  | Links opened without rel="noopener noreferrer"     | Warning  | Info |
| FE004  | Insecure iframe without sandbox attribute          | Warning  | Code |
| FE005  | Script loaded from CDN without integrity check     | Warning  | Code |
| FE006  | Sensitive data stored via document.cookie           | Warning  | Code |
| FE007  | Prototype pollution: unsafe __proto__ or constructor | Warning | Code |
| FE008  | Add Subresource Integrity for CDN resources        | Info     | Info |
| FE009  | Client-side validation is for UX only; server-side required | Info | Info |

### Business Logic & Payment Security (9 rules)

| Code   | Rule                                              | Severity | Type |
|--------|---------------------------------------------------|----------|------|
| BIZ001 | Premium feature check may be client-side only      | Error    | Info |
| BIZ002 | Verify payment success server-side before unlocking | Warning | Info |
| BIZ003 | Refund logic may allow duplicate refunds           | Warning  | Info |
| BIZ004 | Trial period logic may be exploitable              | Warning  | Info |
| BIZ005 | Revoke access on subscription cancellation         | Info     | Info |
| BIZ006 | Keep subscription state synced with payment processor | Info  | Info |
| BIZ007 | Quota or usage limit may be client-side only       | Warning  | Info |
| BIZ008 | Usage tracking may rely on client-reported data    | Warning  | Code |
| BIZ009 | Ensure quota resets occur server-side              | Info     | Info |

### Logging & Monitoring (9 rules)

| Code   | Rule                                              | Severity | Type |
|--------|---------------------------------------------------|----------|------|
| LOG001 | Log all authentication attempts                    | Info     | Info |
| LOG002 | Log all authorization failures                     | Info     | Info |
| LOG003 | Log all admin and privileged operations            | Info     | Info |
| LOG004 | Log role/permission and payment/key changes        | Info     | Info |
| LOG005 | Password may be present in log output              | Error    | Code |
| LOG006 | API key or secret may be present in log output     | Error    | Code |
| LOG007 | Store logs securely with encryption                | Info     | Info |
| LOG008 | Restrict log access to admin/security personnel    | Info     | Info |
| LOG009 | Log data export and API key change operations      | Info     | Info |

### Dependencies & Supply Chain (6 rules)

| Code   | Rule                                              | Severity | Type |
|--------|---------------------------------------------------|----------|------|
| DEP001 | Dependency version is not pinned to an exact version | Warning | Code |
| DEP002 | Keep dependencies updated regularly                | Info     | Info |
| DEP003 | Apply security patches within 48 hours             | Info     | Info |
| DEP004 | Run npm audit / pip-audit weekly                   | Info     | Info |
| DEP005 | Identify and remediate known vulnerable dependencies | Info   | Info |
| DEP006 | Monitor transitive dependencies for vulnerabilities | Info    | Info |

### Infrastructure & Deployment (8 rules)

| Code     | Rule                                              | Severity | Type |
|----------|---------------------------------------------------|----------|------|
| INFRA001 | Use separate databases, keys, and configs for dev and production | Info | Info |
| INFRA002 | Debug mode may be enabled in production configuration | Warning | Code |
| INFRA003 | Verbose or debug logging level may be active in production | Warning | Code |
| INFRA004 | Stack traces may be exposed in production configuration | Warning | Code |
| INFRA005 | Secret may be embedded in Docker image via ENV, ARG, or COPY | Error | Code |
| INFRA006 | Ensure secrets are not printed in build or CI logs | Warning | Info |
| INFRA007 | Source maps may be deployed to production          | Warning  | Code |
| INFRA008 | Test, seed, or mock data may be present in production code | Warning | Code |

---

## Troubleshooting

### Extension not activating

- Ensure you have a supported file open (JavaScript, TypeScript, Python, Java, C#, PHP, Go, or Rust)
- Reload the VS Code window: `Ctrl+Shift+P` then **"Developer: Reload Window"**

### No issues appearing

- Verify **Auto Check** is enabled in settings
- Run a manual check: `Ctrl+Shift+P` then **"Caspian Security: Check Current File"**
- Confirm the file language is listed in `caspianSecurity.enabledLanguages`
- Check that the relevant category is not disabled in settings

### Too many diagnostics

- Increase the severity threshold to `error` to see only critical issues
- Disable informational categories you do not need (e.g., Business Logic, Logging)
- Informational rules fire once per file to minimize noise

---

## Complementary Tools

Caspian Security uses pattern-based static analysis with context-aware intelligence and includes built-in dependency checking. While it provides broad coverage of common vulnerabilities and best practices, it is not a replacement for professional security auditing. For comprehensive coverage, use it alongside:

- **SAST tools** -- SonarQube, Snyk, Semgrep (Caspian's SARIF export integrates with GitHub Code Scanning alongside these tools)
- **Dynamic security testing** -- OWASP ZAP, Burp Suite
- **Dependency scanning** -- Dependabot, Snyk (Caspian's built-in dependency checker covers `npm audit` and `npm outdated`)
- **GitHub Security Alerts** -- upload Caspian's SARIF export to see results in your repository's security dashboard
- **Regular code reviews and security audits**

---

## Contributing

Found a bug or have a suggestion? Please open an issue on [GitHub](https://github.com/Caspian-Explorer/caspian-security/issues).

---

## License

MIT License -- see [LICENSE](LICENSE) for details.
