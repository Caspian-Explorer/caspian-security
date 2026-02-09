# Caspian Security Extension - Start Here

## What You Have

A **production-ready VS Code security extension** with:

- **133+ security rules** across 14 categories
- **Context-aware analysis** with confidence scoring
- **AI-powered fixes** using Claude, GPT-4, or Gemini with function-level understanding
- **Team-shareable `.caspianignore`** for managing false positives
- **SARIF v2.1.0 export** for GitHub Security Alerts
- **8 languages supported** -- JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust

---

## Documentation Index

**If you want to...**

1. **Get it running in 5 minutes** -- Read [QUICKSTART.md](QUICKSTART.md)
2. **Understand all features and rules** -- Read [README.md](README.md)
3. **Build, customize, and extend it** -- Read [BUILD.md](BUILD.md)
4. **Understand the system architecture** -- Read [ARCHITECTURE.md](ARCHITECTURE.md)
5. **Deploy and set it up** -- Read [SETUP_GUIDE.md](SETUP_GUIDE.md)
6. **See release history** -- Read [CHANGELOG.md](CHANGELOG.md)

---

## Quick Start (3 Steps)

### Step 1: Install & Build
```bash
npm install
npm run compile
```

### Step 2: Run in VS Code
```bash
code .
# Press F5 to start debugging
```

### Step 3: Test It
Create a file with insecure code:
```javascript
const password = "admin123";         // CRED001: Hardcoded credential
const query = "SELECT * FROM users WHERE id = " + id;  // DB001: SQL injection
eval(userCode);                       // FE001: Unsafe eval
```

You'll see security warnings with confidence badges and actionable fix suggestions.

---

## Project Structure

```
caspian-security/
├── src/
│   ├── extension.ts            # Main entry point, commands, scanning
│   ├── analyzer.ts             # Rule engine with context-aware analysis
│   ├── diagnosticsManager.ts   # VS Code diagnostic integration
│   ├── configManager.ts        # Configuration handling
│   ├── resultsStore.ts         # Results storage + JSON/CSV/SARIF export
│   ├── resultsPanel.ts         # Webview results panel
│   ├── statusBarManager.ts     # Status bar integration
│   ├── gitIntegration.ts       # Git SCM integration
│   ├── aiFixService.ts         # AI provider abstraction (Claude/GPT-4/Gemini)
│   ├── aiSettingsPanel.ts      # AI configuration webview
│   ├── fixTracker.ts           # Issue status persistence
│   ├── contextExtractor.ts     # Function scope + variable tracing for AI
│   ├── confidenceAnalyzer.ts   # Confidence classification
│   ├── caspianIgnore.ts        # .caspianignore file parsing
│   ├── dependencyChecker.ts    # npm outdated/audit + stack checking
│   ├── types.ts                # TypeScript type definitions
│   ├── rules/                  # 14 category rule files (133+ rules)
│   │   ├── index.ts            # Rule registry
│   │   ├── authRules.ts        # AUTH001--AUTH007
│   │   ├── inputValidationRules.ts  # XSS001--XSS011
│   │   ├── databaseRules.ts    # DB001--DB012
│   │   ├── secretsRules.ts     # CRED001--CRED009
│   │   └── ... (10 more)
│   └── cli/
│       └── checkUpdates.ts     # Standalone dependency checker CLI
├── out/                        # Compiled JavaScript (generated)
├── package.json                # Extension manifest
├── tsconfig.json               # TypeScript configuration
├── CHANGELOG.md                # Release history
├── README.md                   # Full user documentation
├── BUILD.md                    # Development guide
├── ARCHITECTURE.md             # System design
├── SETUP_GUIDE.md              # Deployment guide
└── icon.png                    # Extension icon
```

---

## Security Categories (14)

| Category | Rules | Codes |
|----------|-------|-------|
| Authentication & Access Control | 7 | AUTH001--AUTH007 |
| Input Validation & XSS | 11 | XSS001--XSS011 |
| CSRF Protection | 7 | CSRF001--CSRF007 |
| CORS Configuration | 6 | CORS001--CORS006 |
| Encryption & Data Protection | 12 | ENC001--ENC012 |
| API Security | 14 | API001--API014 |
| Database Security | 12 | DB001--DB012 |
| File Handling | 14 | FILE001--FILE014 |
| Secrets & Credentials | 9 | CRED001--CRED009 |
| Frontend Security | 9 | FE001--FE009 |
| Business Logic & Payment | 9 | BIZ001--BIZ009 |
| Logging & Monitoring | 9 | LOG001--LOG009 |
| Dependencies & Supply Chain | 6 | DEP001--DEP006 |
| Infrastructure & Deployment | 8 | INFRA001--INFRA008 |

**Total: 133+ rules** (74 code-detectable + 59 informational)

---

## Configuration

All settings use the `caspianSecurity.*` namespace:

```json
{
  "caspianSecurity.autoCheck": true,
  "caspianSecurity.checkOnSave": true,
  "caspianSecurity.severity": "warning",
  "caspianSecurity.showInformational": true,
  "caspianSecurity.reduceInternalPathSeverity": true,
  "caspianSecurity.aiProvider": "anthropic",
  "caspianSecurity.enabledLanguages": [
    "javascript", "typescript", "python", "java",
    "csharp", "php", "go", "rust"
  ]
}
```

---

## Key Features

- **Real-time analysis** with 1-second debounce
- **Context-aware scanning** -- skips matches in comments, strings, and JSX text
- **Confidence scoring** -- Critical/Safe/Verify-Needed badges on each finding
- **AI-powered fixes** with full function scope and variable tracing
- **False positive controls** -- masking detection, pagination awareness, internal-path severity reduction
- **Team-shareable `.caspianignore`** with optional reasons
- **SARIF v2.1.0 export** for GitHub Security Alerts
- **Workspace scanning** with batched progress and cancellation
- **Dependency checking** -- npm outdated, npm audit, stack version checks
- **Git integration** -- scan only uncommitted files

---

## Statistics

| Metric | Value |
|--------|-------|
| **Source Code** | ~5300+ lines TypeScript |
| **Security Rules** | 133+ across 14 categories |
| **Languages Supported** | 8 |
| **AI Providers** | 3 (Claude, GPT-4, Gemini) |
| **Export Formats** | 3 (JSON, CSV, SARIF) |
| **Commands** | 24 |
| **Configuration Options** | 20+ settings |

---

## Getting Started

```bash
npm install
npm run compile
code .
# Press F5 to test
```

See [README.md](README.md) for full documentation, or [QUICKSTART.md](QUICKSTART.md) for the 5-minute guide.
