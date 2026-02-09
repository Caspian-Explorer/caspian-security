# Caspian Security Extension - Setup & Deployment Guide

## What's Included

```
caspian-security/
├── src/                              # TypeScript source (~5300+ lines)
│   ├── extension.ts                  # Main entry point, commands, scanning
│   ├── analyzer.ts                   # Rule engine with context-aware analysis
│   ├── diagnosticsManager.ts         # VS Code diagnostic integration
│   ├── configManager.ts              # Configuration handling
│   ├── resultsStore.ts               # Results storage + JSON/CSV/SARIF export
│   ├── resultsPanel.ts               # Webview results panel
│   ├── statusBarManager.ts           # Status bar integration
│   ├── gitIntegration.ts             # Git SCM integration
│   ├── aiFixService.ts              # AI provider abstraction (Claude/GPT-4/Gemini)
│   ├── aiSettingsPanel.ts           # AI configuration webview
│   ├── fixTracker.ts                # Issue status persistence
│   ├── contextExtractor.ts          # Function scope + variable tracing for AI
│   ├── confidenceAnalyzer.ts        # Confidence classification
│   ├── caspianIgnore.ts             # .caspianignore file parsing
│   ├── dependencyChecker.ts         # npm outdated/audit + stack checking
│   ├── types.ts                     # TypeScript type definitions
│   ├── rules/                       # 14 category rule files (133+ rules)
│   │   ├── index.ts                 # Rule registry
│   │   ├── authRules.ts             # AUTH001--AUTH007
│   │   ├── inputValidationRules.ts  # XSS001--XSS011
│   │   ├── csrfRules.ts            # CSRF001--CSRF007
│   │   ├── corsRules.ts            # CORS001--CORS006
│   │   ├── encryptionRules.ts      # ENC001--ENC012
│   │   ├── apiSecurityRules.ts     # API001--API014
│   │   ├── databaseRules.ts        # DB001--DB012
│   │   ├── fileHandlingRules.ts    # FILE001--FILE014
│   │   ├── secretsRules.ts         # CRED001--CRED009
│   │   ├── frontendRules.ts        # FE001--FE009
│   │   ├── businessLogicRules.ts   # BIZ001--BIZ009
│   │   ├── loggingRules.ts         # LOG001--LOG009
│   │   ├── dependenciesRules.ts    # DEP001--DEP006
│   │   └── infrastructureRules.ts  # INFRA001--INFRA008
│   └── cli/
│       └── checkUpdates.ts          # Standalone dependency checker CLI
├── out/                             # Compiled JavaScript (generated)
├── package.json                     # Extension manifest
├── tsconfig.json                    # TypeScript configuration
├── .vscodeignore                    # Packaging config
├── icon.png                         # Extension icon
├── README.md                        # Full user documentation
├── BUILD.md                         # Development guide
├── QUICKSTART.md                    # 5-minute setup
├── ARCHITECTURE.md                  # System design
├── CHANGELOG.md                     # Release history
└── START_HERE.md                    # Documentation index
```

---

## Step-by-Step Setup

### Step 1: Install Dependencies
```bash
cd caspian-security
npm install
```

Installs TypeScript, VS Code SDK, and other build tools.

### Step 2: Compile TypeScript
```bash
npm run compile
```

Converts TypeScript to JavaScript in the `out/` folder.

### Step 3: Test in VS Code (Development Mode)
```bash
code .
```

Then press `F5` to launch the extension in debug mode. A new VS Code window opens with the extension loaded.

### Step 4: Verify It Works

Create a test file with insecure code:

```javascript
// test.js
const password = "admin123";                                    // CRED001
const query = "SELECT * FROM users WHERE id = " + userId;      // DB001
eval(userCode);                                                 // FE001
```

Open the Problems panel (`Ctrl+Shift+M`). You should see security warnings with confidence badges and fix suggestions.

---

## Build & Package (For Distribution)

### Option A: Create VSIX Package
```bash
npm install -g vsce
npm run vscode:prepublish
vsce package
```

Creates a `caspian-security-7.1.0.vsix` file for sharing with teammates or installing locally.

### Option B: Publish to Marketplace
```bash
# First, create Azure DevOps account and Personal Access Token
vsce login Caspian-Explorer
vsce publish
```

Makes the extension available on the VS Code marketplace.

---

## Configuration Reference

All settings are under the `caspianSecurity.*` namespace.

### General Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `autoCheck` | boolean | `true` | Real-time checking as you type (1-second debounce) |
| `checkOnSave` | boolean | `true` | Full check when files are saved |
| `severity` | string | `"warning"` | Minimum severity to display: `"error"`, `"warning"`, or `"info"` |
| `enabledLanguages` | array | 8 languages | Languages to analyze (JS, TS, Python, Java, C#, PHP, Go, Rust) |
| `showInformational` | boolean | `true` | Show informational/best-practice reminders alongside security findings |
| `reduceInternalPathSeverity` | boolean | `true` | Downgrade severity for files in admin, scripts, seed, internal directories |
| `includeDependencyCheck` | boolean | `true` | Include dependency checking in workspace scans |

### AI Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `aiProvider` | string | `"anthropic"` | AI provider: `"anthropic"`, `"openai"`, or `"gemini"` |
| `aiModel` | string | `""` | Optional model override (uses provider default if empty) |

API keys are stored securely in VS Code SecretStorage (OS keychain), not in settings.json.

### Category Toggles

Each security category can be individually enabled or disabled:

| Setting | Category |
|---------|----------|
| `enableAuthentication` | Authentication & Access Control (AUTH) |
| `enableInputValidation` | Input Validation & XSS (XSS) |
| `enableCsrf` | CSRF Protection (CSRF) |
| `enableCors` | CORS Configuration (CORS) |
| `enableEncryption` | Encryption & Data Protection (ENC) |
| `enableApiSecurity` | API Security (API) |
| `enableDatabase` | Database Security (DB) |
| `enableFileHandling` | File Handling (FILE) |
| `enableSecrets` | Secrets & Credentials (CRED) |
| `enableFrontend` | Frontend Security (FE) |
| `enableBusinessLogic` | Business Logic & Payment (BIZ) |
| `enableLogging` | Logging & Monitoring (LOG) |
| `enableDependencies` | Dependencies & Supply Chain (DEP) |
| `enableInfrastructure` | Infrastructure & Deployment (INFRA) |

### Example settings.json

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

## Customization

### Add a New Security Rule

Create a new rule in the appropriate category file under `src/rules/`. For example, to add a new database rule, edit `src/rules/databaseRules.ts`:

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
  contextAware: true,
  negativePatterns: [
    /safe_pattern_on_same_line/i,
  ],
  suppressIfNearby: [
    /safe_pattern_within_3_lines/i,
  ],
  filePatterns: {
    include: [/\.js$/, /\.ts$/],
    exclude: [/\.test\./i, /\.spec\./i],
    reduceSeverityIn: [/scripts?\//i, /admin\//i],
  },
}
```

Then register it in `src/rules/index.ts` and recompile: `npm run compile`.

### Add Support for a New Language

1. Add to `activationEvents` in `package.json`:
   ```json
   "onLanguage:kotlin"
   ```

2. Update defaults in `src/configManager.ts`:
   ```typescript
   return this.config.get('enabledLanguages', [
     'javascript', 'typescript', 'python', 'java',
     'csharp', 'php', 'go', 'rust', 'kotlin'
   ]);
   ```

3. Recompile: `npm run compile`

---

## Testing Checklist

### Functionality
- [ ] Extension activates (F5 debug mode)
- [ ] Real-time checking works (type insecure code)
- [ ] Problems panel shows issues with confidence badges
- [ ] AI fix generates and applies correctly (requires API key)
- [ ] Results panel displays issues with filtering
- [ ] .caspianignore suppresses ignored issues
- [ ] SARIF export produces valid output
- [ ] Workspace scanning completes with progress

### Multi-Language
- [ ] JavaScript (.js)
- [ ] TypeScript (.ts)
- [ ] Python (.py)
- [ ] Java (.java)
- [ ] C# (.cs)
- [ ] PHP (.php)
- [ ] Go (.go)
- [ ] Rust (.rs)
- [ ] Unsupported language produces no false results

### Configuration
- [ ] Auto-check toggle works
- [ ] Check-on-save works
- [ ] Severity filter works
- [ ] Category enable/disable toggles work
- [ ] showInformational toggle hides/shows informational issues
- [ ] reduceInternalPathSeverity downgrades admin/scripts files
- [ ] Settings persist after restart

### Performance
- [ ] No lag during typing (debounce working)
- [ ] Workspace scan completes reasonably (>100 files)
- [ ] Memory usage stable (~5-10 MB)
- [ ] CPU usage minimal when idle

---

## Performance Tuning

If experiencing lag:

**Increase debounce** -- In `src/extension.ts`, change the debounce from 1000 to 2000ms.

**Disable categories** -- Turn off categories you don't need via the `enable<Category>` settings.

**Hide informational rules** -- Set `showInformational` to `false` to reduce noise.

**Limit languages** -- Remove unnecessary languages from `enabledLanguages`.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Cannot find module vscode" | Run `npm install` |
| Extension not appearing | Reload VS Code or restart debug |
| Patterns not matching | Test regex at regex101.com, check language is in enabledLanguages |
| Performance degradation | Increase debounce, disable unused categories, limit languages |
| AI fix not working | Check API key in AI Settings panel, verify provider connectivity |
| .caspianignore not loading | Verify file is in workspace root, check format: `RULE_CODE path:line` |

---

## Deployment Options

### For Internal Use
```bash
vsce package
code --install-extension caspian-security-7.1.0.vsix
```

### For Team Distribution
1. Package the VSIX file
2. Share via your company repository or file share
3. Team members install locally
4. Commit `.caspianignore` to version control for shared false-positive management

### For Public Marketplace
1. Create publisher account on marketplace
2. Update version in `package.json`
3. Run `vsce publish`
4. Extension becomes searchable in VS Code

---

## Release Checklist

Before each release:

- [ ] Update version in `package.json`
- [ ] Update `CHANGELOG.md`
- [ ] Run `npm run compile` successfully
- [ ] Test with multiple file types
- [ ] Test building VSIX: `vsce package`
- [ ] Test installation: `code --install-extension *.vsix`
- [ ] Test in fresh VS Code window
- [ ] Update documentation if rules changed

---

## Extension Metrics

| Metric | Value |
|--------|-------|
| Source Code | ~5300+ lines TypeScript |
| Security Rules | 133+ across 14 categories |
| Languages Supported | 8 |
| AI Providers | 3 (Claude, GPT-4, Gemini) |
| Export Formats | 3 (JSON, CSV, SARIF) |
| Commands | 24 |
| Configuration Options | 20+ settings |
| Memory Usage | ~5-10 MB |
| Analysis Time | 50-200ms per file |
| Debounce Delay | 1 second |

---

## Documentation

| Document | Content |
|----------|---------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute setup guide |
| [README.md](README.md) | Full feature and rule reference |
| [BUILD.md](BUILD.md) | Development and customization guide |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design and analysis pipeline |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [START_HERE.md](START_HERE.md) | Documentation index |
