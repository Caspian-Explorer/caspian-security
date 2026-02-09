# Caspian Security Extension - Build & Development Guide

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
const password = "admin123";  // CRED001: Hardcoded credential
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
│   ├── rules/                  # 14 category rule files (~1200 lines total)
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
│   └── cli/
│       └── checkUpdates.ts     # Standalone dependency checker CLI
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

## Publishing to Marketplace

1. Create Azure DevOps account (required by marketplace)
2. Create Personal Access Token
3. Login:
   ```bash
   vsce login Caspian-Explorer
   ```
4. Publish:
   ```bash
   vsce publish
   ```

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

Example `.github/workflows/publish.yml`:
```yaml
name: Publish
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 18
      - run: npm install
      - run: npm run compile
      - run: npx vsce publish
        env:
          VSCE_PAT: ${{ secrets.VSCE_PAT }}
```

---

For full documentation see [README.md](README.md). For system architecture see [ARCHITECTURE.md](ARCHITECTURE.md).
