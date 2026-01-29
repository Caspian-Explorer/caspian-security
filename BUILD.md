# Caspian Security Extension - Build & Development Guide

## Prerequisites

- Node.js (v18 or higher)
- npm (v9 or higher)
- VS Code (v1.85 or higher)
- Git

## Setup Instructions

### 1. Clone or Download the Extension

```bash
cd security-checker-extension
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Compile TypeScript

```bash
npm run compile
```

This generates JavaScript files in the `out/` directory from TypeScript sources in `src/`.

### 4. Run in Development Mode

Option A: Using VS Code directly
```bash
# Open VS Code
code .

# Press F5 to launch debug mode
# This opens a new VS Code window with the extension loaded
```

Option B: Using npm watch
```bash
npm run watch
```

This watches for TypeScript changes and recompiles automatically.

### 5. Test the Extension

1. Open a file with supported language (JS, TS, Python, Java, etc.)
2. Type some code that triggers a security rule (e.g., `password = "123"`)
3. You should see red/yellow squiggles and messages in the Problems panel

## Project Structure

```
security-checker-extension/
├── src/
│   ├── extension.ts          # Main extension entry point
│   ├── analyzer.ts           # Security rule definitions and pattern matching
│   ├── diagnosticsManager.ts # Diagnostic display and management
│   ├── configManager.ts      # Configuration handling
│   └── types.ts              # TypeScript type definitions
├── out/                      # Compiled JavaScript (generated)
├── package.json              # Extension manifest and dependencies
├── tsconfig.json            # TypeScript configuration
├── .vscodeignore            # Files to exclude from package
├── README.md                # User documentation
└── BUILD.md                 # This file
```

## Adding New Security Rules

Edit `src/analyzer.ts` and add to the `initializeRules()` method:

```typescript
{
  code: 'SEC017',
  message: 'Description of the security issue',
  severity: SecuritySeverity.Warning,
  patterns: [
    /regex pattern to match/i,
    'literal string to match',
  ],
  suggestion: 'How to fix this issue',
},
```

## Debugging

### Enable Debug Logging

In `src/extension.ts`, logs are already included:
```typescript
console.log('Security Checker extension activated');
```

View logs in the Debug Console (Ctrl+Shift+U) or VS Code Output panel.

### Debug Specific Rules

Add console.log statements in `analyzer.ts`:
```typescript
console.log(`Analyzing line ${lineNum}:`, line);
console.log(`Match found for rule ${rule.code}`);
```

## Building the Extension Package

### 1. Install vsce (VS Code Extension Manager)

```bash
npm install -g vsce
```

### 2. Update Version

Edit `package.json` and increment the `version` field (e.g., "1.0.0" → "1.0.1")

### 3. Create VSIX Package

```bash
vsce package
```

This generates `caspian-security-1.0.0.vsix` file.

### 4. Install Locally

```bash
# Option A: From VSIX file
code --install-extension caspian-security-1.0.0.vsix

# Option B: Drag and drop into VS Code Extensions view
```

## Publishing to Marketplace

1. Create Azure DevOps account (required by marketplace)
2. Create Personal Access Token
3. Configure vsce:
   ```bash
   vsce login Caspian-Explorer
   ```
4. Publish:
   ```bash
   vsce publish
   ```

## Extending the Extension

### Add Support for More Languages

In `package.json`, add to `activationEvents`:
```json
"onLanguage:solidity",
"onLanguage:swift"
```

Also update `configManager.ts` default enabled languages.

### Add Custom Rules Configuration

Create `src/customRules.ts` to load external rule definitions:
```typescript
export function loadCustomRules(): SecurityRule[] {
  // Load from files or API
}
```

### Add Code Actions (Auto-fix)

Create `src/codeActions.ts`:
```typescript
export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(document, range, context) {
    // Return CodeAction objects for quick fixes
  }
}
```

Register in `extension.ts`:
```typescript
context.subscriptions.push(
  vscode.languages.registerCodeActionProvider(
    { scheme: 'file', language: '*' },
    new SecurityCodeActionProvider()
  )
);
```

## Troubleshooting

### TypeScript Compilation Error
```bash
npm run compile
# Check for type errors and fix them
```

### Extension doesn't load
1. Check Output panel for errors
2. Verify `package.json` main points to correct file
3. Run `npm run compile` again

### Patterns not matching
1. Test regex patterns at https://regex101.com
2. Remember to escape special characters
3. Use `i` flag for case-insensitive matching

## Performance Optimization

### For Large Files

Current debounce: 1 second
- Increase if experiencing lag: `setTimeout(() => { ... }, 2000)`
- Implement incremental analysis for large files
- Consider limiting to specific file sizes

### Rule Optimization

- Order patterns by frequency (most common first)
- Use simple regex instead of complex patterns when possible
- Consider caching parsed rules

## Testing

### Unit Tests (Optional)

Create `src/analyzer.test.ts`:
```typescript
import { SecurityAnalyzer } from './analyzer';

describe('SecurityAnalyzer', () => {
  it('detects SQL injection', () => {
    const analyzer = new SecurityAnalyzer();
    // Test implementation
  });
});
```

Run with: `npm test`

## Continuous Integration

Create `.github/workflows/publish.yml`:
```yaml
name: Publish
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm install
      - run: npm run compile
      - run: npx vsce publish
```

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| "Cannot find module vscode" | Run `npm install` again |
| Extension not appearing | Reload VS Code or restart |
| Patterns matching too much | Add negative lookbehind or refine regex |
| Performance degradation | Increase debounce timer or disable for large files |
| Rule not triggering | Check language is in enabledLanguages |

## Next Steps

1. **Add More Rules**: Create security rules specific to your needs
2. **Community Feedback**: Gather user feedback on false positives
3. **Integrate External Tools**: Call eslint-plugin-security, bandit, etc.
4. **Analytics**: Track which rules are most useful
5. **UI Enhancements**: Add webview for detailed issue information

---

For questions or contributions, please report issues on the project repository.
