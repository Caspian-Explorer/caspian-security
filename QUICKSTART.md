# Caspian Security Extension - Quick Start Guide

## 5-Minute Setup

### Step 1: Install Dependencies
```bash
npm install
```

### Step 2: Compile TypeScript
```bash
npm run compile
```

### Step 3: Launch in VS Code
```bash
code .
# Then press F5 to start debugging
```

## What to Do Next

1. **Create a test file** (`test.js`):
```javascript
// This will trigger security warnings
const password = "admin123";
const apiKey = "sk_live_secret";

function getUser(id) {
  return query("SELECT * FROM users WHERE id = " + id);
}
```

2. **Watch the magic happen** - Security issues will appear as red/yellow squiggles

3. **Check the Problems panel** - View all detected issues with suggestions

## Key Shortcuts

| Action | Shortcut |
|--------|----------|
| Check current file | `Ctrl+Shift+P` → "Check Current File" |
| Check workspace | `Ctrl+Shift+P` → "Check Entire Workspace" |
| View problems | `Ctrl+Shift+M` |
| Open settings | `Ctrl+,` then search "Caspian Security" |

## Built-in Security Rules

The extension detects 16 security patterns including:
- SQL Injection (SEC001)
- Hardcoded Credentials (SEC002)
- Weak Cryptography (SEC003)
- Unsafe eval() (SEC004)
- Path Traversal (SEC005)
- Missing CSRF Protection (SEC006)
- Unsafe Deserialization (SEC007)
- Missing Input Validation (SEC008)
- Missing Authentication (SEC009)
- XXE Vulnerabilities (SEC010)
- Insecure HTTP (SEC011)
- Missing Security Headers (SEC012)
- Logging Sensitive Data (SEC013)
- Missing Rate Limiting (SEC014)
- Command Injection (SEC015)
- Weak Random Numbers (SEC016)

## Configuration

Open Settings (`Ctrl+,`) and search "caspianSecurity":

```json
{
  "caspianSecurity.autoCheck": true,           // Auto-check as you type
  "caspianSecurity.checkOnSave": true,         // Check on save
  "caspianSecurity.severity": "warning",       // Min level: error|warning|info
  "caspianSecurity.enabledLanguages": [
    "javascript",
    "typescript",
    "python",
    "java",
    "csharp",
    "php",
    "go",
    "rust"
  ]
}
```

## Next Steps

📚 **Read Full Documentation**: See `README.md` for comprehensive guide
🔧 **Development Guide**: See `BUILD.md` for building and extending
🚀 **Create Rules**: Add custom security rules in `src/analyzer.ts`

---

**Questions?** Check the troubleshooting section in README.md
