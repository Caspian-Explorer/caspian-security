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
// These will trigger security warnings
const password = "admin123";         // CRED001: Hardcoded credential
const apiKey = "sk_live_secret";     // CRED001: Hardcoded secret

function getUser(id) {
  return query("SELECT * FROM users WHERE id = " + id);  // DB001: SQL injection
}
```

2. **Watch the magic happen** -- Security issues appear as red/yellow squiggles with confidence badges

3. **Check the Problems panel** (`Ctrl+Shift+M`) -- View all detected issues with fix suggestions

4. **Try AI Fix** -- Click "AI Fix" on any issue to generate and apply an AI-powered fix (requires API key)

## Key Shortcuts

| Action | Shortcut |
|--------|----------|
| Check current file | `Ctrl+Shift+P` then "Check Current File" |
| Check workspace | `Ctrl+Shift+P` then "Check Entire Workspace" |
| View problems | `Ctrl+Shift+M` |
| Open results panel | `Ctrl+Shift+P` then "Show Results Panel" |
| Open settings | `Ctrl+,` then search "Caspian Security" |

## What It Detects

133+ security rules across 14 categories:

| Category | Examples |
|----------|----------|
| **Secrets & Credentials** | Hardcoded passwords, AWS keys, API tokens |
| **Database Security** | SQL injection, NoSQL injection, default credentials |
| **Input Validation & XSS** | innerHTML, dangerouslySetInnerHTML, template injection |
| **Authentication** | JWT secrets, session flags, weak passwords |
| **API Security** | Missing auth middleware, IDOR, error exposure |
| **File Handling** | Path traversal, public storage buckets |
| **Business Logic** | Client-side premium checks, payment verification |
| **And more...** | CSRF, CORS, encryption, frontend, infrastructure |

See [README.md](README.md) for the full rule reference.

## Configuration

Open Settings (`Ctrl+,`) and search "caspianSecurity":

```json
{
  "caspianSecurity.autoCheck": true,
  "caspianSecurity.checkOnSave": true,
  "caspianSecurity.severity": "warning",
  "caspianSecurity.showInformational": true,
  "caspianSecurity.reduceInternalPathSeverity": true,
  "caspianSecurity.aiProvider": "anthropic"
}
```

## Next Steps

- **Full documentation**: [README.md](README.md)
- **Development guide**: [BUILD.md](BUILD.md)
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Troubleshooting**: See the troubleshooting section in [README.md](README.md)
