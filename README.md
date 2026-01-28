# Caspian Security Extension - VS Code

A comprehensive security analysis tool for VS Code that automatically detects vulnerabilities, insecure coding patterns, and security best practice violations in your code.

## Features

✅ **Automatic Real-time Analysis** - Checks code as you type with configurable debouncing
✅ **Multi-Language Support** - Analyzes JavaScript, TypeScript, Python, Java, C#, PHP, Go, and Rust
✅ **16 Built-in Security Rules** - Detects:
   - SQL Injection vulnerabilities
   - Hardcoded credentials
   - Weak cryptographic functions
   - Unsafe eval() usage
   - Path traversal vulnerabilities
   - Missing CSRF protection
   - Unsafe deserialization
   - Missing input validation
   - Missing authentication checks
   - XXE vulnerabilities
   - Insecure HTTP usage
   - Missing security headers
   - Sensitive data logging
   - Missing rate limiting
   - Command injection
   - Weak random number generation

✅ **Actionable Suggestions** - Each issue includes a detailed fix suggestion
✅ **Configurable Severity Levels** - Filter by error, warning, or info
✅ **Workspace-wide Scanning** - Check entire projects with one command
✅ **Smart Debouncing** - Configurable auto-check with 1-second debounce to avoid lag

## Installation

### From VSIX File
1. Download the `security-checker.vsix` file
2. Open VS Code
3. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
4. Search for "Extensions: Install from VSIX"
5. Select the downloaded file

### From VS Code Marketplace
(When published)
1. Open the Extensions view (`Ctrl+Shift+X`)
2. Search for "Security Checker"
3. Click Install

## Usage

### Commands

**Run Security Check on Current File**
- Press `Ctrl+Shift+P` and search for "Caspian Security: Check Current File"
- Or click the Caspian Security icon in the activity bar

**Run Security Check on Entire Workspace**
- Press `Ctrl+Shift+P` and search for "Caspian Security: Check Entire Workspace"

**Auto Check** (Default: Enabled)
- Automatically runs checks as you type
- Results appear in real-time with red/yellow squiggles

**Check on Save** (Default: Enabled)
- Automatically runs a full check when you save files

### Configuration

Open VS Code settings and search for "Caspian Security" to configure:

```json
{
  "caspianSecurity.autoCheck": true,        // Auto-check as you type
  "caspianSecurity.checkOnSave": true,      // Check when files are saved
  "caspianSecurity.severity": "warning",    // Minimum severity: "error", "warning", or "info"
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

## Security Rules Reference

### SEC001: SQL Injection
**Severity**: Error
**Problem**: String concatenation in database queries allows SQL injection
**Fix**: Use parameterized queries with placeholders

```javascript
// ❌ Bad
query("SELECT * FROM users WHERE id = " + userId);

// ✅ Good
query("SELECT * FROM users WHERE id = ?", [userId]);
```

### SEC002: Hardcoded Credentials
**Severity**: Error
**Problem**: Secrets exposed in source code
**Fix**: Use environment variables

```javascript
// ❌ Bad
const apiKey = "sk_live_abc123xyz";

// ✅ Good
const apiKey = process.env.API_KEY;
```

### SEC003: Weak Cryptography
**Severity**: Warning
**Problem**: Using outdated or weak cryptographic algorithms
**Fix**: Use bcrypt, argon2, or PBKDF2 for passwords; SHA-256+ for hashing

```javascript
// ❌ Bad
const hash = crypto.createHash('md5');

// ✅ Good
const hash = crypto.createHash('sha256');
// Or better: use bcrypt for passwords
const hash = await bcrypt.hash(password, 10);
```

### SEC004: Unsafe Eval
**Severity**: Error
**Problem**: eval() executes arbitrary code
**Fix**: Avoid dynamic code execution; use safer alternatives

```javascript
// ❌ Bad
eval(userInput);

// ✅ Good
JSON.parse(userInput);  // For data
```

### SEC005: Path Traversal
**Severity**: Warning
**Problem**: Unvalidated file paths allow access to unintended files
**Fix**: Validate and sanitize file paths

```javascript
// ❌ Bad
readFileSync(userProvidedPath);

// ✅ Good
const safePath = path.resolve(allowedDir, userInput);
if (!safePath.startsWith(allowedDir)) throw new Error('Invalid path');
readFileSync(safePath);
```

### SEC006: Missing CSRF Protection
**Severity**: Warning
**Problem**: POST/PUT/DELETE endpoints without CSRF tokens
**Fix**: Add CSRF middleware

```javascript
// ❌ Bad
app.post('/api/update', (req, res) => {});

// ✅ Good
app.use(csrf());
app.post('/api/update', csrfProtection, (req, res) => {});
```

### SEC007: Unsafe Deserialization
**Severity**: Error
**Problem**: Deserializing untrusted data can execute arbitrary code
**Fix**: Use safe formats and validate input

```python
# ❌ Bad
import pickle
data = pickle.load(file)

# ✅ Good
import json
data = json.load(file)
```

### SEC008: Missing Input Validation
**Severity**: Warning
**Problem**: User input used without validation
**Fix**: Always validate and sanitize input

```javascript
// ❌ Bad
const name = req.body.name;
document.getElementById('output').innerHTML = name;

// ✅ Good
const name = validator.escape(req.body.name);
document.getElementById('output').textContent = name;
```

### SEC009: Missing Authentication
**Severity**: Warning
**Problem**: Protected endpoints accessible without authentication
**Fix**: Add authentication middleware

```javascript
// ❌ Bad
app.get('/api/sensitive', (req, res) => {});

// ✅ Good
app.get('/api/sensitive', authenticateToken, (req, res) => {});
```

### SEC010: XXE (XML External Entity)
**Severity**: Warning
**Problem**: XML parser can be exploited with external entities
**Fix**: Disable external entity processing

```javascript
parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
parser.setFeature("http://xml.org/sax/features/external-general-entities", false);
parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### SEC011: Insecure HTTP
**Severity**: Warning
**Problem**: Using unencrypted HTTP connections
**Fix**: Always use HTTPS in production

```javascript
// ❌ Bad
fetch('http://api.example.com/data');

// ✅ Good
fetch('https://api.example.com/data');
```

### SEC012: Missing Security Headers
**Severity**: Info
**Problem**: Important security headers not configured
**Fix**: Add helmet.js or manually set security headers

```javascript
const helmet = require('helmet');
app.use(helmet());
```

### SEC013: Logging Sensitive Data
**Severity**: Warning
**Problem**: Passwords, tokens, or PII exposed in logs
**Fix**: Never log sensitive information

```javascript
// ❌ Bad
console.log('User login:', { username, password });

// ✅ Good
console.log('User login:', { username });
```

### SEC014: Missing Rate Limiting
**Severity**: Info
**Problem**: No protection against brute force or DoS attacks
**Fix**: Implement rate limiting

```javascript
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);
```

### SEC015: Command Injection
**Severity**: Error
**Problem**: User input passed to shell commands
**Fix**: Use safe command execution with argument arrays

```javascript
// ❌ Bad
exec(`ping ${userInput}`);

// ✅ Good
execFile('ping', [userInput]);
```

### SEC016: Weak Random
**Severity**: Warning
**Problem**: Math.random() is not cryptographically secure
**Fix**: Use crypto.randomBytes()

```javascript
// ❌ Bad
const token = Math.random().toString();

// ✅ Good
const token = crypto.randomBytes(32).toString('hex');
```

## Troubleshooting

### Extension not activating
- Ensure you have supported files open (JS, TS, Python, Java, etc.)
- Reload VS Code window: `Ctrl+Shift+P` → "Developer: Reload Window"

### No issues appearing
- Check that "Auto Check" is enabled in settings
- Try running manual check: `Ctrl+Shift+P` → "Caspian Security: Check Current File"
- Ensure the file language is in `caspianSecurity.enabledLanguages`

### Too many false positives
- Adjust `severity` level to show only errors
- Disable specific languages if needed
- Note: Some rules use pattern matching and may have false positives

## Contributing

Found a bug? Have a suggestion? Please report issues or submit improvements.

## License

MIT License - See LICENSE file for details

## Security Note

This extension uses pattern-based static analysis. While it covers many common vulnerabilities, **it is not a replacement for professional security auditing**. Use in combination with:
- SAST tools (SonarQube, Snyk, etc.)
- Dynamic security testing
- Regular security audits
- Code reviews

---

**Stay Secure! 🔒**
