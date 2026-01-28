# Security Checker - Architecture & Design

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    VS Code Extension API                     │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │
                    ┌─────────┴──────────┐
                    │                    │
            ┌───────▼────────┐   ┌──────▼──────────┐
            │  Document      │   │   Commands      │
            │  Events        │   │   (Commands)    │
            └────────┬───────┘   └──────┬──────────┘
                     │                  │
                     └──────────┬───────┘
                                │
                    ┌───────────▼────────────┐
                    │   Extension Main      │
                    │   (extension.ts)      │
                    └───────────┬────────────┘
                                │
                ┌───────────────┼──────────────────┐
                │               │                  │
        ┌───────▼────────┐  ┌───▼────────┐  ┌────▼──────┐
        │  Analyzer      │  │Diagnostics │  │  Config   │
        │  (analyzer.ts) │  │  Manager   │  │  Manager  │
        │                │  │(diagnostic │  │(config    │
        │- Rules         │  │ Manager.ts)│  │Manager.ts)│
        │- Patterns      │  │            │  │           │
        │- Matching      │  │- Create    │  │- Load     │
        │- Detection     │  │- Publish   │  │- Save     │
        └────────────────┘  │- Display   │  │- Listen   │
                            └────────────┘  └───────────┘
```

## Data Flow

### 1. Document Change Detection
```
User types code
         │
         ▼
onDidChangeTextDocument event fires
         │
         ▼
Check if document should be analyzed (language, scheme)
         │
         ▼
Debounce timer starts (1 second)
         │
         ▼
After timeout: checkDocument() called
```

### 2. Security Analysis
```
Document text → Analyzer
         │
         ▼
Split into lines
         │
         ▼
For each line:
  For each rule:
    For each pattern:
      Match against line
         │
         ▼
Collect all matches → SecurityIssue[]
```

### 3. Diagnostic Display
```
SecurityIssue[]
         │
         ▼
DiagnosticsManager.createDiagnostics()
         │
         ▼
Convert to VS Code Diagnostic objects
         │
         ▼
Map severity levels
         │
         ▼
Attach suggestions
         │
         ▼
publishDiagnostics() to VS Code
         │
         ▼
Display as red/yellow squiggles
```

## Component Details

### extension.ts (Main Controller)
**Responsibilities:**
- Extension lifecycle (activate/deactivate)
- Event registration and handling
- Command registration
- Orchestrating components

**Key Functions:**
- `activate()` - Extension entry point
- `registerCommands()` - Register VS Code commands
- `registerDocumentListeners()` - Set up event handlers
- `checkDocument()` - Trigger analysis on a document
- `runWorkspaceCheck()` - Batch analyze all files

### analyzer.ts (Security Logic)
**Responsibilities:**
- Define security rules
- Pattern matching
- Issue detection
- Rule management

**Key Functions:**
- `analyzeDocument()` - Main analysis function
- `findMatches()` - Find pattern matches in text
- `initializeRules()` - Initialize all 16 security rules

**Security Rules:**
16 built-in rules covering:
- Injection attacks (SQL, Command)
- Cryptography weaknesses
- Authentication/Authorization
- Sensitive data exposure
- Dangerous functions
- Configuration issues

### diagnosticsManager.ts (VS Code Integration)
**Responsibilities:**
- Create VS Code Diagnostic objects
- Manage diagnostic collection
- Handle severity mapping
- Attach suggestions to issues

**Key Functions:**
- `createDiagnostic()` - Convert issue to Diagnostic
- `publishDiagnostics()` - Send to VS Code
- `clearDiagnostics()` - Remove diagnostics
- `getSummary()` - Get issue statistics

### configManager.ts (Configuration)
**Responsibilities:**
- Read user settings
- Manage configuration changes
- Provide defaults
- Handle language preferences

**Key Functions:**
- `getAutoCheck()` - Check if auto-check enabled
- `getCheckOnSave()` - Check if check-on-save enabled
- `getEnabledLanguages()` - Get supported languages list
- `resetToDefaults()` - Reset all settings

### types.ts (Type Definitions)
**Provides:**
- `SecuritySeverity` enum
- `SecurityRule` interface
- `SecurityIssue` interface
- Type safety throughout codebase

## Security Rule Structure

```typescript
{
  code: 'SEC001',                              // Unique identifier
  message: 'Potential SQL Injection...',       // User-facing message
  severity: SecuritySeverity.Error,            // Error/Warning/Info
  patterns: [                                  // Detection patterns
    /query\s*\(\s*["'`].*\$\{.*\}.*["'`]/i,
    /SELECT.*FROM.*WHERE.*\+/i,
  ],
  suggestion: 'Use parameterized queries...'   // Fix suggestion
}
```

## Configuration Schema

```json
{
  "securityChecker.autoCheck": boolean,
  "securityChecker.checkOnSave": boolean,
  "securityChecker.severity": "error" | "warning" | "info",
  "securityChecker.enabledLanguages": string[]
}
```

## Event Flow Diagram

```
┌─────────────────────────┐
│  User Opens File        │
└────────────┬────────────┘
             │
             ▼
┌──────────────────────────┐
│ onDidOpenTextDocument    │
│ Event Fired              │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ shouldCheckDocument()?   │
│ - Check language         │
│ - Check scheme           │
└────────────┬─────────────┘
             │
      ┌──────┴──────┐
      │             │
   YES│             │NO
      │             └──→ Skip
      ▼
┌──────────────────────────┐
│ checkDocument()          │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ analyzer.analyze()       │
│ Returns SecurityIssue[]  │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ diagnosticsManager       │
│ .publishDiagnostics()    │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ Red/Yellow Squiggles     │
│ in VS Code Editor        │
└──────────────────────────┘
```

## Document Change Debouncing

```
User typing... typing... typing...
     │         │         │
     ▼         ▼         ▼
  Timer      Timer      Timer
  Reset      Reset      Reset
     │         │         │
     └─────────┴─────────┘
                │
         (1 second passes,
          no more changes)
                │
                ▼
         Analysis runs
```

Prevents excessive analysis during active typing, improving performance.

## Error Handling

### In analyzer.ts
```typescript
try {
  const issues = await analyzer.analyzeDocument(document);
  // Process issues
} catch (error) {
  console.error('Error during security check:', error);
  // Gracefully handle errors
}
```

### In extension.ts
```typescript
if (!editor) {
  vscode.window.showWarningMessage('No active editor found');
  return;
}
```

## Performance Considerations

1. **Debouncing**: 1-second delay prevents lag during typing
2. **Language Filtering**: Only analyze supported languages
3. **Lazy Initialization**: Rules created once at startup
4. **Regex Compilation**: Patterns compiled once
5. **Early Exit**: Skip untitled and non-file documents

## Extensibility Points

### Add New Rules
Edit `src/analyzer.ts` initializeRules():
```typescript
{
  code: 'SEC017',
  message: 'New security issue',
  severity: SecuritySeverity.Warning,
  patterns: [/pattern/i],
  suggestion: 'How to fix',
}
```

### Add Code Actions
Create `src/codeActions.ts` implementing CodeActionProvider

### Add Custom Rules
Create `src/customRules.ts` to load external rule definitions

### Integrate External Tools
- Call eslint-plugin-security
- Integrate bandit for Python
- Add snyk API integration

## File Size & Performance

- `analyzer.ts`: ~800 lines (16 rules)
- `extension.ts`: ~200 lines (main logic)
- `diagnosticsManager.ts`: ~100 lines
- `configManager.ts`: ~90 lines
- **Total**: ~1200 lines of TypeScript

**Memory usage**: ~5-10 MB
**Analysis time**: ~50-200ms per file (language dependent)

## Testing Strategy

### Unit Tests (Future)
- Test each rule individually
- Test pattern matching
- Test config management

### Integration Tests
- Test with actual VS Code
- Test with multiple file types
- Test workspace-wide analysis

### Performance Tests
- Measure analysis time
- Monitor memory usage
- Test with large files

---

This architecture ensures **modularity**, **maintainability**, and **extensibility** while keeping the codebase clean and focused on security analysis.
