/**
 * False-positive tuning regression suite.
 *
 * Every case here was a real false positive found by running Caspian
 * against its own source (surfaced as code-scanning alerts on PR #121).
 * They fall into three classes that need three different fixes — this
 * suite pins all three so they can't regress.
 */

import { getAllRules } from '../rules';
import { scanFile } from '../scanRunner';
import { RuleType } from '../types';

const rules = getAllRules();
const codesFor = (text: string, file = '/repo/src/app.ts') =>
  new Set(scanFile(file, text, rules, { runTaint: false }).map(i => i.code));

describe('comment suppression (skipComments)', () => {
  it('is applied to Informational rules by default', () => {
    const informational = rules.filter(r => r.ruleType === RuleType.Informational);
    const withSuppression = informational.filter(r => r.skipComments || r.contextAware);
    expect(withSuppression.length).toBeGreaterThan(informational.length * 0.8);
  });

  it('is NEVER applied to provider-token rules — a secret in a comment is still leaked', () => {
    for (const rule of rules.filter(r => r.code.startsWith('TOKEN'))) {
      expect(rule.skipComments).toBeFalsy();
    }
  });

  it('still detects a secret pasted into a comment', () => {
    const token = ['xoxb', '123456789012', '123456789012', '123456789012',
      ['AbCdEfGh', 'IjKlMnOp', 'QrStUvWx'].join('')].join('-');
    const found = codesFor(`// old token was ${token}\n`, '/repo/src/a.js');
    expect([...found].some(c => c.startsWith('TOKEN'))).toBe(true);
  });

  it('does not flag behavioural rules on commented-out code', () => {
    // These exact lines (from Caspian's own comments) produced alerts.
    expect(codesFor('// e.g. `res.json(token)` would leak it\n')).not.toContain('HDR005');
    expect(codesFor('// `const id = Number.parseInt(req.params.id, 10)`\n')).not.toContain('API010');
  });

  it('still flags the same constructs in real (uncommented) code', () => {
    expect(codesFor('res.json({ token: accessToken });\n')).toContain('HDR005');
    expect(codesFor('const row = db.find(req.params.id);\n')).toContain('API010');
  });

  it('leaves string literals matchable — skipComments is not contextAware', () => {
    // DEP001 must match a version string inside package.json.
    expect(codesFor('  "left-pad": "^1.2.3"\n', '/repo/package.json')).toContain('DEP001');
  });
});

describe('manifest-only gating (DEP001 / DEP002)', () => {
  it('fires on a real package.json', () => {
    const manifest = '{\n  "dependencies": {\n    "left-pad": "^1.2.3"\n  }\n}\n';
    const found = codesFor(manifest, '/repo/package.json');
    expect(found).toContain('DEP001');
    expect(found).toContain('DEP002');
  });

  it('does not fire on ordinary source code', () => {
    const src = "const os = require('os');\nif (ch === '*') { out += '.*'; }\n";
    const found = codesFor(src, '/repo/src/globber.ts');
    expect(found).not.toContain('DEP001');
    expect(found).not.toContain('DEP002');
  });
});

describe('LOG009 no longer matches the `export` keyword', () => {
  it('ignores ordinary TypeScript exports', () => {
    expect(codesFor('export interface ScanWorkerData { files: string[] }\n')).not.toContain('LOG009');
    expect(codesFor('export function scanFileBatch(data: Batch): Result {\n')).not.toContain('LOG009');
  });

  it('still flags genuine data-export operations', () => {
    expect(codesFor('function exportData() { return rows; }\n')).toContain('LOG009');
    expect(codesFor("app.get('/api/export', handler);\n")).toContain('LOG009');
  });
});

describe('CRED007 matches .env as a filename, not a property access', () => {
  it.each([
    'const k = process.env.API_KEY;',
    'await vscode.env.clipboard.writeText(x);',
    'const e = os.environ;',
  ])('ignores property access: %s', (line) => {
    expect(codesFor(line + '\n')).not.toContain('CRED007');
  });

  it.each([
    "require('dotenv').config({ path: '.env' });",
    "fs.readFileSync('.env.local')",
  ])('still flags a real .env reference: %s', (line) => {
    expect(codesFor(line + '\n')).toContain('CRED007');
  });
});
