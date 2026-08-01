/**
 * Tests for the shared scan engine (src/scanRunner.ts) — the single
 * implementation behind the CLI, the MCP server, and the extension's
 * analyzer. These are the first tests to exercise the engine itself
 * rather than a re-implementation of it.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  walkFiles,
  resolveLanguage,
  scanFile,
  runWorkspaceScan,
  buildIncludeMatcher,
  pickBestInformationalCandidate,
  AdvisorySink,
} from '../scanRunner';
import { getAllRules } from '../rules';
import { RuleType, SecuritySeverity } from '../types';

const rules = getAllRules();

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-scanrunner-'));
}

function rmrf(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('resolveLanguage', () => {
  it.each([
    ['app.js', 'javascript'],
    ['app.jsx', 'javascriptreact'],
    ['app.ts', 'typescript'],
    ['app.mts', 'typescript'],
    ['app.cts', 'typescript'],
    ['app.tsx', 'typescriptreact'],
    ['main.py', 'python'],
    ['Main.java', 'java'],
    ['app.kt', 'kotlin'],
    ['deploy.yaml', 'yaml'],
    ['deploy.yml', 'yaml'],
    ['main.tf', 'terraform'],
    ['vars.tfvars', 'terraform'],
    ['Dockerfile', 'dockerfile'],
    ['Containerfile', 'dockerfile'],
  ])('%s -> %s', (file, lang) => {
    expect(resolveLanguage(path.join('/tmp/x', file))).toBe(lang);
  });

  it('falls back to the raw extension for unknown types', () => {
    expect(resolveLanguage('/x/readme.txt')).toBe('txt');
  });
});

describe('buildIncludeMatcher', () => {
  it('treats plain tokens as substrings (historical behaviour)', () => {
    const m = buildIncludeMatcher(['special-dir']);
    expect(m('/repo/special-dir/file.xyz')).toBe(true);
    expect(m('/repo/other/file.xyz')).toBe(false);
  });

  it('matches *.ext globs against the basename at any depth', () => {
    const m = buildIncludeMatcher(['*.proto']);
    expect(m('/repo/deep/nested/schema.proto')).toBe(true);
    expect(m('/repo/schema.proto.bak')).toBe(false);
  });

  it('matches path globs with ** across separators', () => {
    const m = buildIncludeMatcher(['**/src/**/*.vue']);
    expect(m('repo/src/components/App.vue')).toBe(true);
    expect(m('repo/lib/App.vue')).toBe(false);
  });

  it('normalises Windows separators before matching', () => {
    const m = buildIncludeMatcher(['*.proto']);
    expect(m('repo\\deep\\schema.proto')).toBe(true);
  });
});

describe('walkFiles', () => {
  let dir: string;

  beforeAll(() => {
    dir = makeTempDir();
    fs.mkdirSync(path.join(dir, 'src'));
    fs.mkdirSync(path.join(dir, 'node_modules', 'dep'), { recursive: true });
    fs.mkdirSync(path.join(dir, '.venv', 'lib'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'src', 'app.js'), 'const x = 1;\n');
    fs.writeFileSync(path.join(dir, 'src', 'main.tf'), 'resource "x" "y" {}\n');
    fs.writeFileSync(path.join(dir, 'Dockerfile'), 'FROM node:20\n');
    fs.writeFileSync(path.join(dir, 'README.md'), '# readme\n');
    fs.writeFileSync(path.join(dir, 'schema.proto'), 'message M {}\n');
    fs.writeFileSync(path.join(dir, 'node_modules', 'dep', 'index.js'), 'x\n');
    fs.writeFileSync(path.join(dir, '.venv', 'lib', 'mod.py'), 'x = 1\n');
  });

  afterAll(() => rmrf(dir));

  it('finds supported extensions, Dockerfiles, and skips excluded dirs', () => {
    const found = walkFiles(dir).map(f => path.relative(dir, f)).sort();
    expect(found).toContain(path.join('src', 'app.js'));
    expect(found).toContain(path.join('src', 'main.tf'));
    expect(found).toContain('Dockerfile');
    expect(found).not.toContain('README.md');
    expect(found.some(f => f.startsWith('node_modules'))).toBe(false);
    expect(found.some(f => f.startsWith('.venv'))).toBe(false);
  });

  it('honours extra excludes', () => {
    const found = walkFiles(dir, ['src']).map(f => path.relative(dir, f));
    expect(found.some(f => f.startsWith('src'))).toBe(false);
  });

  it('honours glob includes for otherwise-unsupported files', () => {
    const found = walkFiles(dir, [], ['*.proto']).map(f => path.relative(dir, f));
    expect(found).toContain('schema.proto');
  });
});

describe('scanFile', () => {
  it('flags an obvious hardcoded credential', () => {
    const issues = scanFile('/x/app.js', 'const password = "hunter2secret";\n', rules);
    expect(issues.some(i => i.code.startsWith('CRED'))).toBe(true);
  });

  it('attaches a confidence level via the default classifier', () => {
    const issues = scanFile('/x/app.js', 'const password = "hunter2secret";\n', rules);
    const cred = issues.find(i => i.code.startsWith('CRED'));
    expect(cred?.confidenceLevel).toBeDefined();
  });

  it('uses a custom classifier when provided', () => {
    const issues = scanFile('/x/app.js', 'const password = "hunter2secret";\n', rules, {
      classify: () => 'safe',
      runTaint: false,
    });
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.every(i => i.confidenceLevel === 'safe')).toBe(true);
  });

  it('drops matches vetoed by the isLineSuppressed hook', () => {
    const text = 'const password = "hunter2secret";\n';
    const baseline = scanFile('/x/app.js', text, rules, { runTaint: false });
    expect(baseline.length).toBeGreaterThan(0);
    const suppressed = scanFile('/x/app.js', text, rules, {
      runTaint: false,
      isLineSuppressed: () => true,
    });
    expect(suppressed).toHaveLength(0);
  });

  it('respects contextAware rules inside comments', () => {
    const rule = rules.find(r => r.contextAware && r.patterns.some(p => p instanceof RegExp));
    expect(rule).toBeDefined();
    // A commented-out eval should not fire the context-aware eval rules.
    const issues = scanFile('/x/app.js', '// eval(userInput)\n', rules, { runTaint: false });
    expect(issues.filter(i => i.line === 0 && getRuleType(i.code) === RuleType.CodeDetectable && isContextAware(i.code))).toHaveLength(0);
  });

  it('collects project advisories in the same pass when a sink is given', () => {
    const sink: AdvisorySink = { fired: new Set(), advisories: [] };
    const advisoryRule = rules.find(r => r.ruleType === RuleType.ProjectAdvisory && r.patterns.some(p => typeof p !== 'string'));
    // Build a line that matches SOME advisory rule pattern; use a string-pattern advisory if regex synthesis is impractical.
    const stringAdvisory = rules.find(r => r.ruleType === RuleType.ProjectAdvisory && r.patterns.some(p => typeof p === 'string'));
    const trigger = stringAdvisory
      ? String(stringAdvisory.patterns.find(p => typeof p === 'string'))
      : '';
    if (!trigger && !advisoryRule) { return; }
    const text = `const marker = 1; ${trigger}\n`;
    scanFile('/x/app.js', text, rules, { runTaint: false, advisorySink: sink });
    if (trigger) {
      expect(sink.advisories.length).toBeGreaterThan(0);
      expect(sink.advisories[0].triggeredBy).toBe('/x/app.js');
      // Deduped: scanning a second file must not re-add the same code.
      const countAfterFirst = sink.advisories.length;
      scanFile('/x/other.js', text, rules, { runTaint: false, advisorySink: sink });
      expect(sink.advisories.length).toBe(countAfterFirst);
    }
  });

  it('never emits ProjectAdvisory rules as regular issues', () => {
    const advisoryCodes = new Set(rules.filter(r => r.ruleType === RuleType.ProjectAdvisory).map(r => r.code));
    const text = 'const password = "hunter2secret";\neval(userInput);\n';
    const issues = scanFile('/x/app.js', text, rules);
    expect(issues.filter(i => advisoryCodes.has(i.code))).toHaveLength(0);
  });

  it('skips lines longer than 2000 characters', () => {
    const longLine = `const password = "hunter2secret"; ${'x'.repeat(2100)}`;
    const issues = scanFile('/x/app.js', longLine + '\n', rules, { runTaint: false });
    expect(issues).toHaveLength(0);
  });

  it('emits at most one finding per informational rule per file', () => {
    const text = Array(5).fill('fetch("https://api.example.com/data");').join('\n');
    const issues = scanFile('/x/app.js', text, rules, { runTaint: false });
    const counts = new Map<string, number>();
    for (const i of issues) {
      counts.set(i.code, (counts.get(i.code) || 0) + 1);
    }
    for (const rule of rules) {
      if (rule.ruleType === RuleType.Informational && counts.has(rule.code)) {
        expect(counts.get(rule.code)).toBe(1);
      }
    }
  });
});

describe('pickBestInformationalCandidate', () => {
  it('prefers function-body lines over import lines', () => {
    const lines = [
      "import { api } from 'api';",
      'function handler() {',
      '  api.call().then(r => r);',
      '}',
    ];
    const mk = (line: number) => ({
      line, column: 0, message: 'm', severity: SecuritySeverity.Info,
      suggestion: 's', code: 'X001', pattern: 'p', category: rules[0].category,
    });
    const best = pickBestInformationalCandidate([mk(0), mk(2)], lines);
    expect(best.line).toBe(2);
  });
});

describe('runWorkspaceScan', () => {
  let dir: string;

  beforeAll(() => {
    dir = makeTempDir();
    fs.mkdirSync(path.join(dir, 'src'));
    fs.writeFileSync(
      path.join(dir, 'src', 'insecure.js'),
      'const password = "hunter2secret";\n'
    );
    fs.writeFileSync(path.join(dir, 'src', 'huge.js'), 'x'.repeat(600_000));
  });

  afterAll(() => rmrf(dir));

  it('scans eligible files and reports findings with relative paths', () => {
    const result = runWorkspaceScan({ workspace: dir, runTaint: false });
    expect(result.filesScanned).toBeGreaterThanOrEqual(2);
    const insecure = result.results.find(r => r.relativePath.endsWith('insecure.js'));
    expect(insecure).toBeDefined();
    expect(insecure!.issues.some(i => i.code.startsWith('CRED'))).toBe(true);
    expect(insecure!.languageId).toBe('javascript');
  });

  it('skips files above maxFileSize', () => {
    const result = runWorkspaceScan({ workspace: dir, runTaint: false });
    expect(result.filesSkipped).toBeGreaterThanOrEqual(1);
    expect(result.results.some(r => r.relativePath.endsWith('huge.js'))).toBe(false);
  });
});

// --- helpers ---------------------------------------------------------------

const ruleByCode = new Map(rules.map(r => [r.code, r]));
function getRuleType(code: string): RuleType | undefined {
  return ruleByCode.get(code)?.ruleType;
}
function isContextAware(code: string): boolean {
  return !!ruleByCode.get(code)?.contextAware;
}
