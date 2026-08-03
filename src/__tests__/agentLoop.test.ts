import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { SecuritySeverity, SecurityCategory, SecurityIssue } from '../types';
import {
  deriveLoopSeverity,
  worstLoopSeverity,
  blocksLoop,
  toLoopFindings,
  formatLoopReport,
  LoopFinding,
} from '../agentLoop/severity';
import { DEFAULT_FILE_CONFIG, loadFileConfig, isPathIgnored, CONFIG_FILENAME } from '../fileConfig';
import { getWorkingTreeChanges } from '../gitWorkingTree';
import { createLoopScanContext, isScannablePath, scanFileForLoop } from '../agentLoop/scanForLoop';
import { DEFAULT_BASELINE_PATH, buildBaseline, writeBaseline } from '../baseline';
import { upsertRulesBlock } from '../cli/init';
import { CASPIAN_MARKER_START, CASPIAN_MARKER_END, buildLoopRulesBlock } from '../integration/agentSnippets';

function makeIssue(overrides: Partial<SecurityIssue> = {}): SecurityIssue {
  return {
    line: 0,
    column: 0,
    message: 'm',
    severity: SecuritySeverity.Error,
    suggestion: 's',
    code: 'X001',
    pattern: 'p',
    category: SecurityCategory.APISecurity,
    ...overrides,
  };
}

function makeFinding(overrides: Partial<SecurityIssue> = {}): LoopFinding {
  const issue = makeIssue(overrides);
  return { ...issue, relativePath: 'src/a.ts', loopSeverity: deriveLoopSeverity(issue) };
}

let tmpRoot: string;
beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-loop-'));
});
afterEach(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

describe('deriveLoopSeverity', () => {
  it('maps Error + critical confidence to critical', () => {
    expect(deriveLoopSeverity(makeIssue({ confidenceLevel: 'critical' }))).toBe('critical');
  });
  it('maps plain Error to high', () => {
    expect(deriveLoopSeverity(makeIssue({ confidenceLevel: 'verify-needed' }))).toBe('high');
  });
  it('maps Warning to medium and Info to low', () => {
    expect(deriveLoopSeverity(makeIssue({ severity: SecuritySeverity.Warning }))).toBe('medium');
    expect(deriveLoopSeverity(makeIssue({ severity: SecuritySeverity.Info }))).toBe('low');
  });
});

describe('blocksLoop', () => {
  it('critical always blocks, even when blockOn omits it', () => {
    const f = makeFinding({ confidenceLevel: 'critical' });
    expect(blocksLoop(f, { ...DEFAULT_FILE_CONFIG, blockOn: [] })).toBe(true);
  });
  it('high blocks by default but respects blockOn', () => {
    const f = makeFinding({ confidenceLevel: 'verify-needed' });
    expect(blocksLoop(f, DEFAULT_FILE_CONFIG)).toBe(true);
    expect(blocksLoop(f, { ...DEFAULT_FILE_CONFIG, blockOn: ['critical'] })).toBe(false);
  });
  it('medium does not block by default', () => {
    expect(blocksLoop(makeFinding({ severity: SecuritySeverity.Warning }), DEFAULT_FILE_CONFIG)).toBe(false);
  });
});

describe('formatLoopReport', () => {
  it('caps findings and mentions the hidden count', () => {
    const findings = Array.from({ length: 8 }, (_, i) =>
      makeFinding({ code: `X00${i}`, severity: SecuritySeverity.Warning })
    );
    const report = formatLoopReport(findings, 5);
    expect(report).toContain('8 new issues');
    expect(report).toContain('3 lower-severity issues not shown');
  });
  it('sorts worst-first and stays under the size cap', () => {
    const findings = [
      makeFinding({ code: 'MED', severity: SecuritySeverity.Warning }),
      makeFinding({ code: 'CRIT', confidenceLevel: 'critical' }),
    ];
    const report = formatLoopReport(findings, 5);
    expect(report.indexOf('CRIT')).toBeLessThan(report.indexOf('MED'));
    expect(report.length).toBeLessThanOrEqual(8000);
  });
  it('uses 1-based line numbers', () => {
    const report = formatLoopReport([makeFinding({ line: 11 })], 5);
    expect(report).toContain('line 12');
  });
});

describe('fileConfig', () => {
  it('returns defaults when the file is missing or malformed', () => {
    expect(loadFileConfig(tmpRoot)).toEqual(DEFAULT_FILE_CONFIG);
    fs.writeFileSync(path.join(tmpRoot, CONFIG_FILENAME), 'not json');
    expect(loadFileConfig(tmpRoot)).toEqual(DEFAULT_FILE_CONFIG);
  });
  it('merges valid fields and drops invalid ones', () => {
    fs.writeFileSync(
      path.join(tmpRoot, CONFIG_FILENAME),
      JSON.stringify({ blockOn: ['critical', 'bogus'], maxFindingsInLoop: 3, ignoreRules: ['API001'] })
    );
    const cfg = loadFileConfig(tmpRoot);
    expect(cfg.blockOn).toEqual(['critical']);
    expect(cfg.maxFindingsInLoop).toBe(3);
    expect(cfg.ignoreRules).toEqual(['API001']);
    expect(cfg.ignorePaths).toEqual(DEFAULT_FILE_CONFIG.ignorePaths);
  });
  it('isPathIgnored handles substrings and globs', () => {
    expect(isPathIgnored('a/node_modules/b.ts', ['**/node_modules/**'])).toBe(true);
    expect(isPathIgnored('src/x.test.ts', ['**/*.test.*'])).toBe(true);
    expect(isPathIgnored('src/x.ts', DEFAULT_FILE_CONFIG.ignorePaths)).toBe(false);
    expect(isPathIgnored('src/legacy/x.ts', ['legacy'])).toBe(true);
  });
});

describe('getWorkingTreeChanges', () => {
  function git(cwd: string, ...args: string[]): void {
    execFileSync('git', ['-C', cwd, ...args], { stdio: 'ignore' });
  }

  it('reports modified tracked files and untracked files', () => {
    git(tmpRoot, 'init');
    git(tmpRoot, 'config', 'user.email', 'test@test.invalid');
    git(tmpRoot, 'config', 'user.name', 'test');
    fs.writeFileSync(path.join(tmpRoot, 'a.ts'), 'const a = 1;\n');
    git(tmpRoot, 'add', '.');
    git(tmpRoot, 'commit', '-m', 'init');

    fs.writeFileSync(path.join(tmpRoot, 'a.ts'), 'const a = 2;\n');
    fs.writeFileSync(path.join(tmpRoot, 'b.ts'), 'const b = 1;\n');

    const changes = getWorkingTreeChanges(tmpRoot);
    const rel = [...changes.files].map(f => path.basename(f)).sort();
    expect(rel).toEqual(['a.ts', 'b.ts']);
  });

  it('throws outside a git repository', () => {
    expect(() => getWorkingTreeChanges(tmpRoot)).toThrow();
  });
});

describe('scanFileForLoop', () => {
  it('reports a finding in a fresh file and suppresses it once baselined', () => {
    const file = path.join(tmpRoot, 'firestore.rules');
    fs.writeFileSync(file, 'allow read, write: if true;\n');

    let findings = scanFileForLoop(file, createLoopScanContext(tmpRoot));
    expect(findings.map(f => f.code)).toContain('DEPLOY001');
    expect(findings[0].loopSeverity).toBe('critical');

    const baselinePath = path.join(tmpRoot, DEFAULT_BASELINE_PATH);
    fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
    writeBaseline(
      baselinePath,
      buildBaseline(findings.map(f => ({ ...f, filePath: f.relativePath })), 'test')
    );

    findings = scanFileForLoop(file, createLoopScanContext(tmpRoot));
    expect(findings).toEqual([]);
  });

  it('honours .caspianignore and config ignoreRules', () => {
    const file = path.join(tmpRoot, 'firestore.rules');
    fs.writeFileSync(file, 'allow read, write: if true;\n');
    fs.writeFileSync(path.join(tmpRoot, '.caspianignore'), 'DEPLOY001 firestore.rules\n');
    expect(scanFileForLoop(file, createLoopScanContext(tmpRoot))).toEqual([]);

    fs.rmSync(path.join(tmpRoot, '.caspianignore'));
    fs.writeFileSync(path.join(tmpRoot, CONFIG_FILENAME), JSON.stringify({ ignoreRules: ['DEPLOY001'] }));
    expect(scanFileForLoop(file, createLoopScanContext(tmpRoot))).toEqual([]);
  });

  it('isScannablePath rejects unknown extensions and ignored paths', () => {
    const ctx = createLoopScanContext(tmpRoot);
    expect(isScannablePath(path.join(tmpRoot, 'a.md'), ctx)).toBe(false);
    expect(isScannablePath(path.join(tmpRoot, 'node_modules', 'x', 'a.ts'), ctx)).toBe(false);
    expect(isScannablePath(path.join(tmpRoot, 'src.test', '..', 'a.ts'), ctx)).toBe(true);
    expect(isScannablePath(path.join(tmpRoot, 'a.test.ts'), ctx)).toBe(false);
  });
});

describe('caspian init helpers', () => {
  it('upsertRulesBlock appends once and replaces on re-run', () => {
    const file = path.join(tmpRoot, 'CLAUDE.md');
    fs.writeFileSync(file, '# Project\n');
    const block = buildLoopRulesBlock('claude');

    expect(upsertRulesBlock(file, block)).toBe(true);
    const first = fs.readFileSync(file, 'utf-8');
    expect(first.startsWith('# Project\n')).toBe(true);
    expect(first.match(new RegExp(CASPIAN_MARKER_START, 'g'))!.length).toBe(1);

    // Re-run with identical content: no change.
    expect(upsertRulesBlock(file, block)).toBe(false);

    // Re-run with new content: replaced in place, not duplicated.
    expect(upsertRulesBlock(file, `${CASPIAN_MARKER_START}\nnew\n${CASPIAN_MARKER_END}`)).toBe(true);
    const second = fs.readFileSync(file, 'utf-8');
    expect(second.match(new RegExp(CASPIAN_MARKER_START, 'g'))!.length).toBe(1);
    expect(second).toContain('new');
    expect(second).not.toContain('security_scan_file');
  });

  it('buildLoopRulesBlock names the three MCP tools and the cursor preamble', () => {
    const claude = buildLoopRulesBlock('claude');
    expect(claude).toContain('security_scan_file');
    expect(claude).toContain('security_scan_changes');
    expect(claude).toContain('check_deployment_security');
    expect(claude).not.toContain('optional extra step');
    expect(buildLoopRulesBlock('cursor')).toContain('optional extra step');
  });
});

describe('toLoopFindings / worstLoopSeverity', () => {
  it('attaches severity and normalises paths', () => {
    const findings = toLoopFindings([makeIssue()], 'src\\win\\a.ts');
    expect(findings[0].relativePath).toBe('src/win/a.ts');
    expect(worstLoopSeverity(findings)).toBe('high');
    expect(worstLoopSeverity([])).toBeNull();
  });
});
