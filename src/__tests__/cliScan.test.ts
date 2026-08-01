/**
 * Tests for the `caspian scan` CLI helpers: argument parsing, severity
 * gating, and output formatting. The self-scan CI workflow's build gate
 * depends on these exact semantics.
 */

import * as os from 'os';
import * as path from 'path';
import {
  parseArgs,
  worstSeverity,
  meetsFailThreshold,
  toJSONOutput,
  toText,
} from '../cli/scan';
import { FileResult } from '../scanRunner';
import { SecuritySeverity, SecurityCategory } from '../types';

function issue(severity: SecuritySeverity, code = 'DB001'): FileResult['issues'][number] {
  return {
    line: 0, column: 0, message: 'msg', severity, suggestion: 'fix it',
    code, pattern: 'p', category: SecurityCategory.DatabaseSecurity,
  };
}

function fileResult(...severities: SecuritySeverity[]): FileResult {
  return {
    filePath: '/w/a.js', relativePath: 'a.js', languageId: 'javascript',
    issues: severities.map(s => issue(s)),
  };
}

describe('parseArgs', () => {
  const cwd = os.tmpdir();

  it('applies defaults', () => {
    const opts = parseArgs([cwd]);
    expect(opts.workspace).toBe(path.resolve(cwd));
    expect(opts.format).toBe('sarif');
    expect(opts.failOn).toBe('error');
    expect(opts.maxFileSize).toBe(500_000);
    expect(opts.include).toEqual([]);
    expect(opts.exclude).toEqual([]);
    expect(opts.updateBaseline).toBe(false);
  });

  it('parses format, fail-on, output, and sizes', () => {
    const opts = parseArgs([
      cwd, '--format', 'json', '--fail-on', 'warning',
      '--output', 'out.json', '--max-file-size', '1234',
    ]);
    expect(opts.format).toBe('json');
    expect(opts.failOn).toBe('warning');
    expect(opts.output).toBe('out.json');
    expect(opts.maxFileSize).toBe(1234);
  });

  it('splits comma-separated include/exclude lists', () => {
    const opts = parseArgs([cwd, '--include', '*.proto, src/**', '--exclude', 'gen,tmp']);
    expect(opts.include).toEqual(['*.proto', 'src/**']);
    expect(opts.exclude).toEqual(['gen', 'tmp']);
  });

  it('parses baseline and changed-since flags', () => {
    const opts = parseArgs([cwd, '--baseline', 'b.json', '--update-baseline', '--changed-since', 'origin/main']);
    expect(opts.baselinePath).toBe('b.json');
    expect(opts.updateBaseline).toBe(true);
    expect(opts.changedSince).toBe('origin/main');
  });

  it.each([
    [['--format', 'xml']],
    [['--fail-on', 'sometimes']],
    [['--unknown-flag']],
    [['--output']],
  ])('rejects invalid arguments %j', (argv) => {
    expect(() => parseArgs([cwd, ...argv])).toThrow();
  });

  it('rejects a second positional path', () => {
    expect(() => parseArgs([cwd, cwd])).toThrow(/only one positional/);
  });

  it('rejects a nonexistent workspace', () => {
    expect(() => parseArgs(['/definitely/not/a/real/path'])).toThrow(/does not exist/);
  });
});

describe('worstSeverity', () => {
  it('returns null with no findings', () => {
    expect(worstSeverity([])).toBeNull();
    expect(worstSeverity([fileResult()])).toBeNull();
  });

  it('returns the highest severity across all files', () => {
    const results = [fileResult(SecuritySeverity.Info), fileResult(SecuritySeverity.Error, SecuritySeverity.Warning)];
    expect(worstSeverity(results)).toBe(SecuritySeverity.Error);
  });
});

describe('meetsFailThreshold', () => {
  it('never fails when failOn=never or there are no findings', () => {
    expect(meetsFailThreshold(SecuritySeverity.Error, 'never')).toBe(false);
    expect(meetsFailThreshold(null, 'error')).toBe(false);
  });

  it.each([
    [SecuritySeverity.Error, 'error', true],
    [SecuritySeverity.Warning, 'error', false],
    [SecuritySeverity.Warning, 'warning', true],
    [SecuritySeverity.Info, 'warning', false],
    [SecuritySeverity.Info, 'info', true],
  ] as const)('worst=%s failOn=%s -> %s', (worst, failOn, expected) => {
    expect(meetsFailThreshold(worst, failOn)).toBe(expected);
  });
});

describe('output formatters', () => {
  it('toJSONOutput emits 1-based lines and severity labels', () => {
    const parsed = JSON.parse(toJSONOutput([fileResult(SecuritySeverity.Error)]));
    expect(parsed.issues).toHaveLength(1);
    expect(parsed.issues[0].line).toBe(1);
    expect(parsed.issues[0].severity).toBe('Error');
    expect(parsed.issues[0].file).toBe('a.js');
  });

  it('toText includes a per-file section and total count', () => {
    const text = toText([fileResult(SecuritySeverity.Warning, SecuritySeverity.Info)]);
    expect(text).toContain('2 finding(s)');
    expect(text).toContain('--- a.js (2 issue(s)) ---');
  });
});
