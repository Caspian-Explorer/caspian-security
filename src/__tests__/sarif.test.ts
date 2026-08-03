/**
 * Tests for the shared SARIF 2.1.0 writer (src/sarif.ts) — consumed by
 * both the CLI (CI / GitHub code scanning) and the extension's export.
 */

import { buildSARIF, resolveToolVersion } from '../sarif';
import { SecuritySeverity, SecurityCategory } from '../types';

function issue(overrides: Partial<{
  line: number; column: number; severity: SecuritySeverity; code: string;
}> = {}) {
  return {
    line: overrides.line ?? 4,
    column: overrides.column ?? 2,
    message: 'SQL injection risk',
    severity: overrides.severity ?? SecuritySeverity.Error,
    suggestion: 'Use parameterized queries',
    code: overrides.code ?? 'DB001',
    pattern: 'query(',
    category: SecurityCategory.DatabaseSecurity,
  };
}

describe('buildSARIF', () => {
  const files = [
    { relativePath: 'src\\a.js', issues: [issue(), issue({ code: 'XSS001', severity: SecuritySeverity.Warning })] },
    { relativePath: 'src/b.js', issues: [issue({ severity: SecuritySeverity.Info, code: 'API001' }), issue()] },
  ];
  const sarif = JSON.parse(buildSARIF(files, '1.2.3'));
  const run = sarif.runs[0];

  it('emits required top-level SARIF 2.1.0 structure', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(run.tool.driver.name).toBe('Caspian Security');
    expect(run.tool.driver.version).toBe('1.2.3');
  });

  it('deduplicates rules and keeps ruleIndex consistent', () => {
    const ruleIds = run.tool.driver.rules.map((r: { id: string }) => r.id);
    expect(new Set(ruleIds).size).toBe(ruleIds.length);
    expect(ruleIds).toEqual(expect.arrayContaining(['DB001', 'XSS001', 'API001']));
    for (const result of run.results) {
      expect(ruleIds[result.ruleIndex]).toBe(result.ruleId);
    }
  });

  it('maps severities to SARIF levels', () => {
    const levels = run.results.map((r: { ruleId: string; level: string }) => [r.ruleId, r.level]);
    expect(levels).toContainEqual(['DB001', 'error']);
    expect(levels).toContainEqual(['XSS001', 'warning']);
    expect(levels).toContainEqual(['API001', 'note']);
  });

  it('uses 1-based line/column and forward-slash URIs', () => {
    const first = run.results[0];
    expect(first.locations[0].physicalLocation.region.startLine).toBe(5);
    expect(first.locations[0].physicalLocation.region.startColumn).toBe(3);
    expect(first.locations[0].physicalLocation.artifactLocation.uri).toBe('src/a.js');
  });

  it('produces an empty results array for a clean scan', () => {
    const clean = JSON.parse(buildSARIF([], '1.2.3'));
    expect(clean.runs[0].results).toEqual([]);
    expect(clean.runs[0].tool.driver.rules).toEqual([]);
  });
});

describe('resolveToolVersion', () => {
  it('matches the real package.json version (no more hardcoded stale versions)', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const pkg = require('../../package.json');
    expect(resolveToolVersion()).toBe(pkg.version);
  });
});
