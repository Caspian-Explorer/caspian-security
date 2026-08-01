/**
 * CRLF regression suite.
 *
 * Git on Windows checks files out with CRLF by default, and the scan
 * engine splits on '\n' — which used to leave a trailing '\r' on every
 * line and defeat any rule pattern anchored to end-of-line. The effect
 * was silent: on the vulnerable corpus, Windows lost TAINT001/003/006/007
 * and gained a spurious TAINT008. Caught by the windows-latest CI leg.
 *
 * The guarantee asserted here is strict: a CRLF file must produce exactly
 * the same findings as its LF twin, at the same line AND column.
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from '../rules';
import { scanFile } from '../scanRunner';
import { runTaintAnalysis } from '../taint';
import { normaliseLineEndings, buildLineStates } from '../scanContext';

const rules = getAllRules();
const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'vulnerable-corpus');
const CLEAN_DIR = path.join(__dirname, 'fixtures', 'clean-corpus');

/** Stable identity of a finding set: code + position. */
function fingerprint(filePath: string, text: string): string {
  return scanFile(filePath, text, rules)
    .map(i => `${i.code}@${i.line}:${i.column}`)
    .sort()
    .join(',');
}

function toCRLF(text: string): string {
  return text.replace(/\n/g, '\r\n');
}

describe('normaliseLineEndings', () => {
  it('rewrites CRLF to LF', () => {
    expect(normaliseLineEndings('a\r\nb\r\n')).toBe('a\nb\n');
  });

  it('leaves LF-only text untouched (identity, no copy needed)', () => {
    const text = 'a\nb\n';
    expect(normaliseLineEndings(text)).toBe(text);
  });

  it('preserves the line count exactly', () => {
    const crlf = 'a\r\nb\r\nc';
    expect(normaliseLineEndings(crlf).split('\n')).toHaveLength(3);
  });

  it('does NOT rewrite a lone CR — that would shift every later line number', () => {
    // A stray carriage return inside a line must not become a line break.
    expect(normaliseLineEndings('a\rb')).toBe('a\rb');
  });
});

describe('buildLineStates is CRLF-safe', () => {
  it('produces the same states for CRLF and LF input', () => {
    const lf = 'const s = `multi\nline`;\nconst x = 1;\n';
    expect(buildLineStates(toCRLF(lf))).toEqual(buildLineStates(lf));
  });
});

describe('taint analysis is CRLF-safe', () => {
  it('finds the same flows in CRLF and LF source', () => {
    const lf = [
      'app.post("/x", (req, res) => {',
      '  const userInput = req.body.q;',
      '  db.query("SELECT * FROM t WHERE a = " + userInput);',
      '});',
    ].join('\n');
    const key = (t: string) => runTaintAnalysis(t).map(i => `${i.code}@${i.line}`).sort().join(',');
    expect(key(lf).length).toBeGreaterThan(0);
    expect(key(toCRLF(lf))).toEqual(key(lf));
  });
});

describe('whole-corpus CRLF equivalence', () => {
  const fixtures = [
    ...fs.readdirSync(FIXTURE_DIR).map(f => path.join(FIXTURE_DIR, f)),
    ...fs.readdirSync(CLEAN_DIR).map(f => path.join(CLEAN_DIR, f)),
  ];

  it.each(fixtures.map(f => [path.basename(f), f]))(
    '%s produces identical findings under CRLF',
    (_name, filePath) => {
      const lf = fs.readFileSync(filePath, 'utf-8');
      expect(fingerprint(filePath, toCRLF(lf))).toBe(fingerprint(filePath, lf));
    }
  );

  it('the vulnerable corpus really does produce findings (guards a vacuous pass)', () => {
    const target = path.join(FIXTURE_DIR, 'express-controller.js');
    expect(fingerprint(target, fs.readFileSync(target, 'utf-8')).length).toBeGreaterThan(0);
  });
});
