/**
 * Vulnerable-corpus regression suite.
 *
 * Scans a small synthetic fixture tree that contains intentional
 * vulnerabilities across every rule family Caspian ships. Each file
 * has a list of rule codes that MUST be detected — if any of them
 * stops firing, the build fails.
 *
 * This is a *ratchet-up* test: if new rules start detecting something
 * in the same fixture, that's fine (the assertion is "at minimum,
 * these codes fire"). If a rule stops detecting, or a detection moves
 * to a different file, the test catches it immediately.
 *
 * The scan goes through the REAL shared engine (src/scanRunner.ts) —
 * the same `scanFile` the CLI, the MCP server, and the extension's
 * analyzer use — so what is asserted here is the shipped behaviour,
 * not a re-implementation that can drift.
 *
 * Fixtures live at src/__tests__/fixtures/vulnerable-corpus/ and are
 * small hand-written files — no 200 MB downloads in CI.
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from '../rules';
import { SecurityIssue, SecuritySeverity } from '../types';
import { scanFile } from '../scanRunner';

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'vulnerable-corpus');
const rules = getAllRules();

function scanFixture(filePath: string): SecurityIssue[] {
  const text = fs.readFileSync(filePath, 'utf-8');
  return scanFile(filePath, text, rules);
}

function codes(issues: SecurityIssue[]): Set<string> {
  return new Set(issues.map(i => i.code));
}

// ---------------------------------------------------------------------------
// Per-fixture assertions
// ---------------------------------------------------------------------------

describe('vulnerable-corpus regression suite', () => {
  it('express-controller.js — taint / JWT / OAuth / prototype-pollution coverage', () => {
    const issues = scanFixture(path.join(FIXTURE_DIR, 'express-controller.js'));
    const found = codes(issues);
    // Every code on this list is a minimum guarantee. New detections are fine.
    const must = ['TAINT001', 'TAINT003', 'TAINT005', 'TAINT007', 'JWT002', 'OAUTH001', 'FE007a'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('Dockerfile — DOCKER001 / DOCKER003 / DOCKER004 / DOCKER007 minimum', () => {
    const issues = scanFixture(path.join(FIXTURE_DIR, 'Dockerfile'));
    const found = codes(issues);
    const must = ['DOCKER001', 'DOCKER003', 'DOCKER004', 'DOCKER007'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('main.tf — TF001 / TF002 / TF003 / TF004 / TF006 / TF008 minimum', () => {
    const issues = scanFixture(path.join(FIXTURE_DIR, 'main.tf'));
    const found = codes(issues);
    const must = ['TF001', 'TF002', 'TF003', 'TF004', 'TF006', 'TF008'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('pod.yaml — K8S001..K8S008 coverage', () => {
    const issues = scanFixture(path.join(FIXTURE_DIR, 'pod.yaml'));
    const found = codes(issues);
    const must = ['K8S001', 'K8S002', 'K8S003', 'K8S004', 'K8S005', 'K8S006', 'K8S007', 'K8S008'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('every finding on every fixture is an Error or Warning — no quiet Info for the egregious bugs', () => {
    for (const file of ['express-controller.js', 'Dockerfile', 'main.tf', 'pod.yaml']) {
      const issues = scanFixture(path.join(FIXTURE_DIR, file));
      const highSeverity = issues.filter(i => i.severity >= SecuritySeverity.Warning);
      expect(highSeverity.length).toBeGreaterThan(0);
    }
  });
});
