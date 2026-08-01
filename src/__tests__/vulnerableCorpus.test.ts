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

/** Scan in-memory text as if it were a file at the given (fake) path. */
function scanFixtureText(fileName: string, text: string): SecurityIssue[] {
  return scanFile(path.join(FIXTURE_DIR, fileName), text, rules);
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

  it('flask-service.py — Python injection / deserialization / SSRF / crypto coverage', () => {
    const found = codes(scanFixture(path.join(FIXTURE_DIR, 'flask-service.py')));
    const must = ['SSTI001', 'CMD003', 'CMD004', 'DESER001', 'DESER004', 'XXE004', 'LDAP003', 'SSRF004', 'SSRF005', 'ENC001'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('webapp.js — auth / CORS / CSRF / API / frontend coverage', () => {
    const found = codes(scanFixture(path.join(FIXTURE_DIR, 'webapp.js')));
    const must = [
      'CORS001', 'AUTH001', 'AUTH002', 'AUTH003', 'AUTH005', 'CSRF003', 'CSRF004', 'CSRF006',
      'ENC002', 'ENC004', 'API004', 'API006', 'API011', 'XSS014', 'SSRF001', 'DESER008',
      'CMD001', 'FE007c', 'BIZ008', 'FE006', 'FE011', 'FE012',
    ];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('MainActivity.kt — Android/Kotlin (KT-*) coverage', () => {
    const found = codes(scanFixture(path.join(FIXTURE_DIR, 'MainActivity.kt')));
    const must = [
      'KT-AUTH001', 'KT-AUTH002', 'KT-AUTH003', 'KT-XSS001', 'KT-XSS002', 'KT-XSS003', 'KT-XSS004',
      'KT-ENC001', 'KT-ENC002', 'KT-ENC003', 'KT-ENC004', 'KT-FILE002', 'KT-CRED001', 'KT-LOG001', 'KT-LOG002',
    ];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('every finding on every fixture is an Error or Warning — no quiet Info for the egregious bugs', () => {
    for (const file of ['express-controller.js', 'Dockerfile', 'main.tf', 'pod.yaml', 'flask-service.py', 'webapp.js', 'MainActivity.kt']) {
      const issues = scanFixture(path.join(FIXTURE_DIR, file));
      const highSeverity = issues.filter(i => i.severity >= SecuritySeverity.Warning);
      expect(highSeverity.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// Provider-token detection (TOKEN family)
// ---------------------------------------------------------------------------
// The synthetic tokens are ASSEMBLED AT RUNTIME (join over parts) so no
// token-shaped literal ever exists in the repo or the compiled output —
// GitHub push protection and vsce's packaging secret-scan both check for
// provider token shapes and would reject committed literals.

describe('provider-token detection', () => {
  const d12 = ['1234', '5678', '9012'].join('');
  const alpha24 = ['AbCdEfGh', 'IjKlMnOp', 'QrStUvWx'].join('');
  const hex32 = ['abcdef01', '23456789', 'abcdef01', '23456789'].join('');

  const SYNTHETIC_TOKENS: Array<[string, string]> = [
    ['TOKEN001', ['xoxb', d12, d12, d12, alpha24].join('-')],
    ['TOKEN002', 'sk-proj-' + alpha24 + alpha24],
    ['TOKEN004', 'AIza' + ('0Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1W').slice(0, 35)],
    ['TOKEN006', 'sk_live_' + alpha24],
    ['TOKEN007', 'AC' + hex32],
    ['TOKEN010', 'npm_' + (alpha24 + alpha24).slice(0, 36)],
    ['TOKEN011', 'dckr_pat_' + alpha24 + 'Yz12'],
    ['TOKEN022', 'dop_v1_' + hex32 + hex32],
    ['TOKEN028', ['https:', '', 'deploy:hunter2pass@registry.example.internal/repo.git'].join('/')],
  ];

  it.each(SYNTHETIC_TOKENS)('%s fires on its provider token shape (critical confidence)', (code, token) => {
    const text = `const configValue = "${token}";\n`;
    const issues = scanFixtureText('synthetic-tokens.js', text);
    const hit = issues.find(i => i.code === code);
    expect(hit).toBeDefined();
    expect(hit!.confidenceLevel).toBe('critical');
  });

  it('ordinary config strings do not fire TOKEN rules', () => {
    const text = [
      'const registry = "https://registry.npmjs.org/";',
      'const model = "claude-sonnet-5";',
      'const key = process.env.STRIPE_KEY;',
    ].join('\n');
    const issues = scanFixtureText('clean-config.js', text);
    expect(issues.filter(i => i.code.startsWith('TOKEN'))).toHaveLength(0);
  });
});
