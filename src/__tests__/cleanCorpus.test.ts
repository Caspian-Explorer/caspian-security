/**
 * Clean-corpus false-positive guard.
 *
 * The mirror image of the vulnerable-corpus suite: a set of idiomatic,
 * SECURE fixtures that must produce ZERO Error- or Warning-severity
 * findings. False positives are the #1 reason users abandon a security
 * scanner — without this suite, a rule tightened for detection could
 * silently start flagging safe code and nothing would fail.
 *
 * Info-severity findings (informational "reminder" rules) are allowed:
 * they fire on the mere presence of auth/db/api code, by design.
 *
 * Like the vulnerable corpus, this runs through the REAL shared engine
 * in src/scanRunner.ts.
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from '../rules';
import { SecuritySeverity, SEVERITY_LABELS } from '../types';
import { scanFile } from '../scanRunner';

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'clean-corpus');
const rules = getAllRules();

const FIXTURES = [
  'express-controller.js',
  'service.py',
  'main.tf',
  'pod.yaml',
  'Dockerfile',
];

describe('clean-corpus false-positive guard', () => {
  it.each(FIXTURES)('%s produces no Error/Warning findings', (fixture) => {
    const filePath = path.join(FIXTURE_DIR, fixture);
    const text = fs.readFileSync(filePath, 'utf-8');
    const issues = scanFile(filePath, text, rules);
    const loud = issues.filter(i => i.severity >= SecuritySeverity.Warning);

    // Build a readable failure message listing exactly what fired.
    const report = loud
      .map(i => `  ${i.code} [${SEVERITY_LABELS[i.severity]}] line ${i.line + 1}: ${i.pattern}`)
      .join('\n');
    expect(loud.length === 0 ? '' : `Unexpected findings in ${fixture}:\n${report}`).toBe('');
  });
});
