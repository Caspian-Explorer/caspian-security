import { getAllRules } from '../rules';

/**
 * Defence-in-depth test against catastrophic backtracking in rule patterns.
 *
 * Every `RegExp` pattern on every rule is exercised against a small library
 * of known ReDoS-trigger shapes. No single pattern is permitted to take more
 * than {@link MAX_MS} on any adversarial input — if one does, the regex is
 * almost certainly unsafe and should be rewritten (add non-capturing groups,
 * flatten alternations, anchor the match).
 *
 * The analyzer has a per-file soft deadline, but that is a last-line
 * mitigation. This test catches the root cause at build time.
 */

const MAX_MS = 200;

// Strings shaped to provoke backtracking in patterns that mix `.*` with
// alternation or nested quantifiers. Sized at 2,000 chars — the scanner's
// actual per-line cap — so a polynomial-backtracking pattern that looks
// fine at 200 chars still gets caught before it can blow the per-file
// budget on a real 2,000-char line. A healthy regex finishes in
// microseconds regardless of length.
const LINE_CAP = 2000;
const ADVERSARIAL_INPUTS: string[] = [
  'a'.repeat(LINE_CAP),
  'a'.repeat(LINE_CAP - 1) + '!',
  'ab'.repeat(LINE_CAP / 2),
  'ab'.repeat(LINE_CAP / 2 - 1) + 'x',
  '"' + 'a'.repeat(LINE_CAP - 2) + '\'',
  'x'.repeat(LINE_CAP / 2 - 2) + '${' + 'y'.repeat(LINE_CAP / 2 - 2) + '}',
  '//' + 'a'.repeat(LINE_CAP - 2),
  '(' + 'a'.repeat(LINE_CAP - 2) + ')',
  'http://' + 'a'.repeat(LINE_CAP - 10) + '/',
  'SELECT ' + 'x'.repeat(LINE_CAP / 2) + " WHERE id='" + 'y'.repeat(LINE_CAP / 2 - 20),
  // Mixed shapes that defeat single-char scans in patterns with several
  // independent greedy `.*` segments.
  ('req.' + 'x'.repeat(60) + '"\'` + ').repeat(Math.floor(LINE_CAP / 70)),
  ('<a ' + 'href='.repeat(20) + '${').repeat(Math.floor(LINE_CAP / 105)),
];

describe('ReDoS guard', () => {
  const rules = getAllRules();

  it('has rules to check', () => {
    expect(rules.length).toBeGreaterThan(0);
  });

  for (const rule of rules) {
    for (let i = 0; i < rule.patterns.length; i++) {
      const pattern = rule.patterns[i];
      if (!(pattern instanceof RegExp)) { continue; }

      it(`${rule.code} pattern #${i} finishes on adversarial inputs`, () => {
        for (const input of ADVERSARIAL_INPUTS) {
          const started = Date.now();
          try {
            pattern.exec(input);
          } catch {
            // A thrown error is fine — it's still bounded execution.
          }
          const elapsed = Date.now() - started;
          if (elapsed > MAX_MS) {
            throw new Error(
              `Rule ${rule.code}, pattern #${i} (${pattern.source}) took ${elapsed}ms ` +
              `on input of length ${input.length}. This regex is ReDoS-prone — ` +
              `flatten alternations, avoid nested quantifiers, or anchor the match.`
            );
          }
        }
      });
    }
  }
});
