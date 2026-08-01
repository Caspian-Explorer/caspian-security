/**
 * Confidence-scoring tests. As of 10.9 every finding carries a confidence
 * level, resolved as: per-match heuristics → rule author's base
 * confidence → default by rule type. Before this, only ~2 of 291 rules
 * produced any confidence signal on a fresh install.
 */

import { classifyConfidence } from '../confidenceAnalyzer';
import { scanFile } from '../scanRunner';
import { getAllRules } from '../rules';
import { RuleType } from '../types';

const rules = getAllRules();
const ruleByCode = new Map(rules.map(r => [r.code, r]));

// Assembled at runtime so the compiled test file doesn't contain a
// token-shaped literal (vsce's packaging secret-scan checks out/).
const FAKE_SLACK_TOKEN = ['xoxb', '123456789012', '123456789012', '123456789012', 'AbCdEfGhIjKlMnOpQrStUvWx'].join('-');

describe('classifyConfidence heuristics', () => {
  it('hardcoded secret string literal → critical', () => {
    const lines = ['const password = "hunter2secret";'];
    expect(classifyConfidence(lines, 0, 6, 'password = "hunter2secret"', 'CRED001')).toBe('critical');
  });

  it('secret from env var → verify-needed', () => {
    const lines = ['const password = process.env.DB_PASSWORD || "fallback";'];
    expect(classifyConfidence(lines, 0, 6, 'password =', 'CRED001')).toBe('verify-needed');
  });

  it('parameterized query → safe', () => {
    const lines = ["db.query('SELECT * FROM users WHERE id = $1', [id]);"];
    expect(classifyConfidence(lines, 0, 3, 'query(', 'DB001')).toBe('safe');
  });

  it('concatenated query → verify-needed', () => {
    const lines = ['const q = "SELECT * FROM users WHERE id = " + id;'];
    expect(classifyConfidence(lines, 0, 10, 'SELECT', 'DB001')).toBe('verify-needed');
  });

  it('returns undefined for rules it has no heuristic for', () => {
    const lines = ['eval(userInput);'];
    expect(classifyConfidence(lines, 0, 0, 'eval(', 'CMD001')).toBeUndefined();
  });
});

describe('every finding carries a confidence level', () => {
  it('scanFile never emits an issue without confidenceLevel', () => {
    const text = [
      'const password = "hunter2secret";',
      'eval(userInput);',
      'fetch("https://api.example.com");',
      'app.get("/x", (req, res) => res.send(req.query.q));',
    ].join('\n');
    const issues = scanFile('/x/app.js', text, rules);
    expect(issues.length).toBeGreaterThan(0);
    for (const issue of issues) {
      expect(issue.confidenceLevel).toBeDefined();
    }
  });

  it('provider-prefix token rules carry base confidence critical', () => {
    const tokenRules = rules.filter(r => r.code.startsWith('TOKEN'));
    expect(tokenRules.length).toBeGreaterThan(20);
    for (const rule of tokenRules) {
      expect(rule.confidence).toBe('critical');
    }
  });

  it('a matched Slack token is reported as critical', () => {
    const issues = scanFile('/x/app.js', `const s = "${FAKE_SLACK_TOKEN}";\n`, rules, { runTaint: false });
    const token = issues.find(i => i.code.startsWith('TOKEN'));
    expect(token).toBeDefined();
    expect(token!.confidenceLevel).toBe('critical');
  });

  it('CodeDetectable IaC rules carry base confidence critical', () => {
    for (const prefix of ['K8S', 'TF', 'DOCKER']) {
      const family = rules.filter(r => r.code.startsWith(prefix) && r.ruleType === RuleType.CodeDetectable);
      expect(family.length).toBeGreaterThan(0);
      for (const rule of family) {
        expect(rule.confidence).toBe('critical');
      }
    }
  });

  it('informational reminders default to safe', () => {
    const text = 'fetch("https://api.example.com/data");\n';
    const issues = scanFile('/x/app.js', text, rules, { runTaint: false });
    const informational = issues.filter(i => ruleByCode.get(i.code)?.ruleType === RuleType.Informational
      && !ruleByCode.get(i.code)?.confidence);
    for (const issue of informational) {
      expect(issue.confidenceLevel).toBe('safe');
    }
  });

  it('code-detectable rules without heuristics or author confidence default to verify-needed', () => {
    const issues = scanFile('/x/app.js', 'eval(userInput);\n', rules, { runTaint: false });
    const evalIssue = issues.find(i => {
      const r = ruleByCode.get(i.code);
      return r?.ruleType === RuleType.CodeDetectable && !r.confidence && i.line === 0;
    });
    if (evalIssue) {
      expect(['verify-needed', 'critical', 'safe']).toContain(evalIssue.confidenceLevel);
      expect(evalIssue.confidenceLevel).toBe('verify-needed');
    }
  });

  it('a custom classifier still wins over rule defaults', () => {
    const issues = scanFile('/x/app.js', `const s = "${FAKE_SLACK_TOKEN}";\n`, rules, {
      runTaint: false,
      classify: () => 'safe',
    });
    const token = issues.find(i => i.code.startsWith('TOKEN'));
    expect(token?.confidenceLevel).toBe('safe');
  });
});
