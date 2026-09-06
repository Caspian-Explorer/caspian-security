import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync, spawnSync } from 'child_process';
import { scanFile, runWorkspaceScan, ScanDiagnostic } from '../scanRunner';
import { getAllRules } from '../rules';
import { buildBaseline, applyBaseline, writeBaseline, loadBaseline } from '../baseline';
import { decideWriteGuard } from '../hooks/preWriteGuard';
import { reconstructEdits } from '../hooks/hookIO';
import { initializeProject, parseInitArgs } from '../cli/init';
import { buildGitHubWorkflow } from '../integration/githubWorkflow';
import { buildGitComparisonBaseline } from '../gitBaseline';
import { getChangedFilesSince } from '../gitDiff';
import { runShipCheck, formatShipCheckReport } from '../cli/shipCheck';
import { toJSONOutput } from '../cli/scan';
import { formatScanSummary } from '../scanReport';

let root: string;
beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-trust-')); });
afterEach(() => { fs.rmSync(root, { recursive: true, force: true }); });
const rules = getAllRules();
function write(name: string, text: string): string {
  const file = path.join(root, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
}
function findings(text: string) {
  return scanFile(path.join(root, 'firestore.rules'), text, rules).map(i => ({ ...i, filePath: 'firestore.rules' }));
}

test('replacement finding cannot consume an unrelated accepted fingerprint; line shifts survive', () => {
  const original = findings('allow write: if true;');
  const baseline = buildBaseline(original, 'test');
  expect(baseline.version).toBe(2);
  expect(applyBaseline(findings('\n  allow write: if true;'), baseline).newFindings).toHaveLength(0);
  expect(applyBaseline(findings('allow read, write: if true;'), baseline).newFindings.map(i => i.code)).toContain('DEPLOY001');
  expect(applyBaseline(findings('allow write: if true;\nallow write: if true;'), baseline).newFindings).toHaveLength(1);
  const target = path.join(root, 'baseline.json');
  writeBaseline(target, baseline);
  expect(loadBaseline(target).fingerprints).toEqual(baseline.fingerprints);
  expect(fs.readFileSync(target, 'utf8')).not.toContain('allow write');
});

test('pre-write guard evaluates token-sized edits in resulting file and preserves disk content', () => {
  const file = write('firestore.rules', 'allow write: if false;');
  const result = decideWriteGuard({ tool_name: 'Edit', cwd: root,
    tool_input: { file_path: file, old_string: 'false', new_string: 'true' } });
  expect(result?.decision).toBe('deny');
  expect(fs.readFileSync(file, 'utf8')).toContain('false');
});

test('sequential edits, deletion, replace-all, and literal replacement syntax are reconstructed', () => {
  expect(reconstructEdits('a b', { edits: [{ old_string: 'a', new_string: 'x' }, { old_string: 'x b', new_string: 'y' }] })).toBe('y');
  expect(reconstructEdits('a b', { old_string: 'a ', new_string: '' })).toBe('b');
  expect(reconstructEdits('aa', { old_string: 'a', new_string: '$&', replace_all: true })).toBe('$&$&');
  expect(() => reconstructEdits('aa', { old_string: 'a', new_string: 'b' })).toThrow('ambiguous');
  expect(() => reconstructEdits('a', { old_string: 'missing', new_string: 'b' })).toThrow();
});

test('skipped and unreadable files are explicit and never counted as analyzed', () => {
  write('large.ts', 'x'.repeat(100));
  const scan = runWorkspaceScan({ workspace: root, maxFileSize: 10 });
  expect(scan.filesScanned).toBe(0);
  expect(scan.filesSkipped).toBe(1);
  expect(scan.diagnostics[0].reason).toBe('too-large');
  const missing = runWorkspaceScan({ workspace: root, files: [path.join(root, 'gone.ts')] });
  expect(missing.diagnostics[0].reason).toBe('unreadable');
  const directory = runWorkspaceScan({ workspace: path.join(root, 'gone') });
  expect(directory.diagnostics[0].reason).toBe('unreadable');
});

test('long-line and timeout truncation have observable coverage diagnostics', () => {
  const reasons: ScanDiagnostic['reason'][] = [];
  scanFile('test.ts', 'x'.repeat(2100), rules, { runTaint: false, onIncomplete: r => reasons.push(r) });
  expect(reasons).toContain('long-line');
  let clock = 0;
  const mock = jest.spyOn(Date, 'now').mockImplementation(() => (clock += 4000));
  try {
    scanFile('test.ts', Array(100).fill('const a = 1;').join('\n'), rules, { runTaint: false, onIncomplete: r => reasons.push(r) });
  } finally { mock.mockRestore(); }
  expect(reasons).toContain('timeout');
});

test('ship check cannot approve an empty project or a generated-marker bypass', () => {
  expect(runShipCheck(root).complete).toBe(false);
  write('firestore.rules', '// @generated\nallow write: if true;');
  const result = runShipCheck(root);
  expect(result.complete).toBe(false);
  expect(formatShipCheckReport(result)).toContain('INCOMPLETE');
  expect(formatShipCheckReport(result)).not.toContain('Clear to launch');
});

test('comments, imports, and unrelated limiters do not silence paid-endpoint review', () => {
  for (const hint of ['// TODO add a rate limit', "import { Ratelimit } from '@upstash/ratelimit';", 'function other() { limiter.limit(); }']) {
    const issues = scanFile('/app/api/chat/route.ts', hint + '\nawait openai.chat.completions.create({});', rules);
    expect(issues.map(i => i.code)).toContain('DEPLOY008');
  }
});

test('GitHub setup preview is read-only and setup preserves existing workflow/config', () => {
  write('package.json', JSON.stringify({ dependencies: { next: '1', '@supabase/supabase-js': '1' } }));
  const options = parseInitArgs([root, '--github', '--dry-run']);
  const preview = initializeProject(options);
  expect(preview.actions.join('\n')).toContain('fail-on: never');
  expect(fs.existsSync(path.join(root, '.github'))).toBe(false);
  expect(preview.notes.join(' ')).toContain('Next.js');
  initializeProject({ ...options, dryRun: false });
  const workflow = path.join(root, '.github/workflows/caspian-security.yml');
  expect(fs.readFileSync(workflow, 'utf8')).toContain('new-only: true');
  expect(fs.existsSync(path.join(root, '.mcp.json'))).toBe(false);
  expect(fs.existsSync(path.join(root, '.caspian/baseline.json'))).toBe(false);
  fs.writeFileSync(workflow, '# custom workflow');
  initializeProject({ ...options, dryRun: false });
  expect(fs.readFileSync(workflow, 'utf8')).toBe('# custom workflow');
  expect(() => buildGitHubWorkflow('main\nmalicious: true')).toThrow();
});

test('PR comparison catches a replacement issue and handles unicode paths from a subdirectory', () => {
  const git = (...args: string[]) => execFileSync('git', ['-C', root, ...args], { stdio: 'pipe' });
  git('init'); git('config', 'user.email', 'test@example.invalid'); git('config', 'user.name', 'test');
  const file = write('app/a space.rules', 'allow write: if true;\n');
  git('add', '.'); git('commit', '-m', 'base');
  const base = git('rev-parse', 'HEAD').toString().trim();
  fs.writeFileSync(file, 'allow read, write: if true;\n');
  git('add', '.'); git('commit', '-m', 'change');
  const workspace = path.join(root, 'app');
  const changed = getChangedFilesSince(workspace, base);
  expect(changed.files.has(file)).toBe(true);
  const comparison = buildGitComparisonBaseline(workspace, base, [...changed.files], 500000);
  const head = scanFile(file, fs.readFileSync(file, 'utf8'), rules).map(i => ({ ...i, filePath: 'a space.rules' }));
  expect(applyBaseline(head, comparison.baseline).newFindings.map(i => i.code)).toContain('DEPLOY001');
  const unchanged = scanFile(file, 'allow write: if true;\n', rules).map(i => ({ ...i, filePath: 'a space.rules' }));
  expect(applyBaseline(unchanged, comparison.baseline).newFindings).toHaveLength(0);
});

test('reports redact credential patterns and escape checkout-controlled Markdown', () => {
  const issue = findings('allow write: if true;')[0];
  issue.category = 'secrets-credentials' as any;
  issue.pattern = 'sensitive-value';
  const files = [{ filePath: 'a', relativePath: '<img>![x](https://example.invalid)', languageId: 'typescript', issues: [issue] }];
  expect(toJSONOutput(files)).not.toContain('sensitive-value');
  const report = formatScanSummary({ status: 'findings', filesScanned: 1, filesSkipped: 0, findings: 1, baselined: 0, ignored: 0, diagnostics: [] }, files);
  expect(report).not.toContain('<img>');
  expect(report).not.toContain('![x]');
});

test('compiled CLI produces a strict incomplete report and setup preview', () => {
  const cli = path.resolve(__dirname, '../../out/cli/caspian.js');
  write('firestore.rules', '// @generated\nallow write: if true;');
  const scan = spawnSync(process.execPath, [cli, 'scan', root, '--format', 'json', '--strict'], { encoding: 'utf8', timeout: 30000 });
  expect(scan.status).toBe(2);
  expect(JSON.parse(scan.stdout).summary.status).toBe('incomplete');
  const preview = spawnSync(process.execPath, [cli, 'init', root, '--github', '--dry-run'], { encoding: 'utf8', timeout: 30000 });
  expect(preview.status).toBe(0);
  expect(preview.stdout).toContain('fail-on: never');
  expect(fs.existsSync(path.join(root, '.github'))).toBe(false);
});

const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
(fs.existsSync(bash) ? test : test.skip)('action quotes untrusted inputs and emits its summary and outcome', () => {
  const repo = path.resolve(__dirname, '../..').replace(/\\/g, '/');
  const yaml = require('js-yaml');
  const action = yaml.load(fs.readFileSync(path.join(repo, '.github/actions/scan/action.yml'), 'utf8'));
  const step = action.runs.steps.find((s: any) => s.id === 'scan');
  write('app.ts', 'export const a = 1;\n');
  const script = write('action-test.sh', step.run);
  const output = path.join(root, 'action-output').replace(/\\/g, '/');
  const summary = path.join(root, 'job-summary').replace(/\\/g, '/');
  const sentinel = path.join(root, 'injected').replace(/\\/g, '/');
  const run = spawnSync(bash, [script.replace(/\\/g, '/')], { encoding: 'utf8', timeout: 30000, env: {
    ...process.env, CASPIAN_ROOT: repo, RUNNER_TEMP: root.replace(/\\/g, '/'),
    GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary,
    SCAN_PATH: root.replace(/\\/g, '/'), SCAN_FORMAT: 'sarif',
    SCAN_OUTPUT: path.join(root, 'report.sarif').replace(/\\/g, '/'),
    SCAN_FAIL_ON: 'never', SCAN_MAX_SIZE: '500000', SCAN_EXCLUDE: '', SCAN_BASELINE: '',
    SCAN_BASE: '', SCAN_STRICT: 'false', SCAN_NEW_ONLY: 'false',
    SCAN_INCLUDE: '$(touch "' + sentinel + '")',
  } });
  expect(run.stderr).not.toContain('command not found');
  expect(run.status).toBe(0);
  expect(fs.existsSync(sentinel)).toBe(false);
  expect(fs.readFileSync(output, 'utf8')).toContain('exit-code=0');
  expect(fs.readFileSync(summary, 'utf8')).toContain('Caspian Security');
  expect(JSON.parse(fs.readFileSync(path.join(root, 'report.sarif'), 'utf8')).runs[0].properties.caspianSummary.status).toBe('passed');
});
