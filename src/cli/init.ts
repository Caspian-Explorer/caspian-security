/** Project onboarding: advisory GitHub checks, optional agent integration,
 * read-only preview, and explicit acceptance of existing findings. */

import * as fs from 'fs';
import * as path from 'path';
import { runWorkspaceScan } from '../scanRunner';
import { buildBaseline, writeBaseline, DEFAULT_BASELINE_PATH } from '../baseline';
import { loadIgnoreFile, isIgnored } from '../caspianIgnore';
import { resolveToolVersion } from '../sarif';
import {
  PACKAGE_NAME,
  CASPIAN_MARKER_START,
  CASPIAN_MARKER_END,
  buildLoopRulesBlock,
} from '../integration/agentSnippets';
import { buildGitHubWorkflow } from '../integration/githubWorkflow';
import { SEVERITY_LABELS } from '../types';

export interface InitReport {
  actions: string[];
  notes: string[];
}

/** Merge the caspian server into .mcp.json, preserving everything else. */
export function mergeMcpJson(workspace: string, report: InitReport): void {
  const mcpPath = path.join(workspace, '.mcp.json');
  let root: any = {};
  if (fs.existsSync(mcpPath)) {
    try {
      root = JSON.parse(fs.readFileSync(mcpPath, 'utf-8'));
    } catch {
      report.notes.push('.mcp.json exists but is not valid JSON — left untouched. Add the caspian server manually (`caspian mcp-config`).');
      return;
    }
    if (!root || typeof root !== 'object' || Array.isArray(root)) {
      report.notes.push('.mcp.json must contain an object; left untouched.');
      return;
    }
  }
  if (root.mcpServers !== undefined && (!root.mcpServers || typeof root.mcpServers !== 'object' || Array.isArray(root.mcpServers))) {
    report.notes.push('.mcp.json has an invalid mcpServers object; left untouched.');
    return;
  }
  root.mcpServers ??= {};
  if (root.mcpServers['caspian-security']) {
    report.notes.push('.mcp.json already has a caspian-security server — left as-is.');
    return;
  }
  root.mcpServers['caspian-security'] = {
    command: 'npx',
    args: ['-y', PACKAGE_NAME, 'mcp'],
  };
  fs.writeFileSync(mcpPath, JSON.stringify(root, null, 2) + '\n', 'utf-8');
  report.actions.push('added the caspian-security MCP server to .mcp.json');
}

/**
 * Insert or replace the marker-delimited rules block in `filePath`.
 * Returns true when the file changed.
 */
export function upsertRulesBlock(filePath: string, block: string): boolean {
  let existing = '';
  if (fs.existsSync(filePath)) {
    existing = fs.readFileSync(filePath, 'utf-8');
  }
  const start = existing.indexOf(CASPIAN_MARKER_START);
  const end = existing.indexOf(CASPIAN_MARKER_END);

  let updated: string;
  if (start !== -1 && end !== -1 && end > start) {
    const before = existing.slice(0, start);
    const after = existing.slice(end + CASPIAN_MARKER_END.length);
    updated = before + block + after;
  } else {
    const separator = existing.length === 0 ? '' : existing.endsWith('\n') ? '\n' : '\n\n';
    updated = existing + separator + block + '\n';
  }
  if (updated === existing) { return false; }
  fs.writeFileSync(filePath, updated, 'utf-8');
  return true;
}

function writeBaselineIfAbsent(workspace: string, report: InitReport): void {
  const baselinePath = path.join(workspace, DEFAULT_BASELINE_PATH);
  if (fs.existsSync(baselinePath)) {
    report.notes.push(`${DEFAULT_BASELINE_PATH} already exists — kept (run \`caspian baseline accept\` to refresh).`);
    return;
  }
  const ignoreEntries = loadIgnoreFile(workspace);
  const scan = runWorkspaceScan({ workspace });
  if (scan.diagnostics.length || !scan.filesScanned) {
    throw new Error('Baseline scan incomplete; review coverage with caspian scan before accepting findings.');
  }
  const flat = scan.results.flatMap(r =>
    r.issues
      .filter(i => !isIgnored(ignoreEntries, i.code, r.relativePath, i.line))
      .map(i => ({ ...i, filePath: r.relativePath }))
  );
  fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
  writeBaseline(baselinePath, buildBaseline(flat, resolveToolVersion()));

  const bySeverity = new Map<string, number>();
  for (const i of flat) {
    const label = SEVERITY_LABELS[i.severity];
    bySeverity.set(label, (bySeverity.get(label) || 0) + 1);
  }
  const summary = ['Error', 'Warning', 'Info']
    .filter(l => bySeverity.has(l))
    .map(l => `${bySeverity.get(l)} ${l}`)
    .join(', ');
  report.actions.push(
    `baselined ${flat.length} pre-existing finding(s)${summary ? ` (${summary})` : ''} → ${DEFAULT_BASELINE_PATH}`
  );
  report.notes.push('Agent-loop scans report only NEW findings beyond the baseline. Commit the baseline file.');
}

export interface InitOptions {
  workspace: string;
  github: boolean;
  agent: boolean;
  dryRun: boolean;
  acceptBaseline: boolean;
  actionRef: string;
}

export function parseInitArgs(argv: string[]): InitOptions {
  const opts: InitOptions = { workspace: process.cwd(), github: false, agent: false,
    dryRun: false, acceptBaseline: false, actionRef: 'main' };
  let positional = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--github') { opts.github = true; }
    else if (a === '--agent') { opts.agent = true; }
    else if (a === '--dry-run') { opts.dryRun = true; }
    else if (a === '--accept-baseline') { opts.acceptBaseline = true; }
    else if (a === '--action-ref') {
      const ref = argv[++i];
      if (!ref) { throw new Error('--action-ref requires a value'); }
      opts.actionRef = ref;
    } else if (a.startsWith('-')) { throw new Error('Unknown flag: ' + a); }
    else if (positional) { throw new Error('Only one workspace path is allowed'); }
    else { opts.workspace = path.resolve(a); positional = true; }
  }
  if (!opts.github) { opts.agent = true; }
  buildGitHubWorkflow(opts.actionRef); // Validate before any writes.
  if (!fs.statSync(opts.workspace).isDirectory()) { throw new Error('Workspace must be a directory'); }
  return opts;
}

export function detectProjectStack(workspace: string): string[] {
  const stack: string[] = [];
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(workspace, 'package.json'), 'utf-8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (deps.typescript || fs.existsSync(path.join(workspace, 'tsconfig.json'))) { stack.push('TypeScript'); }
    for (const [dep, label] of [['next', 'Next.js'], ['@supabase/supabase-js', 'Supabase'],
      ['firebase', 'Firebase'], ['openai', 'OpenAI API'], ['@anthropic-ai/sdk', 'Anthropic API'], ['ai', 'AI SDK']]) {
      if (deps[dep]) { stack.push(label); }
    }
  } catch { /* stack detection is informational, not a prerequisite */ }
  if (fs.existsSync(path.join(workspace, 'requirements.txt'))) { stack.push('Python'); }
  return stack;
}

export function initializeProject(opts: InitOptions): InitReport {
  const report: InitReport = { actions: [], notes: [] };
  const stack = detectProjectStack(opts.workspace);
  if (stack.length) { report.notes.push('Detected: ' + stack.join(', ') + '. All supported rules remain enabled.'); }
  if (opts.github) {
    const rel = '.github/workflows/caspian-security.yml';
    const target = path.join(opts.workspace, rel);
    const content = buildGitHubWorkflow(opts.actionRef);
    if (fs.existsSync(target)) { report.notes.push(rel + ' already exists; kept unchanged.'); }
    else if (opts.dryRun) { report.actions.push('Would create ' + rel + ':\n' + content); }
    else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content, { encoding: 'utf-8', flag: 'wx' });
      report.actions.push('Created ' + rel + ' in advisory mode (findings do not fail the check).');
    }
    report.notes.push('Commit the workflow and open a pull request. Read the Caspian job summary and report artifact.');
    report.notes.push('SARIF upload is optional; no Code Security subscription or extra token is needed for job summaries.');
  }
  if (opts.agent) {
    if (opts.dryRun) {
      report.actions.push('Would merge the caspian-security server into .mcp.json and update agent instruction blocks.');
    } else {
      mergeMcpJson(opts.workspace, report);
      const targets: Array<{ file: string; agent: 'claude' | 'cursor' | 'generic' }> = [];
      for (const [name, agent] of [['CLAUDE.md', 'claude'], ['AGENTS.md', 'generic'], ['.cursorrules', 'cursor']] as const) {
        const file = path.join(opts.workspace, name);
        if (fs.existsSync(file) || (agent === 'cursor' && fs.existsSync(path.join(opts.workspace, '.cursor')))) {
          targets.push({ file, agent });
        }
      }
      if (!targets.length) { targets.push({ file: path.join(opts.workspace, 'AGENTS.md'), agent: 'generic' }); }
      for (const t of targets) {
        if (upsertRulesBlock(t.file, buildLoopRulesBlock(t.agent))) {
          report.actions.push('Updated ' + path.relative(opts.workspace, t.file));
        }
      }
    }
  }
  if (opts.acceptBaseline) {
    if (opts.dryRun) { report.actions.push('Would scan and accept existing findings into ' + DEFAULT_BASELINE_PATH + ' if absent.'); }
    else { writeBaselineIfAbsent(opts.workspace, report); }
  } else {
    report.notes.push('Existing findings have not been accepted automatically. Review them before running caspian baseline accept.');
  }
  return report;
}

function printHelp(): void {
  process.stdout.write([
    'caspian init [path] [--github] [--agent] [--dry-run]',
    '  --github           Add a GitHub PR workflow in advisory mode; preserve an existing workflow.',
    '  --agent            Also configure MCP and agent rules (default when --github is absent).',
    '  --dry-run          Preview setup without changing files.',
    '  --action-ref REF   Caspian action branch/tag/SHA (default main; pin a reviewed SHA for enforcement).',
    '  --accept-baseline  Explicitly accept existing findings if no baseline exists.',
    '', 'Examples:', '  caspian init --github --dry-run', '  caspian init --github',
    '  caspian init --github --agent', '',
  ].join('\n'));
}

export function runInitCli(argv: string[]): void {
  if (argv.includes('--help') || argv.includes('-h')) { printHelp(); process.exit(0); }
  const options = parseInitArgs(argv);
  const report = initializeProject(options);
  process.stdout.write(options.dryRun ? 'Caspian setup preview:\n' : 'Caspian setup:\n');
  for (const a of report.actions) { process.stdout.write('  + ' + a + '\n'); }
  for (const n of report.notes) { process.stdout.write('  ' + n + '\n'); }
  process.exit(0);
}
