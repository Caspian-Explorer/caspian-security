/**
 * `caspian init [path]` — one-command agent-loop setup for a project.
 *
 * What it does (idempotently — safe to re-run):
 *   1. Detects which agents are configured (.claude/, CLAUDE.md, .cursor/,
 *      .cursorrules, AGENTS.md, .mcp.json).
 *   2. Writes or MERGES `.mcp.json` so the caspian MCP server is available
 *      (existing servers are never touched).
 *   3. Appends the security-scanning rules block to existing rules files
 *      (CLAUDE.md / AGENTS.md / .cursorrules), between
 *      `<!-- caspian:start -->` … `<!-- caspian:end -->` markers. On
 *      re-run the block is replaced in place. If no rules file exists,
 *      AGENTS.md is created.
 *   4. Runs a baseline scan and writes `.caspian/baseline.json` (unless
 *      one exists), so the first in-loop experience reports only findings
 *      the agent actually introduces.
 *
 * This is the ONE Caspian command that writes into a user's repository —
 * running it is the consent. Everything it writes is printed, and
 * `snippet` / `mcp-config` remain available for manual, print-only setup.
 */

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
import { SEVERITY_LABELS } from '../types';

interface InitReport {
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
    if (!root || typeof root !== 'object') { root = {}; }
  }
  if (!root.mcpServers || typeof root.mcpServers !== 'object') { root.mcpServers = {}; }
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

function printHelp(): void {
  process.stdout.write(
    'caspian init [path]\n' +
    '\n' +
    'Sets up Caspian Security for AI-agent workflows in one command:\n' +
    '  - writes/merges .mcp.json with the caspian MCP server\n' +
    '  - appends the security-scanning rules block to CLAUDE.md / AGENTS.md /\n' +
    '    .cursorrules (idempotent, between <!-- caspian:start/end --> markers)\n' +
    '  - runs a baseline scan into .caspian/baseline.json so only NEW findings\n' +
    '    surface in the agent loop\n' +
    '\n' +
    'Claude Code users: the Caspian plugin (hooks + MCP + /ship-check) is the\n' +
    'richer integration — see the README. `init` covers Cursor and other agents.\n'
  );
}

export function runInitCli(argv: string[]): void {
  let workspace = process.cwd();
  for (const a of argv) {
    if (a === '-h' || a === '--help') { printHelp(); process.exit(0); }
    else if (a.startsWith('-')) {
      process.stderr.write(`caspian init: unknown flag ${a}\n`);
      printHelp();
      process.exit(2);
    } else { workspace = path.resolve(a); }
  }
  if (!fs.existsSync(workspace)) {
    process.stderr.write(`caspian init: path does not exist: ${workspace}\n`);
    process.exit(2);
  }

  const report: InitReport = { actions: [], notes: [] };

  mergeMcpJson(workspace, report);

  // Rules files: update every one that exists; create AGENTS.md when none do.
  const claudeMd = path.join(workspace, 'CLAUDE.md');
  const agentsMd = path.join(workspace, 'AGENTS.md');
  const cursorRules = path.join(workspace, '.cursorrules');
  const targets: Array<{ file: string; agent: 'claude' | 'cursor' | 'generic' }> = [];
  if (fs.existsSync(claudeMd)) { targets.push({ file: claudeMd, agent: 'claude' }); }
  if (fs.existsSync(agentsMd)) { targets.push({ file: agentsMd, agent: 'generic' }); }
  if (fs.existsSync(cursorRules) || fs.existsSync(path.join(workspace, '.cursor'))) {
    targets.push({ file: cursorRules, agent: 'cursor' });
  }
  if (targets.length === 0) { targets.push({ file: agentsMd, agent: 'generic' }); }

  for (const t of targets) {
    const changed = upsertRulesBlock(t.file, buildLoopRulesBlock(t.agent));
    const rel = path.relative(workspace, t.file);
    if (changed) { report.actions.push(`wrote the security-scanning rules block to ${rel}`); }
    else { report.notes.push(`${rel} already up to date.`); }
  }

  if (fs.existsSync(path.join(workspace, '.claude'))) {
    report.notes.push(
      'Claude Code detected: the Caspian plugin adds write-time blocking and ' +
      'post-edit scanning hooks on top of this setup — see the README.'
    );
  }

  writeBaselineIfAbsent(workspace, report);

  process.stdout.write('caspian init:\n');
  for (const a of report.actions) { process.stdout.write(`  + ${a}\n`); }
  for (const n of report.notes) { process.stdout.write(`  · ${n}\n`); }
  process.exit(0);
}
