/**
 * Shared scan entry points for the agent loop. The PostToolUse hook, the
 * `caspian scan-file` CLI, and the `security_scan_file` /
 * `security_scan_changes` MCP tools all funnel through here so they cannot
 * disagree about what counts as a NEW finding.
 *
 * Pipeline per file: engine scan → drop Info/Informational noise →
 * .caspianignore → caspian.config.json ignoreRules → baseline (only
 * findings beyond the accepted counts survive) → LoopFinding[].
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from '../rules';
import { scanFile, DEFAULT_EXTENSIONS, DEFAULT_FILENAMES } from '../scanRunner';
import { SecurityIssue, SecuritySeverity } from '../types';
import { isGeneratedFile } from '../generatedFileDetector';
import { loadIgnoreFile, isIgnored, IgnoreEntry } from '../caspianIgnore';
import { loadDefaultBaseline, applyBaseline } from '../baseline';
import { CaspianFileConfig, loadFileConfig, isPathIgnored } from '../fileConfig';
import { LoopFinding, toLoopFindings } from './severity';

export interface LoopScanContext {
  workspaceRoot: string;
  config: CaspianFileConfig;
  ignoreEntries: IgnoreEntry[];
}

export function createLoopScanContext(workspaceRoot: string): LoopScanContext {
  return {
    workspaceRoot,
    config: loadFileConfig(workspaceRoot),
    ignoreEntries: loadIgnoreFile(workspaceRoot),
  };
}

/** Is this a file the loop should scan at all? */
export function isScannablePath(filePath: string, ctx: LoopScanContext): boolean {
  const base = path.basename(filePath);
  const ext = path.extname(base).slice(1).toLowerCase();
  if (!DEFAULT_EXTENSIONS.has(ext) && !DEFAULT_FILENAMES.has(base)) { return false; }
  const rel = path.relative(ctx.workspaceRoot, filePath).replace(/\\/g, '/');
  if (rel.startsWith('..')) { return false; }
  return !isPathIgnored(rel, ctx.config.ignorePaths);
}

const MAX_LOOP_FILE_SIZE = 500_000;

/**
 * Scan one file and return only the findings the agent loop should see:
 * new (non-baselined), non-ignored, medium severity or above.
 *
 * `content` is optional — when omitted the file is read from disk (the
 * PostToolUse case, where the write has already happened).
 */
export function scanFileForLoop(
  filePath: string,
  ctx: LoopScanContext,
  content?: string
): LoopFinding[] {
  let text = content;
  if (text === undefined) {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_LOOP_FILE_SIZE) { return []; }
    text = fs.readFileSync(filePath, 'utf-8');
  }
  if (isGeneratedFile(filePath, text)) { return []; }

  const relativePath = path.relative(ctx.workspaceRoot, filePath).replace(/\\/g, '/');
  const issues = scanFile(filePath, text, getAllRules(), { runTaint: true });

  const filtered = issues.filter(issue => {
    if (issue.severity === SecuritySeverity.Info) { return false; }
    if (ctx.config.ignoreRules.includes(issue.code)) { return false; }
    if (isIgnored(ctx.ignoreEntries, issue.code, relativePath, issue.line)) { return false; }
    return true;
  });
  if (filtered.length === 0) { return []; }

  const withPath = filtered.map(i => ({ ...i, filePath: relativePath }));
  const baseline = loadDefaultBaseline(ctx.workspaceRoot);
  const fresh: Array<SecurityIssue & { filePath: string }> = baseline
    ? applyBaseline(withPath, baseline).newFindings
    : withPath;

  return toLoopFindings(fresh, relativePath);
}

/**
 * Scan a set of files (the changed-set case). Files that vanished, are
 * unscannable, or fail to read are skipped silently — the loop must not
 * error on a half-written tree.
 */
export function scanFilesForLoop(files: Iterable<string>, ctx: LoopScanContext): LoopFinding[] {
  const findings: LoopFinding[] = [];
  for (const file of files) {
    if (!isScannablePath(file, ctx)) { continue; }
    try {
      findings.push(...scanFileForLoop(file, ctx));
    } catch { /* unreadable file — skip */ }
  }
  return findings;
}
