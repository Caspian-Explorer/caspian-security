import * as path from 'path';
import { spawnSync } from 'child_process';
import { buildBaseline, Baseline } from './baseline';
import { getAllRules } from './rules';
import { scanFile, ScanDiagnostic } from './scanRunner';
import { isGeneratedFile } from './generatedFileDetector';
import { SecurityIssue } from './types';

function git(workspace: string, args: string[], maxBuffer = 50 * 1024 * 1024): string {
  const result = spawnSync('git', ['-C', workspace, ...args], { encoding: 'utf-8', maxBuffer, timeout: 30000 });
  if (result.error || result.status !== 0) { throw new Error('Cannot compare PR base: git ' + args[0] + ' failed. Fetch the base history and retry.'); }
  return result.stdout;
}

/** Read git objects only: never checkout or execute code from the comparison ref. */
export function buildGitComparisonBaseline(workspace: string, ref: string, files: string[], maxFileSize: number): { baseline: Baseline; diagnostics: ScanDiagnostic[] } {
  const commit = git(workspace, ['rev-parse', '--verify', '--end-of-options', ref + '^{commit}']).trim();
  const base = git(workspace, ['merge-base', commit, 'HEAD']).trim();
  const root = git(workspace, ['rev-parse', '--show-toplevel']).trim();
  const tree = git(workspace, ['ls-tree', '-r', '-z', '--full-tree', base]);
  const blobs = new Map<string, string>();
  for (const entry of tree.split('\0')) {
    const tab = entry.indexOf('\t');
    if (tab < 0) { continue; }
    const [mode, type, hash] = entry.slice(0, tab).split(' ');
    if (type === 'blob' && mode !== '120000') { blobs.set(entry.slice(tab + 1), hash); }
  }
  const issues: Array<SecurityIssue & { filePath: string }> = [];
  const diagnostics: ScanDiagnostic[] = [];
  const rules = getAllRules();
  for (const file of files) {
    const repoPath = path.relative(root, file).replace(/\\/g, '/');
    const relative = path.relative(workspace, file).replace(/\\/g, '/');
    const blob = blobs.get(repoPath);
    if (!blob) { continue; } // Added files (including renames) have no accepted findings.
    const diagnosticPath = 'base:' + relative;
    const size = Number(git(workspace, ['cat-file', '-s', blob]).trim());
    if (maxFileSize > 0 && size > maxFileSize) { diagnostics.push({ path: diagnosticPath, reason: 'too-large' }); continue; }
    const text = git(workspace, ['cat-file', 'blob', blob], Math.max(size + 1024, 1024));
    if (isGeneratedFile(file, text)) { diagnostics.push({ path: diagnosticPath, reason: 'generated' }); continue; }
    const found = scanFile(file, text, rules, { onIncomplete: (reason, line) => diagnostics.push({ path: diagnosticPath, reason, line }) });
    issues.push(...found.map(issue => ({ ...issue, filePath: relative })));
  }
  return { baseline: buildBaseline(issues, 'git-base'), diagnostics };
}
