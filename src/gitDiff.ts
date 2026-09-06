/**
 * Resolve the set of files that have changed since a given git reference.
 *
 * The canonical PR-scope invocation. CI workflows pass
 * `--changed-since origin/main` and scan only what this branch adds on
 * top of main — turns a 40-second full-repo scan into 2 seconds on
 * most PRs.
 *
 * Semantics mirror `git diff --name-only --diff-filter=d <ref>...HEAD`:
 *   - Three-dot syntax so the diff is "everything this branch added
 *     since it diverged from <ref>", not "everything different from
 *     <ref> right now" (which would include unrelated newer commits on
 *     <ref> itself).
 *   - `--diff-filter=d` excludes deletions — a file that no longer
 *     exists in HEAD is not scannable.
 *   - Working-tree / untracked files are NOT included by design. For a
 *     local dev workflow that needs dirty files, just run a full scan.
 */

import * as path from 'path';
import { spawnSync } from 'child_process';

export interface ChangedFilesResult {
  /** Absolute paths that match the diff. */
  files: Set<string>;
  /** The ref we diffed against, normalised for display. */
  ref: string;
  /** How many files the diff returned before filtering. */
  diffCount: number;
}

/**
 * Resolve which files in `workspace` differ from `ref` in the PR-scope
 * sense. Returns absolute paths so the caller can use Set membership
 * against the existing walker output.
 */
export function getChangedFilesSince(workspace: string, ref: string): ChangedFilesResult {
  if (!ref || ref.startsWith('-')) { throw new Error('Invalid comparison ref'); }
  const result = spawnSync(
    'git',
    ['-C', workspace, 'diff', '--name-only', '-z', '--diff-filter=d', `${ref}...HEAD`, '--'],
    { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024, timeout: 30000 }, // 50 MB is generous; most PRs produce <1 KB
  );

  if (result.error) {
    throw new Error(
      `git not available (cannot resolve --changed-since ${ref}): ${result.error.message}`
    );
  }
  if (result.status !== 0) {
    const stderr = (result.stderr || '').trim();
    throw new Error(
      `git diff exited with code ${result.status} (ref '${ref}' may not exist or ${workspace} is not a git repo). ` +
      `stderr: ${stderr || '(empty)'}`
    );
  }

  const root = resolveGitRoot(workspace);
  const lines = result.stdout.split('\0').filter(Boolean);
  const files = new Set<string>();
  for (const rel of lines) {
    // Preserve the workspace spelling, including Windows short paths.
    // the set matches the absolute paths walkFiles() produces.
    files.add(path.resolve(root, rel));
  }

  return { files, ref, diffCount: lines.length };
}

/** Resolve a lexical repo root without Git expanding Windows short paths or symlinks. */
export function resolveGitRoot(workspace: string): string {
  const result = spawnSync('git', ['-C', workspace, 'rev-parse', '--show-prefix'], { encoding: 'utf-8', timeout: 30000 });
  if (result.error || result.status !== 0) { throw new Error('Cannot resolve git repository root'); }
  const parents = result.stdout.trim().split('/').filter(Boolean).map(() => '..');
  return path.resolve(workspace, ...parents);
}
