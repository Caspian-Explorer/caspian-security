/**
 * Resolve the set of files changed in the WORKING TREE — staged, unstaged,
 * and untracked — relative to HEAD.
 *
 * This is the agent-loop counterpart to gitDiff.ts. That module answers
 * "what did this branch add since it diverged from <ref>?" (committed work,
 * the PR/CI question). Hooks and the `security_scan_changes` MCP tool need
 * the opposite: "what has the agent touched that isn't committed yet?" —
 * which gitDiff.ts deliberately excludes.
 *
 * Semantics:
 *   - `git diff HEAD --name-only --diff-filter=d` → staged + unstaged
 *     modifications, deletions excluded (a deleted file is not scannable).
 *   - `git ls-files --others --exclude-standard` → untracked files that are
 *     not ignored by .gitignore.
 *   - In a repo with no commits yet (no HEAD), the diff falls back to
 *     treating every tracked+untracked file as changed via ls-files.
 */

import * as path from 'path';
import { spawnSync } from 'child_process';

export interface WorkingTreeChanges {
  /** Absolute paths of changed (tracked-modified + untracked) files. */
  files: Set<string>;
  /** How many entries came back before de-duplication. */
  rawCount: number;
}

function runGit(workspace: string, args: string[]): string {
  const result = spawnSync('git', ['-C', workspace, ...args], {
    encoding: 'utf-8',
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(`git not available: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = (result.stderr || '').trim();
    throw new Error(
      `git ${args[0]} exited with code ${result.status} (${workspace} may not be a git repo). ` +
      `stderr: ${stderr || '(empty)'}`
    );
  }
  return result.stdout;
}

/**
 * Files touched in the working tree of `workspace`. Throws when git is
 * unavailable or the directory is not a repository — callers in the hook
 * path catch and fail open.
 */
export function getWorkingTreeChanges(workspace: string): WorkingTreeChanges {
  let modified: string[] = [];
  try {
    modified = runGit(workspace, ['diff', 'HEAD', '--name-only', '--diff-filter=d'])
      .split('\n').map(l => l.trim()).filter(Boolean);
  } catch (err) {
    // A repo with zero commits has no HEAD; every tracked file is "new".
    // Any other failure (not a repo, git missing) re-throws below via the
    // ls-files call, which shares the same failure modes.
    modified = [];
  }

  const untracked = runGit(workspace, ['ls-files', '--others', '--exclude-standard'])
    .split('\n').map(l => l.trim()).filter(Boolean);

  const files = new Set<string>();
  for (const rel of modified.concat(untracked)) {
    files.add(path.resolve(workspace, rel));
  }
  return { files, rawCount: modified.length + untracked.length };
}
