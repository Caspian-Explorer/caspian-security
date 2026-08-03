/**
 * Stop hook — the "are you actually done" gate.
 *
 * Fires when the agent finishes its turn. Scans the working-tree changes
 * (staged + unstaged + untracked) and blocks stopping (exit 2) ONLY when
 * unresolved CRITICAL findings exist — a high finding the agent already
 * declined to fix is not worth trapping the user in a loop.
 *
 * Loop protection, in order:
 *   - `stop_hook_active` on stdin means we already blocked this stop and
 *     the agent is continuing because of it → exit 0.
 *   - A set of critical findings is only reported once per session; if
 *     the same set is still unresolved at the next stop, let it through
 *     (the user has seen it and the agent could not fix it).
 *   - Claude Code additionally caps consecutive stop-hook blocks.
 *
 * Fail open on any error, including "not a git repo".
 */

import { HookInput, runHook } from './hookIO';
import { getWorkingTreeChanges } from '../gitWorkingTree';
import { createLoopScanContext, scanFilesForLoop } from '../agentLoop/scanForLoop';
import { formatLoopReport } from '../agentLoop/severity';
import {
  loadSessionState,
  saveSessionState,
  findingKey,
} from './sessionState';

export function stopGateMain(input: HookInput): number {
  if (input.stop_hook_active) { return 0; }
  const cwd = input.cwd || process.cwd();

  let changed: Set<string>;
  try {
    changed = getWorkingTreeChanges(cwd).files;
  } catch {
    return 0; // not a git repo (or git missing) — nothing to gate
  }
  if (changed.size === 0) { return 0; }

  const ctx = createLoopScanContext(cwd);
  const critical = scanFilesForLoop(changed, ctx).filter(f => f.loopSeverity === 'critical');
  if (critical.length === 0) { return 0; }

  const sessionId = input.session_id || 'default';
  const state = loadSessionState(sessionId);
  const keys = critical.map(f => findingKey(f.relativePath, f.code));
  const unseen = keys.filter(k => !state.stopGateReported.includes(k));
  if (unseen.length === 0) {
    // Same criticals as last time — already reported, don't re-trap.
    return 0;
  }

  state.stopGateReported = [...new Set([...state.stopGateReported, ...keys])];
  saveSessionState(sessionId, state);

  const header =
    'The working tree still contains unresolved CRITICAL security findings. ' +
    'These must be fixed before this task can be considered done:\n\n';
  process.stderr.write(header + formatLoopReport(critical, ctx.config.maxFindingsInLoop));
  return 2;
}

if (require.main === module) {
  void runHook(stopGateMain);
}
