/**
 * PostToolUse hook — the workhorse.
 *
 * The write has already happened; this hook scans the file and feeds the
 * findings back to the model, which fixes them in the same turn:
 *   - critical/high (per caspian.config.json blockOn) → exit 2, report on
 *     stderr (Claude Code feeds stderr back to the model as an error);
 *   - medium only → exit 0 with non-blocking additionalContext JSON;
 *   - clean → exit 0, silent. No "0 issues found" noise on every edit.
 *
 * Only NEW findings surface (baseline-filtered), and the loop guard
 * downgrades repeat offenders so a finding the agent can't fix cannot
 * ping-pong the session forever. Fail open on any error.
 */

import {
  HookInput,
  runHook,
  extractFilePath,
  emitPostToolUseContext,
} from './hookIO';
import { createLoopScanContext, isScannablePath, scanFileForLoop } from '../agentLoop/scanForLoop';
import { blocksLoop, formatLoopReport, LoopFinding } from '../agentLoop/severity';
import {
  loadSessionState,
  saveSessionState,
  applyLoopGuard,
  recordBlocks,
  pruneOldSessions,
} from './sessionState';
import * as path from 'path';

const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

export function postWriteScanMain(input: HookInput): number {
  if (!input.tool_name || !WRITE_TOOLS.has(input.tool_name)) { return 0; }
  const rawPath = extractFilePath(input.tool_input);
  if (!rawPath) { return 0; }

  const cwd = input.cwd || process.cwd();
  const filePath = path.resolve(cwd, rawPath);
  const ctx = createLoopScanContext(cwd);
  if (!isScannablePath(filePath, ctx)) { return 0; }

  const findings: LoopFinding[] = scanFileForLoop(filePath, ctx);
  if (findings.length === 0) { return 0; }

  const sessionId = input.session_id || 'default';
  const state = loadSessionState(sessionId);
  pruneOldSessions();

  const wouldBlock = findings.filter(f => blocksLoop(f, ctx.config));
  const context = findings.filter(f => !blocksLoop(f, ctx.config));
  const { blockable, downgraded } = applyLoopGuard(state, wouldBlock);

  if (blockable.length > 0) {
    recordBlocks(state, blockable);
    saveSessionState(sessionId, state);
    // Blocking branch: report EVERYTHING (blocking first) on stderr.
    const report = formatLoopReport(
      [...blockable, ...downgraded, ...context],
      ctx.config.maxFindingsInLoop
    );
    process.stderr.write(report);
    return 2;
  }

  // Nothing blockable (medium only, or repeat offenders downgraded by the
  // loop guard) → non-blocking context.
  const remaining = [...downgraded, ...context];
  if (remaining.length > 0) {
    saveSessionState(sessionId, state);
    emitPostToolUseContext(formatLoopReport(remaining, ctx.config.maxFindingsInLoop));
  }
  return 0;
}

if (require.main === module) {
  void runHook(postWriteScanMain);
}
