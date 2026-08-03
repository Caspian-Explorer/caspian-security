/**
 * Per-session hook state — the loop guard.
 *
 * A PostToolUse hook that blocks an edit provokes another edit, which
 * fires the hook again. Without a guard this ping-pongs forever when the
 * agent can't (or won't) fix a finding. The guard downgrades repeat
 * offenders to non-blocking context:
 *   - the same file::ruleCode blocked twice already → context from the
 *     third occurrence on;
 *   - more than 20 blocking events in one session → everything becomes
 *     context.
 *
 * State lives outside the repository (the agent must not be able to edit
 * it): ${CLAUDE_PLUGIN_DATA}/sessions/ when the platform provides a
 * plugin data dir, else the OS temp dir. Files older than 7 days are
 * pruned opportunistically.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface SessionState {
  /** file::ruleCode → times this finding has blocked. */
  blocks: Record<string, number>;
  /** Total blocking events this session. */
  totalBlocks: number;
  /** Stop-gate finding keys already reported (don't re-trap on the same set). */
  stopGateReported: string[];
  updatedAt: string;
}

export const MAX_BLOCKS_PER_FINDING = 2;
export const MAX_BLOCKS_PER_SESSION = 20;
const MAX_STATE_AGE_MS = 7 * 24 * 60 * 60 * 1000;

export function stateDir(): string {
  const base = process.env.CLAUDE_PLUGIN_DATA && process.env.CLAUDE_PLUGIN_DATA.trim()
    ? process.env.CLAUDE_PLUGIN_DATA
    : path.join(os.tmpdir(), 'caspian-hooks');
  return path.join(base, 'sessions');
}

function stateFile(sessionId: string): string {
  const safe = sessionId.replace(/[^A-Za-z0-9_-]/g, '_') || 'default';
  return path.join(stateDir(), `${safe}.json`);
}

export function emptyState(): SessionState {
  return { blocks: {}, totalBlocks: 0, stopGateReported: [], updatedAt: new Date().toISOString() };
}

export function loadSessionState(sessionId: string): SessionState {
  try {
    const parsed = JSON.parse(fs.readFileSync(stateFile(sessionId), 'utf-8'));
    if (parsed && typeof parsed === 'object') {
      return {
        blocks: typeof parsed.blocks === 'object' && parsed.blocks ? parsed.blocks : {},
        totalBlocks: typeof parsed.totalBlocks === 'number' ? parsed.totalBlocks : 0,
        stopGateReported: Array.isArray(parsed.stopGateReported) ? parsed.stopGateReported : [],
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
      };
    }
  } catch { /* fresh session */ }
  return emptyState();
}

export function saveSessionState(sessionId: string, state: SessionState): void {
  try {
    const dir = stateDir();
    fs.mkdirSync(dir, { recursive: true });
    state.updatedAt = new Date().toISOString();
    fs.writeFileSync(stateFile(sessionId), JSON.stringify(state, null, 2), 'utf-8');
  } catch { /* state is best-effort — never break the hook over it */ }
}

/** Remove session files older than 7 days. Best-effort. */
export function pruneOldSessions(): void {
  try {
    const dir = stateDir();
    const cutoff = Date.now() - MAX_STATE_AGE_MS;
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      try {
        if (fs.statSync(full).mtimeMs < cutoff) { fs.rmSync(full, { force: true }); }
      } catch { /* skip */ }
    }
  } catch { /* dir missing — nothing to prune */ }
}

export function findingKey(relativePath: string, ruleCode: string): string {
  return `${relativePath}::${ruleCode}`;
}

/**
 * Partition blockable findings into those that may still block and those
 * downgraded by the loop guard. Does NOT record anything — call
 * recordBlocks() only when the hook actually blocks.
 */
export function applyLoopGuard<T extends { relativePath: string; code: string }>(
  state: SessionState,
  findings: T[]
): { blockable: T[]; downgraded: T[] } {
  if (state.totalBlocks >= MAX_BLOCKS_PER_SESSION) {
    return { blockable: [], downgraded: findings };
  }
  const blockable: T[] = [];
  const downgraded: T[] = [];
  for (const f of findings) {
    const count = state.blocks[findingKey(f.relativePath, f.code)] || 0;
    if (count >= MAX_BLOCKS_PER_FINDING) { downgraded.push(f); }
    else { blockable.push(f); }
  }
  return { blockable, downgraded };
}

export function recordBlocks<T extends { relativePath: string; code: string }>(
  state: SessionState,
  blocked: T[]
): void {
  for (const f of blocked) {
    const key = findingKey(f.relativePath, f.code);
    state.blocks[key] = (state.blocks[key] || 0) + 1;
  }
  state.totalBlocks += 1;
}
