/**
 * Agent-loop severity model and report formatting.
 *
 * The engine's native taxonomy is 3-level (Info/Warning/Error) plus a
 * confidence axis ('critical' | 'safe' | 'verify-needed'). Agent loops
 * (Claude Code hooks, MCP tools) need a 4-level model where the top tier
 * blocks unconditionally, so we DERIVE one instead of inventing a second
 * taxonomy on the rules:
 *
 *   Error   + confidence 'critical'  → 'critical'  (blocks; live secrets, open DB rules)
 *   Error                            → 'high'      (blocks by default)
 *   Warning                          → 'medium'    (reported as context, never blocks)
 *   Info                             → 'low'       (never surfaced in the loop)
 *
 * Report text is written as factual statements about the code — never as
 * instructions addressed to the model ("SYSTEM: fix this now"). Text framed
 * as out-of-band commands trips prompt-injection defences and gets flagged
 * to the user instead of acted on.
 */

import { SecurityIssue, SecuritySeverity } from '../types';
import { CaspianFileConfig, LoopSeverity } from '../fileConfig';

export interface LoopFinding extends SecurityIssue {
  /** Workspace-relative path, forward slashes. */
  relativePath: string;
  loopSeverity: LoopSeverity;
}

export function deriveLoopSeverity(issue: SecurityIssue): LoopSeverity {
  if (issue.severity === SecuritySeverity.Error) {
    return issue.confidenceLevel === 'critical' ? 'critical' : 'high';
  }
  if (issue.severity === SecuritySeverity.Warning) { return 'medium'; }
  return 'low';
}

const SEVERITY_RANK: Record<LoopSeverity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

export function worstLoopSeverity(findings: LoopFinding[]): LoopSeverity | null {
  let worst: LoopSeverity | null = null;
  for (const f of findings) {
    if (worst === null || SEVERITY_RANK[f.loopSeverity] > SEVERITY_RANK[worst]) {
      worst = f.loopSeverity;
    }
  }
  return worst;
}

/**
 * Whether a finding blocks the loop under `config.blockOn`.
 *
 * The floor that config cannot lower: 'critical' findings always block.
 * `blockOn` can stop 'high' from blocking, but an agent (or a config file
 * an agent wrote) must not be able to let a live provider credential or a
 * wide-open database rule through silently.
 */
export function blocksLoop(finding: LoopFinding, config: CaspianFileConfig): boolean {
  if (finding.loopSeverity === 'critical') { return true; }
  return config.blockOn.includes(finding.loopSeverity);
}

/** Attach loop severity + relative path to raw engine issues. */
export function toLoopFindings(
  issues: Array<SecurityIssue & { filePath?: string }>,
  relativePath: string
): LoopFinding[] {
  return issues.map(issue => ({
    ...issue,
    relativePath: relativePath.replace(/\\/g, '/'),
    loopSeverity: deriveLoopSeverity(issue),
  }));
}

const MAX_REPORT_CHARS = 8000;

/**
 * Human/model-readable report for in-loop feedback. Identical format for
 * the blocking (stderr) and non-blocking (additionalContext) branches.
 * Sorted worst-first, capped at `maxFindings` entries and 8,000 characters
 * (the platform truncates hook output around 10,000).
 */
export function formatLoopReport(findings: LoopFinding[], maxFindings: number): string {
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_RANK[b.loopSeverity] - SEVERITY_RANK[a.loopSeverity]
  );
  const shown = sorted.slice(0, maxFindings);
  const hidden = sorted.length - shown.length;

  const byFile = new Set(shown.map(f => f.relativePath));
  const where = byFile.size === 1 ? [...byFile][0] : `${byFile.size} files`;
  const count = sorted.length === 1 ? '1 new issue' : `${sorted.length} new issues`;

  const parts: string[] = [`Caspian Security found ${count} in ${where}`];
  for (const f of shown) {
    const loc = byFile.size === 1
      ? `line ${f.line + 1}`
      : `${f.relativePath}:${f.line + 1}`;
    parts.push(
      `[${f.loopSeverity.toUpperCase()}] ${f.code} — ${loc}\n` +
      `  ${f.message}\n` +
      `  Fix: ${f.suggestion}`
    );
  }
  if (hidden > 0) {
    parts.push(`${hidden} lower-severity issue${hidden === 1 ? '' : 's'} not shown. Run \`caspian scan\` for the full list.`);
  }

  let report = parts.join('\n');
  if (report.length > MAX_REPORT_CHARS) {
    report = report.slice(0, MAX_REPORT_CHARS - 15) + '\n… truncated';
  }
  return report;
}
