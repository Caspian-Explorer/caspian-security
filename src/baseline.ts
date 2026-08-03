/**
 * Baseline support — the "adopt Caspian into an existing codebase" feature.
 *
 * The format is deliberately simple: per-file, per-rule counts of known
 * findings. When a baseline is in effect, the first N occurrences of each
 * (file, rule) pair are considered "suppressed" and do NOT count toward
 * the `--fail-on` threshold. Anything beyond that is a NEW finding and
 * gates the build as usual.
 *
 * Design notes:
 *   - Counts, not per-finding fingerprints. Fingerprints need either a line
 *     number (fragile; breaks on every edit) or a normalised context hash
 *     (fragile for different reasons and opaque in diffs). A count is
 *     human-readable, git-diff-friendly, and auto-tightens: if you fix one
 *     of three occurrences, the count drops on the next --update-baseline
 *     and adding a new one will fail the build.
 *   - JSON with top-level `version`, `generatedAt`, `generatedBy`, and
 *     `counts`. Stable across releases.
 *   - Matching is file-path-exact using forward-slash normalised paths —
 *     baselines survive Windows/Linux CI migration.
 *   - Nothing is cryptographically signed. A baseline is a code artefact
 *     under review, just like a PR — if someone sneaks a bypass past
 *     review, that's a process failure, not something crypto solves.
 */

import * as fs from 'fs';
import * as path from 'path';
import { SecurityIssue } from './types';

/**
 * Standard on-disk location used by the agent-loop surfaces (hooks, the
 * `security_scan_*` MCP tools, `caspian baseline accept`, `caspian init`).
 * The classic CLI keeps its explicit `--baseline <file>` flag; this default
 * exists so those newer surfaces agree on one path without configuration.
 */
export const DEFAULT_BASELINE_PATH = path.join('.caspian', 'baseline.json');

export interface Baseline {
  version: 1;
  generatedAt: string;
  generatedBy: string;
  counts: {
    [filePath: string]: {
      [ruleCode: string]: number;
    };
  };
}

/** Normalise a path so Windows / POSIX produce the same key. */
export function normalisePath(filePath: string): string {
  return filePath.replace(/\\/g, '/');
}

export function loadBaseline(filePath: string): Baseline {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err: any) {
    throw new Error(`baseline file not readable: ${filePath} (${err.message})`);
  }
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`baseline file is not valid JSON: ${filePath} (${err.message})`);
  }
  if (!parsed || parsed.version !== 1 || typeof parsed.counts !== 'object') {
    throw new Error(`baseline file has unsupported shape (expected { version: 1, counts: {...} }): ${filePath}`);
  }
  return parsed as Baseline;
}

/**
 * Load the baseline at the standard `.caspian/baseline.json` location,
 * or null when none exists or it is unreadable. The agent-loop callers
 * treat a broken baseline as "no baseline" (fail open) rather than
 * erroring — the classic CLI path keeps its strict loadBaseline().
 */
export function loadDefaultBaseline(workspaceRoot: string): Baseline | null {
  try {
    return loadBaseline(path.join(workspaceRoot, DEFAULT_BASELINE_PATH));
  } catch {
    return null;
  }
}

/**
 * Given a result set, produce a Baseline that, if applied, would suppress
 * every current finding. Called by `--update-baseline`.
 */
export function buildBaseline(
  issues: Array<SecurityIssue & { filePath: string }>,
  toolVersion: string
): Baseline {
  const counts: Baseline['counts'] = {};
  for (const issue of issues) {
    const key = normalisePath(issue.filePath);
    if (!counts[key]) { counts[key] = {}; }
    counts[key][issue.code] = (counts[key][issue.code] || 0) + 1;
  }
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    generatedBy: `caspian-security ${toolVersion}`,
    counts,
  };
}

export function writeBaseline(filePath: string, baseline: Baseline): void {
  // Sort keys so repeated runs produce identical diffs.
  const sorted: Baseline = {
    version: baseline.version,
    generatedAt: baseline.generatedAt,
    generatedBy: baseline.generatedBy,
    counts: {},
  };
  const files = Object.keys(baseline.counts).sort();
  for (const f of files) {
    const rules = Object.keys(baseline.counts[f]).sort();
    sorted.counts[f] = {};
    for (const r of rules) { sorted.counts[f][r] = baseline.counts[f][r]; }
  }
  fs.writeFileSync(filePath, JSON.stringify(sorted, null, 2) + '\n', 'utf-8');
}

export interface BaselineApplication {
  /** Issues that match the baseline (first N for each (file, rule) pair). */
  baselined: Array<SecurityIssue & { filePath: string }>;
  /** Issues beyond what the baseline suppresses — "new" findings. */
  newFindings: Array<SecurityIssue & { filePath: string }>;
}

/**
 * Apply a baseline against a fresh scan's findings.
 *
 * Ordering: within a (file, rule) group, we drop the FIRST N findings as
 * baselined (where N is the baseline count). This keeps diff output
 * compact — users see the newer findings first in the unsuppressed list.
 * The specific N findings chosen don't matter because they're all the
 * same rule against the same file; what matters is the total.
 */
export function applyBaseline(
  issues: Array<SecurityIssue & { filePath: string }>,
  baseline: Baseline
): BaselineApplication {
  // Group by (file, rule).
  const groups = new Map<string, Array<SecurityIssue & { filePath: string }>>();
  for (const issue of issues) {
    const key = `${normalisePath(issue.filePath)}\u0001${issue.code}`;
    if (!groups.has(key)) { groups.set(key, []); }
    groups.get(key)!.push(issue);
  }

  const baselined: Array<SecurityIssue & { filePath: string }> = [];
  const newFindings: Array<SecurityIssue & { filePath: string }> = [];

  for (const [key, group] of groups) {
    const [file, code] = key.split('\u0001');
    const budget = (baseline.counts[file] && baseline.counts[file][code]) || 0;
    if (budget >= group.length) {
      // Every current finding is baselined.
      baselined.push(...group);
    } else {
      baselined.push(...group.slice(0, budget));
      newFindings.push(...group.slice(budget));
    }
  }

  return { baselined, newFindings };
}
