/** Version 2 identifies findings by source fingerprints. Version 1 count baselines
 * remain readable for migration, but cannot distinguish replacement findings. */

import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { SecurityIssue } from './types';

/**
 * Standard on-disk location used by the agent-loop surfaces (hooks, the
 * `security_scan_*` MCP tools, `caspian baseline accept`, `caspian init`).
 * The classic CLI keeps its explicit `--baseline <file>` flag; this default
 * exists so those newer surfaces agree on one path without configuration.
 */
export const DEFAULT_BASELINE_PATH = path.join('.caspian', 'baseline.json');

export interface Baseline {
  version: 1 | 2;
  fingerprints?: Record<string, Record<string, Record<string, number>>>;
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
  if (!parsed || ![1, 2].includes(parsed.version) || !parsed.counts || typeof parsed.counts !== 'object' || Array.isArray(parsed.counts) || (parsed.version === 2 && (!parsed.fingerprints || typeof parsed.fingerprints !== 'object' || Array.isArray(parsed.fingerprints)))) {
    throw new Error(`baseline file has unsupported shape (expected a version 1 count or version 2 fingerprint baseline): ${filePath}`);
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
  const counts: Baseline['counts'] = Object.create(null);
  const fingerprints: NonNullable<Baseline['fingerprints']> = Object.create(null);
  for (const issue of issues) {
    const key = normalisePath(issue.filePath);
    if (!counts[key]) { counts[key] = Object.create(null); }
    counts[key][issue.code] = (counts[key][issue.code] || 0) + 1;
    fingerprints[key] ??= Object.create(null);
    fingerprints[key][issue.code] ??= Object.create(null);
    const identity = findingIdentity(issue);
    fingerprints[key][issue.code][identity] = (fingerprints[key][issue.code][identity] || 0) + 1;
  }
  return {
    version: 2,
    fingerprints,
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
    ...(baseline.version === 2 ? { fingerprints: sortObject(baseline.fingerprints || {}) } : {}),
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

/** Match version 2 source identities with occurrence counts. Legacy version 1
 * retains file/rule count matching until explicitly migrated. */
export function applyBaseline(
  issues: Array<SecurityIssue & { filePath: string }>,
  baseline: Baseline
): BaselineApplication {
  if (baseline.version === 2) {
    const baselined: BaselineApplication['baselined'] = [];
    const newFindings: BaselineApplication['newFindings'] = [];
    const used = new Map<string, number>();
    for (const issue of issues) {
      const file = normalisePath(issue.filePath);
      const identity = findingIdentity(issue);
      const key = JSON.stringify([file, issue.code, identity]);
      const budget = baseline.fingerprints?.[file]?.[issue.code]?.[identity];
      const consumed = used.get(key) || 0;
      if (typeof budget === 'number' && Number.isSafeInteger(budget) && consumed < budget) {
        baselined.push(issue);
        used.set(key, consumed + 1);
      } else { newFindings.push(issue); }
    }
    return { baselined, newFindings };
  }
  // Legacy version 1: Group by (file, rule).
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

function findingIdentity(issue: SecurityIssue): string {
  return issue.fingerprint || createHash('sha256')
    .update(JSON.stringify([issue.code, issue.pattern, issue.line, issue.column])).digest('hex');
}

function sortObject(value: Record<string, any>): Record<string, any> {
  return Object.fromEntries(Object.keys(value).sort().map(key => [
    key, value[key] && typeof value[key] === 'object' ? sortObject(value[key]) : value[key],
  ]));
}
