/**
 * File-based configuration — `caspian.config.json` at the workspace root.
 *
 * The VS Code extension configures itself through `caspianSecurity.*`
 * settings, which the CLI, MCP server, and agent-loop hooks cannot see.
 * This file is the surface those headless consumers share. Every field is
 * optional; absence of the file is not an error.
 *
 * Scope is deliberately narrow: this config can RELAX what the agent loop
 * reports (ignore paths, fewer findings per report) but it can never
 * disable the hard-block on provider-prefixed secrets — an agent that can
 * rewrite its own guardrails will rewrite its own guardrails. See
 * `blocksLoop` in agentLoop/severity.ts for where that floor is enforced.
 */

import * as fs from 'fs';
import * as path from 'path';

export const CONFIG_FILENAME = 'caspian.config.json';

export type LoopSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface CaspianFileConfig {
  /** Loop severities that block (PostToolUse exit 2). Default: critical + high. */
  blockOn: LoopSeverity[];
  /** Rule codes never reported in the agent loop (full scans still show them). */
  ignoreRules: string[];
  /** Path fragments / simple globs the hooks skip entirely. */
  ignorePaths: string[];
  /** Cap on findings included in a single in-loop report. */
  maxFindingsInLoop: number;
}

export const DEFAULT_FILE_CONFIG: CaspianFileConfig = {
  blockOn: ['critical', 'high'],
  ignoreRules: [],
  ignorePaths: ['**/node_modules/**', '**/*.test.*', '**/*.spec.*', '**/dist/**', '**/out/**'],
  maxFindingsInLoop: 5,
};

const VALID_SEVERITIES = new Set<string>(['critical', 'high', 'medium', 'low']);

/**
 * Load `caspian.config.json` from `workspaceRoot`, merged over defaults.
 * Malformed files degrade to the defaults rather than throwing — a broken
 * config must never break the agent loop (fail open).
 */
export function loadFileConfig(workspaceRoot: string): CaspianFileConfig {
  const filePath = path.join(workspaceRoot, CONFIG_FILENAME);
  let parsed: any;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch {
    return { ...DEFAULT_FILE_CONFIG };
  }
  if (!parsed || typeof parsed !== 'object') {
    return { ...DEFAULT_FILE_CONFIG };
  }

  const config: CaspianFileConfig = { ...DEFAULT_FILE_CONFIG };
  if (Array.isArray(parsed.blockOn)) {
    const cleaned = parsed.blockOn.filter((s: unknown) => typeof s === 'string' && VALID_SEVERITIES.has(s));
    if (cleaned.length > 0) { config.blockOn = cleaned as LoopSeverity[]; }
  }
  if (Array.isArray(parsed.ignoreRules)) {
    config.ignoreRules = parsed.ignoreRules.filter((s: unknown) => typeof s === 'string');
  }
  if (Array.isArray(parsed.ignorePaths)) {
    config.ignorePaths = parsed.ignorePaths.filter((s: unknown) => typeof s === 'string');
  }
  if (typeof parsed.maxFindingsInLoop === 'number' && parsed.maxFindingsInLoop >= 1) {
    config.maxFindingsInLoop = Math.floor(parsed.maxFindingsInLoop);
  }
  return config;
}

/**
 * Match a path against an ignorePaths entry. Entries are either plain
 * fragments (substring match, the historical CLI behaviour) or simple
 * globs using `*` / `**`. Matching is done on forward-slash paths.
 */
export function isPathIgnored(filePath: string, ignorePaths: string[]): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  for (const entry of ignorePaths) {
    if (!/[*?]/.test(entry)) {
      if (normalized.includes(entry)) { return true; }
      continue;
    }
    let out = '';
    for (let i = 0; i < entry.length; i++) {
      const ch = entry[i];
      if (ch === '*') {
        if (entry[i + 1] === '*') {
          out += '.*';
          i++;
          if (entry[i + 1] === '/') { i++; }
        } else {
          out += '[^/]*';
        }
      } else if (ch === '?') {
        out += '[^/]';
      } else {
        out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
      }
    }
    try {
      if (new RegExp(`(^|/)${out}$`).test(normalized) || new RegExp(`^${out}$`).test(normalized)) {
        return true;
      }
    } catch { /* malformed entry — skip */ }
  }
  return false;
}
