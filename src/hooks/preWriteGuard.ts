/**
 * PreToolUse hook — the only hook that stops an action before it happens.
 *
 * Kept EXTREMELY narrow: only patterns that are unambiguous and
 * catastrophic deny outright, because a false positive here stops work.
 *
 * Denies:
 *   1. A live provider credential in the content about to be written
 *      (Error-severity TOKEN rules: AWS, Stripe live, OpenAI, Anthropic,
 *      private-key PEM blocks, …).
 *   2. A wide-open platform rule about to land in a rules/SQL file
 *      (deployConfigBlockingRules: `allow write: if true`, RLS disable,
 *      `".write": true`, client-exposed service-role/secret env vars).
 *   3. A .env-style file that git does not ignore (the secrets would be
 *      committed).
 *
 * Asks (user decides):
 *   4. Writes targeting Caspian's own guardrail files (.caspian/baseline.json,
 *      caspian.config.json, .caspianignore) — an agent that can silence its
 *      own findings will silence its own findings.
 *
 * Everything else: exit 0, silent. Fail open on any internal error.
 */

import * as path from 'path';
import { spawnSync } from 'child_process';
import { scanFile } from '../scanRunner';
import { SecuritySeverity } from '../types';
import { providerSecretsRules } from '../rules/providerSecretsRules';
import { deployConfigBlockingRules } from '../rules/deployConfigRules';
import {
  HookInput,
  runHook,
  extractFilePath,
  extractWriteContent,
  emitPreToolUseDecision,
} from './hookIO';

const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

/** Caspian guardrail files the agent should not edit unreviewed. */
const GUARDED_FILES = new Set(['caspian.config.json', '.caspianignore']);

function isGuardedPath(filePath: string): boolean {
  const base = path.basename(filePath);
  if (GUARDED_FILES.has(base)) { return true; }
  const normalized = filePath.replace(/\\/g, '/');
  return normalized.endsWith('.caspian/baseline.json');
}

function isEnvFile(filePath: string): boolean {
  const base = path.basename(filePath);
  return base === '.env' || (base.startsWith('.env.') && !/\.(example|sample|template|dist)$/i.test(base));
}

/** True when git tracks the repo but does NOT ignore this path. */
function envFileWouldBeCommitted(filePath: string, cwd: string): boolean {
  const check = spawnSync('git', ['-C', cwd, 'check-ignore', '-q', filePath], { encoding: 'utf-8' });
  if (check.error) { return false; }            // no git — nothing gets committed
  if (check.status === 0) { return false; }     // ignored — safe
  if (check.status !== 1) { return false; }     // not a repo / error — fail open
  // Status 1: git runs here and the path is NOT ignored.
  return true;
}

export interface GuardDecision {
  decision: 'deny' | 'ask';
  reason: string;
}

/** Pure decision logic — exported for tests. Null = allow. */
export function decideWriteGuard(input: HookInput): GuardDecision | null {
  if (!input.tool_name || !WRITE_TOOLS.has(input.tool_name)) { return null; }
  const filePath = extractFilePath(input.tool_input);
  if (!filePath) { return null; }

  if (isGuardedPath(filePath)) {
    return {
      decision: 'ask',
      reason:
        `Caspian: this write changes ${path.basename(filePath)}, which controls what the ` +
        'security scanner reports. Scanner guardrails should only change with your approval — ' +
        'a finding that is wrong is silenced by a human via `caspian baseline accept` or ' +
        '.caspianignore, not by the agent.',
    };
  }

  const content = extractWriteContent(input.tool_input);
  if (!content) { return null; }

  // 1. Live provider credentials. Error-severity TOKEN rules only —
  //    sandbox/test keys (Warning) do not block a write.
  const tokenHits = scanFile(filePath, content, providerSecretsRules, { runTaint: false })
    .filter(i => i.severity === SecuritySeverity.Error);
  if (tokenHits.length > 0) {
    const hit = tokenHits[0];
    return {
      decision: 'deny',
      reason:
        `Caspian: this write puts a live credential in source (${hit.message}). ` +
        'Read it from an environment variable or a secrets manager at runtime instead. ' +
        'If this key was ever real, rotate it with the provider.',
    };
  }

  // 2. Wide-open platform rules. The rule set's own filePatterns scope
  //    each check to the right file type, so a .ts file never matches the
  //    firestore.rules patterns.
  const configHits = scanFile(filePath, content, deployConfigBlockingRules, { runTaint: false });
  if (configHits.length > 0) {
    const hit = configHits[0];
    return {
      decision: 'deny',
      reason: `Caspian: ${hit.message} Fix before writing: ${hit.suggestion}`,
    };
  }

  // 3. A .env file that would be committed.
  if (isEnvFile(filePath) && input.cwd && envFileWouldBeCommitted(filePath, input.cwd)) {
    return {
      decision: 'deny',
      reason:
        `Caspian: ${path.basename(filePath)} is not covered by .gitignore, so its secrets ` +
        'would be committed to the repository. Add it to .gitignore first, then write it.',
    };
  }

  return null;
}

export function preWriteGuardMain(input: HookInput): number {
  const result = decideWriteGuard(input);
  if (result) {
    emitPreToolUseDecision(result.decision, result.reason);
  }
  return 0;
}

if (require.main === module) {
  void runHook(preWriteGuardMain);
}
