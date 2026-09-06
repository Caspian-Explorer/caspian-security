/**
 * `caspian ship-check [path]` — the pre-deploy gate.
 *
 * Scans the workspace for the deploy-configuration mistakes that most
 * often expose AI-built apps (open Firestore/Supabase rules, RLS
 * disabled, client-exposed secrets, unmetered AI endpoints, leaked
 * provider tokens) plus credential files tracked by git.
 *
 * Deliberately NOT baseline-filtered: this is the "is it safe to launch"
 * question, and a pre-existing open database rule sinks the ship whether
 * or not it predates this branch. `.caspianignore` is honoured.
 *
 * Exit codes: 0 = nothing blocking, 1 = critical/high findings, 2 = failed.
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { runWorkspaceScan, FileResult, ScanDiagnostic } from '../scanRunner';
import { SecurityCategory, SecuritySeverity } from '../types';
import { loadIgnoreFile, isIgnored } from '../caspianIgnore';
import { loadFileConfig } from '../fileConfig';
import { deriveLoopSeverity, LoopFinding } from '../agentLoop/severity';

/** Categories that make up the deployment-security surface. */
const SHIP_CATEGORIES = new Set<SecurityCategory>([
  SecurityCategory.InfrastructureDeployment,
  SecurityCategory.SecretsCredentials,
  SecurityCategory.APISecurity,
  SecurityCategory.CORSConfiguration,
]);

/** Git-tracked files that should essentially never be committed. */
const TRACKED_CREDENTIAL_PATTERNS: Array<{ rx: RegExp; label: string }> = [
  { rx: /(^|\/)\.env(\.[^/]*)?$/, label: 'environment file (.env)' },
  { rx: /\.pem$/i, label: 'PEM key file' },
  { rx: /(^|\/)id_(?:rsa|ed25519|ecdsa)$/, label: 'SSH private key' },
  { rx: /(^|\/)(?:serviceaccount|service-account)[^/]*\.json$/i, label: 'service-account key file' },
  { rx: /\.p12$|\.pfx$/i, label: 'PKCS keystore' },
];

/** Env files matched above that are templates, not secrets. */
const CREDENTIAL_FILE_ALLOW = /\.(?:example|sample|template|dist)$/i;

export interface TrackedCredentialFile {
  path: string;
  label: string;
}

/** Files git tracks that look like credentials. Empty when git is absent. */
export function findTrackedCredentialFiles(workspace: string): TrackedCredentialFile[] {
  const result = spawnSync('git', ['-C', workspace, 'ls-files'], {
    encoding: 'utf-8',
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) { return []; }
  const hits: TrackedCredentialFile[] = [];
  for (const rel of result.stdout.split('\n')) {
    const p = rel.trim();
    if (!p || CREDENTIAL_FILE_ALLOW.test(p)) { continue; }
    for (const { rx, label } of TRACKED_CREDENTIAL_PATTERNS) {
      if (rx.test(p)) { hits.push({ path: p, label }); break; }
    }
  }
  return hits;
}

export interface ShipCheckResult {
  findings: LoopFinding[];
  trackedCredentials: TrackedCredentialFile[];
  filesScanned: number;
  filesSkipped: number;
  diagnostics: ScanDiagnostic[];
  complete: boolean;
}

/** Shared by the CLI below and the `check_deployment_security` MCP tool. */
export function runShipCheck(workspace: string): ShipCheckResult {
  const config = loadFileConfig(workspace);
  const ignoreEntries = loadIgnoreFile(workspace);
  const scan = runWorkspaceScan({ workspace });

  const findings: LoopFinding[] = [];
  for (const r of scan.results as FileResult[]) {
    for (const issue of r.issues) {
      if (!SHIP_CATEGORIES.has(issue.category)) { continue; }
      if (issue.severity === SecuritySeverity.Info) { continue; }
      if (config.ignoreRules.includes(issue.code)) { continue; }
      if (isIgnored(ignoreEntries, issue.code, r.relativePath, issue.line)) { continue; }
      findings.push({
        ...issue,
        relativePath: r.relativePath.replace(/\\/g, '/'),
        loopSeverity: deriveLoopSeverity(issue),
      });
    }
  }

  return {
    findings,
    trackedCredentials: findTrackedCredentialFiles(workspace),
    filesScanned: scan.filesScanned,
    filesSkipped: scan.filesSkipped,
    diagnostics: scan.diagnostics,
    complete: scan.diagnostics.length === 0 && scan.filesScanned > 0,
  };
}

const ORDER: Array<LoopFinding['loopSeverity']> = ['critical', 'high', 'medium', 'low'];

export function formatShipCheckReport(result: ShipCheckResult): string {
  const lines: string[] = [];
  const total = result.findings.length + result.trackedCredentials.length;
  if (!result.complete) {
    lines.push('Ship check INCOMPLETE: ' + result.filesScanned + ' file(s) analyzed, ' + result.filesSkipped + ' skipped.');
    lines.push(...result.diagnostics.slice(0, 30).map(d => '  ' + d.path + ': ' + d.reason));
    if (!result.filesScanned) { lines.push('No supported files were analyzed.'); }
  }
  if (total === 0 && result.complete) {
    return `Ship check: no deployment-security findings across ${result.filesScanned} file(s). No blocking findings in completed checks; this is not a deployment safety certification.`;
  }

  lines.push(`Ship check: ${total} deployment-security finding(s) across ${result.filesScanned} scanned file(s)`);
  lines.push('');

  for (const cred of result.trackedCredentials) {
    lines.push(`[CRITICAL] git-tracked ${cred.label} — ${cred.path}`);
    lines.push('  This file is committed to the repository, so its contents are in git history');
    lines.push('  for anyone with repo access. Remove it from tracking, add it to .gitignore,');
    lines.push('  and rotate any credentials it contains.');
  }

  const sorted = [...result.findings].sort(
    (a, b) => ORDER.indexOf(a.loopSeverity) - ORDER.indexOf(b.loopSeverity)
  );
  for (const f of sorted) {
    lines.push(`[${f.loopSeverity.toUpperCase()}] ${f.code} — ${f.relativePath}:${f.line + 1}`);
    lines.push(`  ${f.message}`);
    lines.push(`  Fix: ${f.suggestion}`);
  }
  return lines.join('\n');
}

export function shipCheckBlocks(result: ShipCheckResult): boolean {
  return (
    !result.complete ||
    result.trackedCredentials.length > 0 ||
    result.findings.some(f => f.loopSeverity === 'critical' || f.loopSeverity === 'high')
  );
}

function printHelp(): void {
  process.stdout.write(
    'caspian ship-check [path]\n' +
    '  --json    emit the result as JSON instead of text\n' +
    '\n' +
    'Pre-deploy check for the mistakes that most often expose AI-built apps:\n' +
    'open Firestore/Supabase rules, RLS disabled, client-exposed secrets,\n' +
    'AI endpoints with no rate limit, leaked provider tokens, and credential\n' +
    'files tracked by git. Not baseline-filtered — pre-existing holes count.\n' +
    '\n' +
    'Exit codes: 0 = nothing blocking, 1 = critical/high findings, 2 = failed\n'
  );
}

export function runShipCheckCli(argv: string[]): void {
  let workspace = process.cwd();
  let json = false;
  for (const a of argv) {
    if (a === '-h' || a === '--help') { printHelp(); process.exit(0); }
    else if (a === '--json') { json = true; }
    else if (a.startsWith('-')) {
      process.stderr.write(`caspian ship-check: unknown flag ${a}\n`);
      printHelp();
      process.exit(2);
    } else { workspace = path.resolve(a); }
  }
  if (!fs.existsSync(workspace)) {
    process.stderr.write(`caspian ship-check: path does not exist: ${workspace}\n`);
    process.exit(2);
  }

  let result: ShipCheckResult;
  try {
    result = runShipCheck(workspace);
  } catch (err: any) {
    process.stderr.write(`caspian ship-check: ${err.message}\n`);
    process.exit(2);
    return;
  }

  if (json) {
    process.stdout.write(JSON.stringify({
      status: !result.complete ? 'incomplete' : shipCheckBlocks(result) ? 'findings' : 'passed',
      filesScanned: result.filesScanned,
      filesSkipped: result.filesSkipped,
      diagnostics: result.diagnostics,
      trackedCredentials: result.trackedCredentials,
      findings: result.findings.map(f => ({
        file: f.relativePath,
        line: f.line + 1,
        severity: f.loopSeverity,
        code: f.code,
        message: f.message,
        fix: f.suggestion,
      })),
    }, null, 2) + '\n');
  } else {
    process.stdout.write(formatShipCheckReport(result) + '\n');
  }
  process.exit(!result.complete ? 2 : shipCheckBlocks(result) ? 1 : 0);
}
