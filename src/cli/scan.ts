#!/usr/bin/env node
/**
 * Caspian Security — CLI scanner.
 *
 * Runs the same rule set as the VS Code extension against a workspace, emits
 * SARIF 2.1 (or JSON / plain text), and sets its exit code based on the
 * highest-severity finding. Designed to be dropped into CI — GitHub Actions'
 * `upload-sarif` step can consume the SARIF output directly.
 *
 * Usage:
 *   caspian-scan [path]
 *       --output <file>         default: stdout
 *       --format sarif|json|text  default: sarif
 *       --fail-on error|warning|info|never  default: error
 *       --include <glob,glob>   additional include patterns
 *       --exclude <glob,glob>   additional exclude patterns
 *       --max-file-size <bytes> default: 500000
 *
 * Exit codes:
 *   0  scan ran, no finding at or above the --fail-on threshold
 *   1  scan ran, at least one finding at or above the --fail-on threshold
 *   2  scan failed to run (bad args, I/O error, parse failure)
 *
 * This file deliberately does NOT import `vscode`. The walk and per-file
 * scan loop are imported from ../scanRunner — the same engine the MCP
 * server uses and the extension's analyzer delegates to — so all entry
 * points share one implementation and cannot drift apart.
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from '../rules';
import {
  SecuritySeverity,
  SecurityCategory,
  SEVERITY_LABELS,
  CATEGORY_LABELS,
} from '../types';
import { walkFiles, runWorkspaceScanParallel, FileResult, ScanDiagnostic } from '../scanRunner';
import { formatScanSummary, ScanSummary } from '../scanReport';
import { buildSARIF, resolveToolVersion } from '../sarif';
import { loadBaseline, buildBaseline, writeBaseline, applyBaseline, Baseline } from '../baseline';
import { buildGitComparisonBaseline } from '../gitBaseline';
import { getChangedFilesSince } from '../gitDiff';
import { loadIgnoreFile, isIgnored } from '../caspianIgnore';

// --- CLI argument parsing -------------------------------------------------

export interface CliOptions {
  workspace: string;
  output?: string;
  format: 'sarif' | 'json' | 'text';
  failOn: 'error' | 'warning' | 'info' | 'never';
  include: string[];
  exclude: string[];
  maxFileSize: number;
  baselinePath?: string;
  updateBaseline: boolean;
  changedSince?: string;
  concurrency?: number;
  summaryPath?: string;
  strict?: boolean;
  newOnly?: boolean;
}

export function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    workspace: process.cwd(),
    format: 'sarif',
    failOn: 'error',
    include: [],
    exclude: [],
    maxFileSize: 500_000,
    updateBaseline: false,
  };

  let positionalSeen = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) {
        throw new Error(`${a} requires a value`);
      }
      return v;
    };
    switch (a) {
      case '-h':
      case '--help':
        printHelp();
        process.exit(0);
        break;
      case '-o':
      case '--output':
        opts.output = next();
        break;
      case '--format': {
        const v = next();
        if (v !== 'sarif' && v !== 'json' && v !== 'text') {
          throw new Error(`--format must be sarif|json|text (got ${v})`);
        }
        opts.format = v;
        break;
      }
      case '--fail-on': {
        const v = next();
        if (v !== 'error' && v !== 'warning' && v !== 'info' && v !== 'never') {
          throw new Error(`--fail-on must be error|warning|info|never (got ${v})`);
        }
        opts.failOn = v;
        break;
      }
      case '--new-only':
        opts.newOnly = true;
        break;
      case '--summary':
        opts.summaryPath = next();
        break;
      case '--strict':
        opts.strict = true;
        break;
      case '--include':
        opts.include.push(...next().split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '--exclude':
        opts.exclude.push(...next().split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '--max-file-size':
        opts.maxFileSize = Math.max(0, parseInt(next(), 10) || 0);
        break;
      case '--baseline':
        opts.baselinePath = next();
        break;
      case '--update-baseline':
        opts.updateBaseline = true;
        break;
      case '--changed-since':
        opts.changedSince = next();
        break;
      case '--concurrency': {
        const v = parseInt(next(), 10);
        if (Number.isNaN(v) || v < 1) {
          throw new Error(`--concurrency must be a positive integer (got ${argv[i]})`);
        }
        opts.concurrency = v;
        break;
      }
      default:
        if (a.startsWith('-')) {
          throw new Error(`unknown flag: ${a}`);
        }
        if (positionalSeen) {
          throw new Error(`only one positional workspace path is allowed (got ${a})`);
        }
        opts.workspace = path.resolve(a);
        positionalSeen = true;
    }
  }

  if (opts.newOnly && !opts.changedSince) { throw new Error('--new-only requires --changed-since'); }
  if (opts.newOnly && (opts.baselinePath || opts.updateBaseline)) { throw new Error('--new-only cannot be combined with an accepted baseline'); }
  if (!fs.existsSync(opts.workspace) || !fs.statSync(opts.workspace).isDirectory()) {
    throw new Error(`workspace path does not exist: ${opts.workspace}`);
  }
  return opts;
}

function printHelp(): void {
  process.stdout.write(
    'caspian-scan [path]\n' +
    '  --summary <file>              write a Markdown report for GitHub or local review\n' +
    '  --new-only                    compare findings against the merge base of --changed-since\n' +
    '  --strict                      fail with exit 2 on any incomplete coverage\n' +
    '  --output <file>               write results to file (default: stdout)\n' +
    '  --format sarif|json|text      output format (default: sarif)\n' +
    '  --fail-on error|warning|info|never\n' +
    '                                minimum severity that causes non-zero exit (default: error)\n' +
    '  --include <glob,glob,...>     extra files to scan: globs (*.proto, src/**/*.vue)\n' +
    '                                or plain substrings of the file path\n' +
    '  --exclude <dir,dir,...>       additional directory names to skip\n' +
    '  --max-file-size <bytes>       skip files larger than this (default: 500000)\n' +
    '  --concurrency <n>             worker threads for large scans (default: CPU count;\n' +
    '                                small scans run inline regardless)\n' +
    '  --baseline <file>             suppress findings listed in baseline; only NEW\n' +
    '                                findings not matched by the baseline gate the build\n' +
    '  --update-baseline             regenerate <baseline> to match the current scan,\n' +
    '                                then exit 0. Use after an intentional rule change.\n' +
    '  --changed-since <ref>         only scan files that differ from <ref> in a\n' +
    '                                `<ref>...HEAD` diff. Ideal for PR CI:\n' +
    '                                --changed-since origin/main. Excludes deletions.\n' +
    '\n' +
    'Exit codes: 0 = clean (or baselined), 1 = new findings above threshold, 2 = scan failed\n'
  );
}

// --- Filesystem walk + core scan loop -------------------------------------
// The walk, language resolution, and per-file scan loop live in
// ../scanRunner and are shared with the MCP server, so the CLI and the
// other entry points cannot drift apart.

// --- Output formatters ----------------------------------------------------

function toSARIF(results: FileResult[], toolVersion: string): string {
  return buildSARIF(results, toolVersion);
}

export function toJSONOutput(results: FileResult[], summary?: ScanSummary): string {
  const issues = results.flatMap(r =>
    r.issues.map(issue => ({
      file: r.relativePath,
      line: issue.line + 1,
      column: issue.column + 1,
      severity: SEVERITY_LABELS[issue.severity],
      code: issue.code,
      category: CATEGORY_LABELS[issue.category],
      message: issue.message,
      suggestion: issue.suggestion,
      pattern: issue.category === SecurityCategory.SecretsCredentials ? '[redacted]' : issue.pattern,
      confidence: issue.confidenceLevel,
    }))
  );
  return JSON.stringify({ issues, ...(summary ? { summary } : {}) }, null, 2);
}

export function toText(results: FileResult[]): string {
  const out: string[] = [];
  let total = 0;
  for (const r of results) {
    if (!r.issues.length) { continue; }
    total += r.issues.length;
    out.push(`--- ${r.relativePath} (${r.issues.length} issue(s)) ---`);
    for (const issue of r.issues) {
      out.push(`  [${SEVERITY_LABELS[issue.severity]}] ${issue.code} (Line ${issue.line + 1}): ${issue.message}`);
      out.push(`    Suggestion: ${issue.suggestion}`);
    }
    out.push('');
  }
  out.unshift(`Caspian Security CLI — ${total} finding(s) across ${results.filter(r => r.issues.length).length} file(s)`, '='.repeat(60), '');
  return out.join('\n');
}

// --- Entry point ----------------------------------------------------------

const resolveVersion = resolveToolVersion;

export function worstSeverity(results: FileResult[]): SecuritySeverity | null {
  let worst: SecuritySeverity | null = null;
  for (const r of results) {
    for (const issue of r.issues) {
      if (worst === null || issue.severity > worst) { worst = issue.severity; }
    }
  }
  return worst;
}

export function meetsFailThreshold(worst: SecuritySeverity | null, failOn: CliOptions['failOn']): boolean {
  if (worst === null || failOn === 'never') { return false; }
  const thresholds: Record<Exclude<CliOptions['failOn'], 'never'>, SecuritySeverity> = {
    info: SecuritySeverity.Info,
    warning: SecuritySeverity.Warning,
    error: SecuritySeverity.Error,
  };
  return worst >= thresholds[failOn];
}

export async function runScanCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  let opts: CliOptions;
  try {
    opts = parseArgs(argv);
  } catch (err: any) {
    process.stderr.write(`caspian-scan: ${err.message}\n`);
    printHelp();
    process.exit(2);
  }

  const walkDiagnostics: ScanDiagnostic[] = [];
  let files = walkFiles(opts.workspace, opts.exclude, opts.include, walkDiagnostics);

  // --changed-since: restrict the file set to what differs from the given
  // ref. Resolve before the scan loop so the "scanned N file(s)" counter
  // reflects the PR-scoped universe, not the full repo.
  let changedSinceNote = '';
  if (opts.changedSince) {
    let changed: ReturnType<typeof getChangedFilesSince>;
    try {
      changed = getChangedFilesSince(opts.workspace, opts.changedSince);
    } catch (err: any) {
      process.stderr.write(`caspian-scan: ${err.message}\n`);
      process.exit(2);
      return; // unreachable but TS needs the narrowing
    }
    const before = files.length;
    files = files.filter(f => changed.files.has(f));
    changedSinceNote =
      ` (PR-scope: ${changed.diffCount} changed file(s) vs ${changed.ref}, ` +
      `${files.length}/${before} scannable)`;
  }

  // Scan across worker threads when the file set is large enough to earn
  // back the thread overhead; otherwise this transparently runs inline.
  const scan = await runWorkspaceScanParallel({
    workspace: opts.workspace,
    files,
    maxFileSize: opts.maxFileSize,
    concurrency: opts.concurrency,
  });
  scan.diagnostics.unshift(...walkDiagnostics);
  let results: FileResult[] = scan.results;
  const filesSkipped = scan.filesSkipped;

  // Honour .caspianignore so the CLI agrees with the editor. Historically
  // only the extension applied it, which meant CI re-reported findings the
  // team had already reviewed and dismissed.
  let ignoredCount = 0;
  const ignoreEntries = loadIgnoreFile(opts.workspace);
  if (ignoreEntries.length > 0) {
    results = results
      .map(r => {
        const kept = r.issues.filter(issue => {
          const dropped = isIgnored(ignoreEntries, issue.code, r.relativePath, issue.line);
          if (dropped) { ignoredCount++; }
          return !dropped;
        });
        return { ...r, issues: kept };
      })
      .filter(r => r.issues.length > 0);
  }
  const totalIssues = results.reduce((n, r) => n + r.issues.length, 0);

  // --update-baseline: write the current findings as the new baseline and exit.
  if (opts.updateBaseline) {
    if (scan.diagnostics.length || (!files.length && !opts.changedSince)) {
      throw new Error('Refusing to accept a baseline from an incomplete scan. Review exclusions and coverage first.');
    }
    if (!opts.baselinePath) {
      process.stderr.write('caspian-scan: --update-baseline requires --baseline <file>\n');
      process.exit(2);
    }
    const flat = results.flatMap(r => r.issues.map(i => ({ ...i, filePath: r.relativePath })));
    const fresh = buildBaseline(flat, resolveVersion());
    writeBaseline(opts.baselinePath, fresh);
    process.stderr.write(
      `caspian-scan: wrote baseline with ${totalIssues} suppressed finding(s) to ${opts.baselinePath}\n`
    );
    process.exit(0);
  }

  // Apply baseline if present.
  let newCount = totalIssues;
  let baselinedCount = 0;
  let resultsForOutput = results;
  if (opts.baselinePath || opts.newOnly) {
    let baseline: Baseline;
    try {
      if (opts.newOnly) {
        const comparison = buildGitComparisonBaseline(opts.workspace, opts.changedSince!, files, opts.maxFileSize);
        baseline = comparison.baseline;
        scan.diagnostics.push(...comparison.diagnostics);
      } else { baseline = loadBaseline(opts.baselinePath!); }
    } catch (err: any) {
      process.stderr.write(`caspian-scan: ${err.message}\n`);
      process.exit(2);
    }
    if (baseline.version === 1) { process.stderr.write('caspian-scan: legacy count baseline; refresh it to use finding fingerprints.\n'); }
    const flat = results.flatMap(r => r.issues.map(i => ({ ...i, filePath: r.relativePath })));
    const applied = applyBaseline(flat, baseline);
    baselinedCount = applied.baselined.length;
    newCount = applied.newFindings.length;
    // Rebuild FileResult[] from just the new findings so output formats see
    // only what gates the build.
    const byFile = new Map<string, FileResult>();
    for (const src of results) {
      byFile.set(src.filePath, { ...src, issues: [] });
    }
    for (const n of applied.newFindings) {
      // n.filePath is relativePath; look up the FileResult by relativePath.
      const target = Array.from(byFile.values()).find(r => r.relativePath === n.filePath);
      if (target) { target.issues.push(n); }
    }
    resultsForOutput = Array.from(byFile.values()).filter(r => r.issues.length > 0);
  }

  // Summarise to stderr so piping --format=sarif works.
  const ignoredNote = ignoredCount > 0 ? `, ${ignoredCount} ignored via .caspianignore` : '';
  if (opts.baselinePath || opts.newOnly) {
    process.stderr.write(
      `caspian-scan: scanned ${scan.filesScanned} file(s)${changedSinceNote}, ${filesSkipped} skipped, ` +
      `${totalIssues} finding(s) (${baselinedCount} baselined, ${newCount} new)${ignoredNote}\n`
    );
  } else {
    process.stderr.write(
      `caspian-scan: scanned ${scan.filesScanned} file(s)${changedSinceNote}, ${filesSkipped} skipped, ${totalIssues} finding(s)${ignoredNote}\n`
    );
  }

  const incomplete = scan.diagnostics.length > 0 || (!files.length && !opts.changedSince);
  const summary: ScanSummary = {
    status: incomplete ? 'incomplete' : newCount ? 'findings' : 'passed',
    filesScanned: scan.filesScanned, filesSkipped, findings: newCount,
    baselined: baselinedCount, ignored: ignoredCount, diagnostics: scan.diagnostics,
  };
  if (incomplete) { process.stderr.write('caspian-scan: INCOMPLETE coverage; inspect the summary. Use --strict to reject all coverage gaps.\n'); }
  if (opts.summaryPath) { fs.writeFileSync(opts.summaryPath, formatScanSummary(summary, resultsForOutput), 'utf-8'); }
  let output: string;
  switch (opts.format) {
    case 'json': output = toJSONOutput(resultsForOutput, summary); break;
    case 'text': output = toText(resultsForOutput) + '\nCoverage: ' + summary.status + '\n' + scan.diagnostics.map(d => d.path + ': ' + d.reason).join('\n'); break;
    case 'sarif':
    default: output = toSARIF(resultsForOutput, resolveVersion());
  }

  if (opts.format === 'sarif') {
    const sarif = JSON.parse(output);
    sarif.runs[0].invocations = [{ executionSuccessful: !incomplete,
      toolExecutionNotifications: scan.diagnostics.map(d => ({ level: 'warning', message: { text: d.path + ': ' + d.reason } })),
    }];
    sarif.runs[0].properties = { caspianSummary: summary };
    output = JSON.stringify(sarif, null, 2);
  }
  if (opts.output) {
    fs.writeFileSync(opts.output, output, 'utf-8');
  } else {
    process.stdout.write(output + '\n');
  }

  if ((opts.strict && incomplete) || scan.diagnostics.some(d => ['unreadable', 'timeout', 'analysis-error'].includes(d.reason))) { process.exit(2); }
  process.exit(meetsFailThreshold(worstSeverity(resultsForOutput), opts.failOn) ? 1 : 0);
}

if (require.main === module) {
  runScanCli().catch((err: Error) => {
    process.stderr.write(`caspian-scan: fatal — ${err.message}\n`);
    process.exit(2);
  });
}
