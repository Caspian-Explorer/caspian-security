/**
 * `caspian scan-file <path>` — fast single-file scan with agent-loop
 * semantics: only NEW findings (baseline-filtered), .caspianignore and
 * caspian.config.json honoured, findings carry the derived loop severity
 * (critical/high/medium/low).
 *
 * This is the CLI twin of the `security_scan_file` MCP tool and the
 * debugging surface for the PostToolUse hook — all three share
 * scanFileForLoop, so what the hook blocks on is exactly what this
 * command prints.
 *
 * Exit codes: 0 = no blocking findings, 1 = blocking findings, 2 = failed.
 */

import * as fs from 'fs';
import * as path from 'path';
import { createLoopScanContext, isScannablePath, scanFileForLoop } from '../agentLoop/scanForLoop';
import { formatLoopReport, worstLoopSeverity, blocksLoop, LoopFinding } from '../agentLoop/severity';

interface ScanFileOptions {
  file: string;
  workspace: string;
  json: boolean;
}

function printHelp(): void {
  process.stdout.write(
    'caspian scan-file <path>\n' +
    '  --workspace <dir>   project root for baseline/.caspianignore/config lookup\n' +
    '                      (default: current directory)\n' +
    '  --json              emit findings as JSON instead of text\n' +
    '\n' +
    'Scans one file with agent-loop semantics: only findings NOT covered by\n' +
    '.caspian/baseline.json are reported; .caspianignore and caspian.config.json\n' +
    'are honoured. Exit codes: 0 = clean, 1 = blocking findings, 2 = failed.\n'
  );
}

function parseArgs(argv: string[]): ScanFileOptions {
  const opts: ScanFileOptions = { file: '', workspace: process.cwd(), json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h':
      case '--help':
        printHelp();
        process.exit(0);
        break;
      case '--json':
        opts.json = true;
        break;
      case '--workspace': {
        const v = argv[++i];
        if (v === undefined) { throw new Error('--workspace requires a value'); }
        opts.workspace = path.resolve(v);
        break;
      }
      default:
        if (a.startsWith('-')) { throw new Error(`unknown flag: ${a}`); }
        if (opts.file) { throw new Error(`only one file path is allowed (got ${a})`); }
        opts.file = path.resolve(a);
    }
  }
  if (!opts.file) { throw new Error('a file path is required'); }
  if (!fs.existsSync(opts.file)) { throw new Error(`file does not exist: ${opts.file}`); }
  return opts;
}

export function toScanFileJSON(findings: LoopFinding[]): string {
  return JSON.stringify(
    {
      findings: findings.map(f => ({
        file: f.relativePath,
        line: f.line + 1,
        column: f.column + 1,
        severity: f.loopSeverity,
        code: f.code,
        message: f.message,
        fix: f.suggestion,
        confidence: f.confidenceLevel,
      })),
    },
    null,
    2
  );
}

export function runScanFileCli(argv: string[]): void {
  let opts: ScanFileOptions;
  try {
    opts = parseArgs(argv);
  } catch (err: any) {
    process.stderr.write(`caspian scan-file: ${err.message}\n`);
    printHelp();
    process.exit(2);
    return;
  }

  let findings: LoopFinding[];
  const ctx = createLoopScanContext(opts.workspace);
  try {
    if (!isScannablePath(opts.file, ctx)) {
      process.stderr.write('caspian scan-file: file type not scanned (or path ignored by config)\n');
      process.exit(0);
      return;
    }
    findings = scanFileForLoop(opts.file, ctx);
  } catch (err: any) {
    process.stderr.write(`caspian scan-file: ${err.message}\n`);
    process.exit(2);
    return;
  }

  if (opts.json) {
    process.stdout.write(toScanFileJSON(findings) + '\n');
  } else if (findings.length === 0) {
    process.stdout.write('No new findings.\n');
  } else {
    process.stdout.write(formatLoopReport(findings, ctx.config.maxFindingsInLoop) + '\n');
  }

  const blocking = findings.some(f => blocksLoop(f, ctx.config));
  if (blocking) {
    const worst = worstLoopSeverity(findings);
    process.stderr.write(`caspian scan-file: blocking findings present (worst: ${worst})\n`);
  }
  process.exit(blocking ? 1 : 0);
}
