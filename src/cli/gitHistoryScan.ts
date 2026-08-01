#!/usr/bin/env node
/**
 * Caspian Security — git-history secret scanner.
 *
 * Walks every commit reachable from `--all` and runs the provider-prefix
 * secret rules (TOKEN001..TOKEN028) against every ADDED line in every
 * diff. Reports each historical leak with the commit SHA, author, date,
 * file, and line number.
 *
 * Why this matters: `caspian-scan` only sees the current working tree,
 * so a secret that was committed and then "fixed" in a follow-up commit
 * is invisible to normal scans but very much still present in the
 * repository history — and, once pushed, in every clone on earth. The
 * only remediations are (a) rotate the secret at the provider, and
 * (b) rewrite history with BFG or git-filter-repo. This tool tells you
 * *which* secrets need rotating.
 *
 * Usage:
 *   caspian-git-history-scan [path]
 *     --output <file>    write findings to file (default: stdout)
 *     --format json|text default: text
 *     --max-commits <n>  bail out after scanning N commits (default: all)
 *     --rules secrets|all  which rule set to run (default: secrets)
 *
 * Exit codes:
 *   0 no findings
 *   1 at least one finding
 *   2 git not available, not a git repo, or other fatal error
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { SecurityRule, SecuritySeverity, SecurityCategory, SEVERITY_LABELS } from '../types';
import { providerSecretsRules } from '../rules/providerSecretsRules';
import { secretsRules } from '../rules/secretsRules';

interface CliOptions {
  workspace: string;
  output?: string;
  format: 'json' | 'text';
  maxCommits: number; // 0 = unlimited
  rules: 'secrets' | 'all';
}

interface HistoricalFinding {
  commitSha: string;
  author: string;
  date: string;
  filePath: string;
  lineNumber: number;
  ruleCode: string;
  ruleMessage: string;
  severity: string;
  match: string; // the matched token — this file is an alert report, so we preserve the match
}

// --- Argument parsing -----------------------------------------------------

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    workspace: process.cwd(),
    format: 'text',
    maxCommits: 0,
    rules: 'secrets',
  };

  let positionalSeen = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) { throw new Error(`${a} requires a value`); }
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
        if (v !== 'json' && v !== 'text') { throw new Error(`--format must be json|text (got ${v})`); }
        opts.format = v;
        break;
      }
      case '--max-commits':
        opts.maxCommits = Math.max(0, parseInt(next(), 10) || 0);
        break;
      case '--rules': {
        const v = next();
        if (v !== 'secrets' && v !== 'all') { throw new Error(`--rules must be secrets|all (got ${v})`); }
        opts.rules = v;
        break;
      }
      default:
        if (a.startsWith('-')) { throw new Error(`unknown flag: ${a}`); }
        if (positionalSeen) { throw new Error(`only one positional workspace path is allowed (got ${a})`); }
        opts.workspace = path.resolve(a);
        positionalSeen = true;
    }
  }
  if (!fs.existsSync(opts.workspace)) { throw new Error(`workspace path does not exist: ${opts.workspace}`); }
  if (!fs.existsSync(path.join(opts.workspace, '.git'))) {
    throw new Error(`not a git repository (no .git directory): ${opts.workspace}`);
  }
  return opts;
}

function printHelp(): void {
  process.stdout.write(
    'caspian-git-history-scan [path]\n' +
    '  --output <file>         write findings to file (default: stdout)\n' +
    '  --format json|text      output format (default: text)\n' +
    '  --max-commits <n>       stop after N commits (default: no limit)\n' +
    '  --rules secrets|all     rules to run; "secrets" = TOKEN + CRED (default),\n' +
    '                          "all" = every Caspian rule (slow, high false-positive rate\n' +
    '                          against code that historically existed but was then removed)\n' +
    '\n' +
    'Exit codes: 0 = clean, 1 = findings, 2 = git or I/O failure\n'
  );
}

// --- Rule selection -------------------------------------------------------

function collectRules(mode: CliOptions['rules']): SecurityRule[] {
  if (mode === 'secrets') {
    // providerSecretsRules (TOKEN001..) + the Error-severity CRED rules. We
    // omit Info / ProjectAdvisory / Informational rules — they're not secret
    // leaks and would flood the report.
    return [
      ...providerSecretsRules,
      ...secretsRules.filter(r =>
        r.severity !== SecuritySeverity.Info &&
        r.category === SecurityCategory.SecretsCredentials
      ),
    ];
  }
  // `all` mode would pull in every rule, but doing so on historical diffs
  // produces noise (XSS rules firing on code that no longer exists). We
  // keep the option but document the caveat in --help.
  return [
    ...providerSecretsRules,
    ...secretsRules.filter(r => r.severity !== SecuritySeverity.Info),
  ];
}

// --- Git diff streaming parser --------------------------------------------

/**
 * State machine that consumes `git log --all -p --format=...` output one
 * line at a time and emits a finding for every line that starts with `+`
 * and matches one of our secret rules.
 *
 * The `--format` we request injects a sentinel header at the start of
 * each commit so we can correlate findings with commit metadata without
 * having to parse the free-form author line.
 */
// Long, unlikely-to-collide sentinel. Can't use NUL (\u0000) because Node's
// child_process.spawn rejects arguments containing null bytes, and we need
// the sentinel to survive as part of git's --format string.
const HEADER_SENTINEL = '>>>CASPIAN_COMMIT_36e7a1b9<<<';

interface ParserState {
  currentCommit: { sha: string; author: string; date: string } | null;
  currentFile: string | null;
  currentPlusLine: number; // line number in the post-image of the current hunk
}

function scanLine(
  state: ParserState,
  rules: SecurityRule[],
  line: string,
  findings: HistoricalFinding[]
): void {
  // Commit header sentinel: parse metadata and reset.
  if (line.startsWith(HEADER_SENTINEL)) {
    const fields = line.substring(HEADER_SENTINEL.length).split('\u0001');
    if (fields.length >= 3) {
      state.currentCommit = { sha: fields[0], author: fields[1], date: fields[2] };
      state.currentFile = null;
      state.currentPlusLine = 0;
    }
    return;
  }

  if (line.startsWith('diff --git')) {
    const match = line.match(/^diff --git a\/(.+?) b\/(.+)$/);
    state.currentFile = match ? match[2] : null;
    state.currentPlusLine = 0;
    return;
  }

  // Skip context noise that would otherwise be misread as additions.
  if (line.startsWith('+++') || line.startsWith('---')) { return; }
  if (line.startsWith('index ') || line.startsWith('similarity ') || line.startsWith('rename ')) { return; }

  // Hunk header: `@@ -a,b +c,d @@ ...`  — the `+c` is the starting line in
  // the new file, which we use to number the subsequent + lines.
  const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
  if (hunk) {
    state.currentPlusLine = parseInt(hunk[1], 10);
    return;
  }

  if (!state.currentCommit || !state.currentFile) { return; }

  // Added line.
  if (line.startsWith('+')) {
    const content = line.substring(1);
    // Run rules against the content. We inline the minimum of
    // src/cli/scan.ts's logic — no comment / string context awareness,
    // because the diff is already text fragments and context doesn't
    // carry across hunks reliably.
    for (const rule of rules) {
      for (const pattern of rule.patterns) {
        let hit: { index: number; text: string } | null = null;
        try {
          if (typeof pattern === 'string') {
            const idx = content.toLowerCase().indexOf(pattern.toLowerCase());
            if (idx >= 0) { hit = { index: idx, text: pattern }; }
          } else if (pattern instanceof RegExp) {
            const m = pattern.exec(content);
            if (m) { hit = { index: m.index, text: m[0] }; }
          }
        } catch {
          continue;
        }
        if (!hit) { continue; }

        // Honour negativePatterns just like the main scan loop.
        if (rule.negativePatterns) {
          let negated = false;
          for (const neg of rule.negativePatterns) {
            if (typeof neg === 'string') {
              if (content.toLowerCase().includes(neg.toLowerCase())) { negated = true; break; }
            } else if (neg instanceof RegExp) {
              if (neg.test(content)) { negated = true; break; }
            }
          }
          if (negated) { continue; }
        }

        findings.push({
          commitSha: state.currentCommit.sha,
          author: state.currentCommit.author,
          date: state.currentCommit.date,
          filePath: state.currentFile,
          lineNumber: state.currentPlusLine,
          ruleCode: rule.code,
          ruleMessage: rule.message,
          severity: SEVERITY_LABELS[rule.severity],
          match: hit.text,
        });
        break; // one rule per line max
      }
    }
    state.currentPlusLine++;
    return;
  }

  // Context lines and unchanged lines advance the counter; removed (`-`) do not.
  if (line.startsWith(' ')) {
    state.currentPlusLine++;
  }
}

async function runGitLog(
  workspace: string,
  rules: SecurityRule[],
  maxCommits: number,
): Promise<HistoricalFinding[]> {
  return new Promise((resolve, reject) => {
    const findings: HistoricalFinding[] = [];
    const state: ParserState = { currentCommit: null, currentFile: null, currentPlusLine: 0 };

    const args = [
      'log',
      '--all',
      '--full-history',
      '--format=' + HEADER_SENTINEL + '%H\u0001%an <%ae>\u0001%aI',
      '-p',
      '--no-color',
      '-U0', // zero context — smaller output, faster
    ];
    if (maxCommits > 0) { args.push(`-n${maxCommits}`); }

    const proc = spawn('git', args, { cwd: workspace });
    let buf = '';
    let commitsSeen = 0;

    proc.stdout.setEncoding('utf-8');
    proc.stdout.on('data', (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) !== -1) {
        // Strip the CR of a CRLF pair: diff lines from a Windows checkout
        // otherwise carry a trailing '\r' that defeats `$`-anchored
        // secret patterns.
        let line = buf.substring(0, nl);
        if (line.endsWith('\r')) { line = line.slice(0, -1); }
        buf = buf.substring(nl + 1);
        if (line.startsWith(HEADER_SENTINEL)) { commitsSeen++; }
        scanLine(state, rules, line, findings);
      }
    });

    proc.stdout.on('end', () => {
      if (buf.length > 0) { scanLine(state, rules, buf, findings); }
    });

    proc.stderr.on('data', (chunk: Buffer) => {
      process.stderr.write(chunk.toString());
    });

    proc.on('error', (err) => {
      reject(new Error(`failed to spawn git: ${err.message}`));
    });

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`git log exited with code ${code}`));
        return;
      }
      process.stderr.write(`caspian-git-history-scan: scanned ${commitsSeen} commit(s), ${findings.length} finding(s)\n`);
      resolve(findings);
    });
  });
}

// --- Output ---------------------------------------------------------------

function formatText(findings: HistoricalFinding[]): string {
  if (findings.length === 0) { return 'caspian-git-history-scan: no secret leaks found in history.\n'; }
  const out: string[] = [];
  out.push(`Caspian Git-History Secret Scanner — ${findings.length} finding(s)`);
  out.push('='.repeat(72));
  out.push('');

  // Group by commit so reports read like a fix list.
  const byCommit = new Map<string, HistoricalFinding[]>();
  for (const f of findings) {
    if (!byCommit.has(f.commitSha)) { byCommit.set(f.commitSha, []); }
    byCommit.get(f.commitSha)!.push(f);
  }

  for (const [sha, group] of byCommit) {
    const first = group[0];
    out.push(`commit ${sha.substring(0, 12)} — ${first.author} — ${first.date}`);
    for (const f of group) {
      out.push(`  [${f.severity}] ${f.ruleCode}  ${f.filePath}:${f.lineNumber}`);
      out.push(`    ${f.ruleMessage}`);
      out.push(`    match: ${f.match.length > 80 ? f.match.substring(0, 77) + '...' : f.match}`);
    }
    out.push('');
  }

  out.push(
    'Next steps:\n' +
    '  1. Rotate every matched secret at the issuing provider NOW — even if the\n' +
    '     commit has been "fixed" in a later revision, the secret is still in history\n' +
    '     and in every clone / mirror / fork of this repository.\n' +
    '  2. Once rotated, remove the commit from history with `git filter-repo` or BFG,\n' +
    '     then force-push and require all collaborators to re-clone.\n' +
    '  3. Add Caspian\'s GitHub Action to PR CI so future leaks are blocked at review.\n'
  );
  return out.join('\n');
}

function formatJSON(findings: HistoricalFinding[]): string {
  return JSON.stringify({ version: 1, findings }, null, 2);
}

// --- Entry point ----------------------------------------------------------

export async function runGitHistoryCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  let opts: CliOptions;
  try {
    opts = parseArgs(argv);
  } catch (err: any) {
    process.stderr.write(`caspian-git-history-scan: ${err.message}\n`);
    printHelp();
    process.exit(2);
  }

  const rules = collectRules(opts.rules);

  let findings: HistoricalFinding[];
  try {
    findings = await runGitLog(opts.workspace, rules, opts.maxCommits);
  } catch (err: any) {
    process.stderr.write(`caspian-git-history-scan: ${err.message}\n`);
    process.exit(2);
  }

  const output = opts.format === 'json' ? formatJSON(findings) : formatText(findings);
  if (opts.output) {
    fs.writeFileSync(opts.output, output, 'utf-8');
  } else {
    process.stdout.write(output + (output.endsWith('\n') ? '' : '\n'));
  }

  process.exit(findings.length > 0 ? 1 : 0);
}

if (require.main === module) {
  runGitHistoryCli().catch((err: Error) => {
    process.stderr.write(`caspian-git-history-scan: fatal — ${err.message}\n`);
    process.exit(2);
  });
}
