/**
 * `caspian baseline accept [path]` — record the current findings as the
 * accepted baseline at the standard `.caspian/baseline.json` location.
 *
 * Deliberately a CLI-only surface. The agent-loop tools (hooks, MCP)
 * report only findings beyond this baseline, and none of them can WRITE
 * it — an agent that can accept its own findings will accept its own
 * findings. A human runs this, reviews the diff, and commits the file.
 */

import * as fs from 'fs';
import * as path from 'path';
import { runWorkspaceScan } from '../scanRunner';
import { buildBaseline, writeBaseline, DEFAULT_BASELINE_PATH } from '../baseline';
import { loadIgnoreFile, isIgnored } from '../caspianIgnore';
import { resolveToolVersion } from '../sarif';

function printHelp(): void {
  process.stdout.write(
    'caspian baseline accept [path]\n' +
    '\n' +
    `Scans the workspace and writes every current finding to ${DEFAULT_BASELINE_PATH}\n` +
    'as accepted. From then on, agent-loop scans (hooks, security_scan_file,\n' +
    'security_scan_changes) report only NEW findings beyond these counts.\n' +
    'Review and commit the baseline file like any other change.\n' +
    '\n' +
    'Note: `caspian ship-check` ignores the baseline on purpose.\n'
  );
}

export function runBaselineCli(argv: string[]): void {
  const sub = argv[0];
  if (sub === '-h' || sub === '--help' || sub === undefined) {
    printHelp();
    process.exit(sub === undefined ? 2 : 0);
  }
  if (sub !== 'accept') {
    process.stderr.write(`caspian baseline: unknown subcommand "${sub}" (expected: accept)\n`);
    printHelp();
    process.exit(2);
  }

  let workspace = process.cwd();
  for (const a of argv.slice(1)) {
    if (a === '-h' || a === '--help') { printHelp(); process.exit(0); }
    else if (a.startsWith('-')) {
      process.stderr.write(`caspian baseline accept: unknown flag ${a}\n`);
      process.exit(2);
    } else { workspace = path.resolve(a); }
  }
  if (!fs.existsSync(workspace)) {
    process.stderr.write(`caspian baseline accept: path does not exist: ${workspace}\n`);
    process.exit(2);
  }

  const ignoreEntries = loadIgnoreFile(workspace);
  const scan = runWorkspaceScan({ workspace });
  const flat = scan.results.flatMap(r =>
    r.issues
      .filter(i => !isIgnored(ignoreEntries, i.code, r.relativePath, i.line))
      .map(i => ({ ...i, filePath: r.relativePath }))
  );

  const baselinePath = path.join(workspace, DEFAULT_BASELINE_PATH);
  fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
  writeBaseline(baselinePath, buildBaseline(flat, resolveToolVersion()));

  process.stdout.write(
    `caspian baseline: accepted ${flat.length} existing finding(s) across ` +
    `${scan.results.length} file(s) → ${path.relative(workspace, baselinePath)}\n` +
    'Agent-loop scans will now report only NEW findings. Commit this file.\n'
  );
  process.exit(0);
}
