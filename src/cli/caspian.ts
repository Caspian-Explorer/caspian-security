#!/usr/bin/env node
/**
 * Caspian Security — unified `caspian` command.
 *
 * A single entry point that makes Caspian a robust, standalone security tool
 * runnable ANYWHERE — a normal PowerShell / cmd / bash terminal, with or
 * without VS Code — and easy for any AI agent (Claude Code, Cursor,
 * Antigravity, Claude Desktop, Cline) to invoke.
 *
 *   caspian scan [path] [flags]      run the security scanner
 *   caspian git-history [path]       walk git history for leaked secrets
 *   caspian check-updates [path]     npm audit + stack version checks (--osv for OSV.dev)
 *   caspian mcp                      start the MCP server (stdio)
 *   caspian snippet [--agent ...]    print a paste-ready CLAUDE.md / rules block
 *   caspian mcp-config [--client ...] print an MCP client config block
 *   caspian help | --version
 *
 * Install once and use everywhere:
 *   npm install -g caspian-security   →   caspian scan .
 * Or zero-install:
 *   npx -y caspian-security scan .
 *
 * This dispatcher delegates to the same exported entry points the individual
 * bins use (runScanCli, runGitHistoryCli, runCheckUpdatesCli, startMcpServer),
 * so there is one implementation per capability — no duplication. Each
 * delegated subcommand owns its own exit code via process.exit.
 */

import * as fs from 'fs';
import * as path from 'path';
import { runScanCli } from './scan';
import { runScanFileCli } from './scanFileCli';
import { runShipCheckCli } from './shipCheck';
import { runBaselineCli } from './baselineCli';
import { runInitCli } from './init';
import { runGitHistoryCli } from './gitHistoryScan';
import { runCheckUpdatesCli } from './checkUpdates';
import { startMcpServer } from './mcpServer';
import {
  AGENTS,
  MCP_CLIENTS,
  TRIGGERS,
  AgentId,
  McpClientId,
  TriggerMode,
  buildAgentInstructions,
  formatMcpConfigForDisplay,
} from '../integration/agentSnippets';

function resolveVersion(): string {
  try {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')
    );
    return pkg.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function printHelp(): void {
  process.stdout.write(
    `caspian — Caspian Security, runnable anywhere (v${resolveVersion()})\n` +
    '\n' +
    'Usage: caspian <command> [options]\n' +
    '\n' +
    'Commands:\n' +
    '  scan [path]              Run the security scanner (SARIF/JSON/text, exit code gating).\n' +
    '  scan-file <file>         Fast single-file scan with agent-loop semantics\n' +
    '                             (only NEW findings beyond .caspian/baseline.json).\n' +
    '  ship-check [path]        Pre-deploy check: open Firebase/Supabase rules, RLS off,\n' +
    '                             client-exposed secrets, unmetered AI endpoints,\n' +
    '                             git-tracked credential files. Ignores the baseline.\n' +
    '  baseline accept [path]   Accept all current findings into .caspian/baseline.json\n' +
    '                             so agent-loop scans report only NEW findings.\n' +
    '  init [path]              One-command agent setup: merge .mcp.json, write the\n' +
    '                             rules block (CLAUDE.md/AGENTS.md/.cursorrules), baseline.\n' +
    '  git-history [path]       Walk git history for leaked secrets.\n' +
    '  check-updates [path]     npm audit + stack version checks.\n' +
    '                             --osv adds an OSV.dev check of non-npm manifests\n' +
    '                             (requirements.txt, go.mod, Cargo.lock, pom.xml, ...).\n' +
    '  mcp                      Start the Model Context Protocol server (stdio).\n' +
    '  snippet                  Print a paste-ready instruction block for an AI agent.\n' +
    '                             --agent claude|cursor|antigravity|generic (default: claude)\n' +
    '                             --mode  request|after-edits|pre-commit    (default: after-edits)\n' +
    '  mcp-config               Print an MCP server config for a client.\n' +
    '                             --client claude-code|claude-desktop|cursor|antigravity|cline\n' +
    '                             (default: claude-code)\n' +
    '  help                     Show this help.\n' +
    '\n' +
    'Options:\n' +
    '  -v, --version            Print the version.\n' +
    '  -h, --help               Show this help.\n' +
    '\n' +
    'Run a subcommand with --help for its own flags, e.g. `caspian scan --help`.\n' +
    '\n' +
    'Examples:\n' +
    '  caspian scan . --format json --fail-on error\n' +
    '  npx -y caspian-security scan . --changed-since origin/main\n' +
    '  caspian snippet --agent claude --mode after-edits\n' +
    '  caspian mcp-config --client cursor\n'
  );
}

/** Read a `--flag value` option from an argv slice; returns the value or a fallback. */
function readOption(argv: string[], flag: string, fallback: string): string {
  const i = argv.indexOf(flag);
  if (i >= 0 && i + 1 < argv.length) { return argv[i + 1]; }
  return fallback;
}

function runSnippet(argv: string[]): void {
  const agent = readOption(argv, '--agent', 'claude');
  const mode = readOption(argv, '--mode', 'after-edits');
  if (!AGENTS.some(a => a.id === agent)) {
    process.stderr.write(
      `caspian snippet: --agent must be one of ${AGENTS.map(a => a.id).join('|')} (got ${agent})\n`
    );
    process.exit(2);
  }
  if (!TRIGGERS.some(t => t.id === mode)) {
    process.stderr.write(
      `caspian snippet: --mode must be one of ${TRIGGERS.map(t => t.id).join('|')} (got ${mode})\n`
    );
    process.exit(2);
  }
  process.stdout.write(buildAgentInstructions(agent as AgentId, mode as TriggerMode) + '\n');
}

function runMcpConfig(argv: string[]): void {
  const client = readOption(argv, '--client', 'claude-code');
  if (!MCP_CLIENTS.some(c => c.id === client)) {
    process.stderr.write(
      `caspian mcp-config: --client must be one of ${MCP_CLIENTS.map(c => c.id).join('|')} (got ${client})\n`
    );
    process.exit(2);
  }
  process.stdout.write(formatMcpConfigForDisplay(client as McpClientId));
}

export async function runCaspian(argv: string[] = process.argv.slice(2)): Promise<void> {
  // Back-compat: older docs invoked `npx -y caspian-security caspian <sub>`. Now that
  // `caspian-security` is itself a bin (npx resolves it directly by name), that legacy
  // form arrives here with a redundant leading `caspian` token. Strip one so both the
  // new `caspian-security <sub>` and the legacy `caspian-security caspian <sub>` resolve
  // to the same subcommand. No real subcommand is named `caspian`, so this is safe.
  if (argv[0] === 'caspian') { argv = argv.slice(1); }

  const sub = argv[0];
  const rest = argv.slice(1);

  switch (sub) {
    case undefined:
    case 'help':
    case '-h':
    case '--help':
      printHelp();
      process.exit(0);
      break;
    case '-v':
    case '--version':
    case 'version':
      process.stdout.write(resolveVersion() + '\n');
      process.exit(0);
      break;
    case 'scan':
      await runScanCli(rest);
      break;
    case 'scan-file':
      runScanFileCli(rest);
      break;
    case 'ship-check':
      runShipCheckCli(rest);
      break;
    case 'baseline':
      runBaselineCli(rest);
      break;
    case 'init':
      runInitCli(rest);
      break;
    case 'git-history':
    case 'git-history-scan':
      await runGitHistoryCli(rest);
      break;
    case 'check-updates':
      await runCheckUpdatesCli(rest);
      break;
    case 'mcp':
      await startMcpServer();
      break;
    case 'snippet':
      runSnippet(rest);
      process.exit(0);
      break;
    case 'mcp-config':
      runMcpConfig(rest);
      process.exit(0);
      break;
    default:
      process.stderr.write(`caspian: unknown command "${sub}"\n\n`);
      printHelp();
      process.exit(2);
  }
}

if (require.main === module) {
  runCaspian().catch((err: Error) => {
    process.stderr.write(`caspian: fatal — ${err.message}\n`);
    process.exit(2);
  });
}
