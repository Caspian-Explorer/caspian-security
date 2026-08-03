#!/usr/bin/env node
/**
 * Caspian Security — Model Context Protocol server.
 *
 * Exposes Caspian's scanning capabilities as MCP tools so any MCP
 * client (Claude Desktop, Cursor, Zed AI, cline.bot, etc.) can call
 * them directly from tool use. One stdio-based server process per
 * client — started by the client as a subprocess.
 *
 * Tools:
 *   scan                      Scan a workspace path, return findings (JSON).
 *   security_scan_file        Agent-loop scan of ONE file (only NEW findings).
 *   security_scan_changes     Agent-loop scan of the changed set (only NEW findings).
 *   check_deployment_security Pre-deploy config check (rules files, RLS, exposed env).
 *   scan_git_history          Walk git history for leaked secrets.
 *   list_rules                Enumerate all rule codes / categories / severities.
 *   explain_rule              Full description + suggestion for a rule code.
 *
 * Deliberately absent: any tool that suppresses findings, accepts a
 * baseline, or edits scanner config. The agent must not be able to turn
 * the scanner off; a human runs `caspian baseline accept` / edits config.
 *
 * Transport: stdio (standard for local MCP servers). Clients spawn this
 * bin from their config:
 *
 *   // Claude Desktop claude_desktop_config.json
 *   {
 *     "mcpServers": {
 *       "caspian-security": {
 *         "command": "npx",
 *         "args": ["-y", "caspian-security", "caspian-mcp"]
 *       }
 *     }
 *   }
 *
 * The server has no network access, no telemetry, and no persistent
 * state — it's a thin wrapper over the same scanRunner the CLI uses.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { runWorkspaceScan } from '../scanRunner';
import { getAllRules, getRuleByCode } from '../rules';
import { CATEGORY_LABELS, SEVERITY_LABELS } from '../types';
import { loadIgnoreFile, isIgnored } from '../caspianIgnore';
import { createLoopScanContext, isScannablePath, scanFileForLoop, scanFilesForLoop } from '../agentLoop/scanForLoop';
import { formatLoopReport, LoopFinding } from '../agentLoop/severity';
import { getWorkingTreeChanges } from '../gitWorkingTree';
import { getChangedFilesSince } from '../gitDiff';
import { runShipCheck, formatShipCheckReport, shipCheckBlocks } from './shipCheck';
import { FIX_REGISTRY } from '../codeActions/fixes';

// --- Tool definitions -----------------------------------------------------

const TOOLS = [
  {
    name: 'scan',
    description:
      'Run Caspian Security against a workspace path. Returns findings grouped by file, ' +
      'including line/column, rule code, category, severity, message, and suggested fix. ' +
      'Use this when the user asks to check code for security issues, audit a repo, or find vulnerabilities.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the workspace / directory to scan. Must exist and be readable.',
        },
        include: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional file-path substrings to force-include beyond the default file types.',
        },
        exclude: {
          type: 'array',
          items: { type: 'string' },
          description: 'Directory basenames to skip (added to node_modules/.git/dist/build/out/coverage defaults).',
        },
        severity: {
          type: 'string',
          enum: ['error', 'warning', 'info'],
          description: 'Minimum severity to include in the response (default: info — all findings).',
        },
        max_findings: {
          type: 'integer',
          description: 'Truncate the response to this many findings (default: 200). Full counts are still reported in the summary.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'security_scan_file',
    description:
      'Scans one source file for security vulnerabilities and returns each finding with its impact ' +
      'and a suggested fix. Call this immediately after writing or editing any file that touches ' +
      'authentication, user input, database queries, file paths, HTTP requests, secrets, environment ' +
      'variables, or an AI/LLM API. Only NEW findings are reported — pre-existing, baselined issues ' +
      'are excluded. Returns an empty list in under a second when the file is clean, so there is no ' +
      'cost to checking.',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: 'Path to the file to scan (absolute, or relative to the project root).',
        },
        project_root: {
          type: 'string',
          description: 'Project root for baseline/config lookup. Defaults to the git root above the file, else the current directory.',
        },
      },
      required: ['file_path'],
    },
  },
  {
    name: 'security_scan_changes',
    description:
      'Scans every file changed in the working tree (staged, unstaged, and untracked) and returns ' +
      'only the security issues those changes introduced, ignoring pre-existing ones. Call this ' +
      'before telling the user a feature is finished, before running git commit, and before any ' +
      'push. Use this rather than scanning files one at a time when several files have changed. ' +
      'Pass `base` (e.g. "origin/main") to also include files this branch changed in earlier commits.',
    inputSchema: {
      type: 'object',
      properties: {
        base: {
          type: 'string',
          description: 'Optional git ref: also scan files changed since `base...HEAD` (e.g. "origin/main").',
        },
        project_root: {
          type: 'string',
          description: 'Repository root. Defaults to the current directory.',
        },
      },
    },
  },
  {
    name: 'check_deployment_security',
    description:
      'Inspects deployment and platform configuration for the mistakes that most often expose ' +
      'AI-built apps: Firestore or Supabase rules that allow public read/write, row-level security ' +
      'left disabled, secrets exposed through client-visible environment variables (NEXT_PUBLIC_, ' +
      'VITE_, …), AI/LLM endpoints with no rate limit, leaked provider tokens, and credential files ' +
      'committed to the repo. Call this before any deploy, publish, or release step, when setting ' +
      'up a database or auth for the first time, and whenever the user asks whether their app is ' +
      'safe to launch. Pre-existing issues ARE included — this is the launch gate.',
    inputSchema: {
      type: 'object',
      properties: {
        project_root: {
          type: 'string',
          description: 'Project root to inspect. Defaults to the current directory.',
        },
      },
    },
  },
  {
    name: 'scan_git_history',
    description:
      'Walk the full git history of a repository and flag any secret-shaped string added in any commit. ' +
      'Reports commit SHA, author, date, file, and line. Use this after onboarding a repo to surface credentials ' +
      'that may have leaked historically, even if "fixed" in a later commit.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to a git repository (must contain a .git directory).',
        },
        max_commits: {
          type: 'integer',
          description: 'Stop after N commits (default: all). Useful for very old repos.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'list_rules',
    description:
      'Enumerate every rule Caspian knows about. Returns rule code, category, severity, and one-line message. ' +
      'Use this for discovery / filtering before a scan.',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          description: 'Optional category filter (e.g. "Authentication & Access Control").',
        },
      },
    },
  },
  {
    name: 'explain_rule',
    description:
      'Return the full description and suggested remediation for a given rule code (e.g. "SSRF001", "TAINT003"). ' +
      'Use this when the user asks "what does rule X mean" or wants a remediation reference.',
    inputSchema: {
      type: 'object',
      properties: {
        code: {
          type: 'string',
          description: 'The rule code (e.g. "TAINT001", "DOCKER003", "K8S001").',
        },
      },
      required: ['code'],
    },
  },
];

// --- Tool handlers --------------------------------------------------------

interface ToolResponse {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

function toolError(msg: string): ToolResponse {
  return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
}

function toolText(body: unknown): ToolResponse {
  const text = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
  return { content: [{ type: 'text', text }] };
}

function validatePath(p: unknown): string {
  if (typeof p !== 'string' || !p) { throw new Error('`path` must be a non-empty string'); }
  const abs = path.resolve(p);
  if (!fs.existsSync(abs)) { throw new Error(`path does not exist: ${abs}`); }
  if (!fs.statSync(abs).isDirectory()) { throw new Error(`path is not a directory: ${abs}`); }
  return abs;
}

export function handleScan(args: any): ToolResponse {
  let workspace: string;
  try { workspace = validatePath(args?.path); } catch (err: any) { return toolError(err.message); }

  const minSev = args?.severity || 'info';
  const sevThreshold = minSev === 'error' ? 2 : minSev === 'warning' ? 1 : 0;
  const maxFindings = typeof args?.max_findings === 'number' ? args.max_findings : 200;

  const result = runWorkspaceScan({
    workspace,
    include: Array.isArray(args?.include) ? args.include : [],
    exclude: Array.isArray(args?.exclude) ? args.exclude : [],
  });

  // Flatten + filter. .caspianignore is honoured so the MCP surface agrees
  // with the editor and the CLI.
  const ignoreEntries = loadIgnoreFile(workspace);
  const flat = result.results.flatMap(r =>
    r.issues
      .filter(i => i.severity >= sevThreshold)
      .filter(i => !isIgnored(ignoreEntries, i.code, r.relativePath, i.line))
      .map(i => ({
        file: r.relativePath.replace(/\\/g, '/'),
        line: i.line + 1,
        column: i.column + 1,
        severity: SEVERITY_LABELS[i.severity],
        code: i.code,
        category: CATEGORY_LABELS[i.category] || i.category,
        message: i.message,
        suggestion: i.suggestion,
      }))
  );

  const truncated = flat.slice(0, maxFindings);

  // Category histogram for the summary.
  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const f of flat) {
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  return toolText({
    summary: {
      files_scanned: result.filesScanned,
      files_skipped: result.filesSkipped,
      total_findings: flat.length,
      returned: truncated.length,
      truncated: flat.length > truncated.length,
      by_severity: bySeverity,
      by_category: byCategory,
    },
    findings: truncated,
  });
}

/**
 * Best-effort project root for a file: nearest ancestor with .git,
 * caspian.config.json, or .caspian/ — else the server's cwd (MCP clients
 * spawn this server at the project root).
 */
function resolveProjectRoot(filePath: string): string {
  let dir = path.dirname(filePath);
  for (let depth = 0; depth < 50; depth++) {
    if (
      fs.existsSync(path.join(dir, '.git')) ||
      fs.existsSync(path.join(dir, 'caspian.config.json')) ||
      fs.existsSync(path.join(dir, '.caspian'))
    ) { return dir; }
    const parent = path.dirname(dir);
    if (parent === dir) { break; }
    dir = parent;
  }
  return process.cwd();
}

function loopFindingsPayload(findings: LoopFinding[], maxInReport: number) {
  return {
    report: findings.length === 0 ? 'No new security findings.' : formatLoopReport(findings, maxInReport),
    findings: findings.map(f => ({
      file: f.relativePath,
      line: f.line + 1,
      column: f.column + 1,
      severity: f.loopSeverity,
      code: f.code,
      message: f.message,
      fix: f.suggestion,
      has_mechanical_fix: !!FIX_REGISTRY[f.code],
    })),
  };
}

export function handleSecurityScanFile(args: any): ToolResponse {
  const raw = args?.file_path;
  if (typeof raw !== 'string' || !raw) {
    return toolError('`file_path` must be a non-empty string');
  }
  const filePath = path.resolve(raw);
  if (!fs.existsSync(filePath)) { return toolError(`file does not exist: ${filePath}`); }
  if (!fs.statSync(filePath).isFile()) { return toolError(`not a file: ${filePath}`); }

  const root = typeof args?.project_root === 'string' && args.project_root
    ? path.resolve(args.project_root)
    : resolveProjectRoot(filePath);

  const ctx = createLoopScanContext(root);
  if (!isScannablePath(filePath, ctx)) {
    return toolText({ report: 'File type not scanned (or path ignored by config). No findings.', findings: [] });
  }
  try {
    const findings = scanFileForLoop(filePath, ctx);
    return toolText(loopFindingsPayload(findings, ctx.config.maxFindingsInLoop));
  } catch (err: any) {
    return toolError(`scan failed: ${err.message}`);
  }
}

export function handleSecurityScanChanges(args: any): ToolResponse {
  const root = typeof args?.project_root === 'string' && args.project_root
    ? path.resolve(args.project_root)
    : process.cwd();
  if (!fs.existsSync(root)) { return toolError(`project root does not exist: ${root}`); }

  const files = new Set<string>();
  try {
    for (const f of getWorkingTreeChanges(root).files) { files.add(f); }
  } catch (err: any) {
    return toolError(`could not resolve changed files: ${err.message}`);
  }
  if (typeof args?.base === 'string' && args.base) {
    try {
      for (const f of getChangedFilesSince(root, args.base).files) { files.add(f); }
    } catch (err: any) {
      return toolError(`could not diff against base '${args.base}': ${err.message}`);
    }
  }

  const ctx = createLoopScanContext(root);
  const findings = scanFilesForLoop(files, ctx);
  return toolText({
    changed_files: files.size,
    ...loopFindingsPayload(findings, ctx.config.maxFindingsInLoop),
  });
}

export function handleCheckDeploymentSecurity(args: any): ToolResponse {
  const root = typeof args?.project_root === 'string' && args.project_root
    ? path.resolve(args.project_root)
    : process.cwd();
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return toolError(`project root is not a directory: ${root}`);
  }
  try {
    const result = runShipCheck(root);
    return toolText({
      report: formatShipCheckReport(result),
      blocking: shipCheckBlocks(result),
      tracked_credential_files: result.trackedCredentials,
      findings: result.findings.map(f => ({
        file: f.relativePath,
        line: f.line + 1,
        severity: f.loopSeverity,
        code: f.code,
        message: f.message,
        fix: f.suggestion,
      })),
    });
  } catch (err: any) {
    return toolError(`deployment check failed: ${err.message}`);
  }
}

export function handleGitHistoryScan(args: any): ToolResponse {
  let workspace: string;
  try { workspace = validatePath(args?.path); } catch (err: any) { return toolError(err.message); }
  if (!fs.existsSync(path.join(workspace, '.git'))) {
    return toolError(`not a git repository (no .git at ${workspace})`);
  }

  // Shell out to the existing gitHistoryScan CLI in JSON mode. Cheaper than
  // duplicating its stream-parsing state machine here; the CLI is already
  // battle-tested.
  const cliPath = path.join(__dirname, 'gitHistoryScan.js');
  const cmdArgs = [cliPath, workspace, '--format', 'json', '--rules', 'secrets'];
  if (typeof args?.max_commits === 'number' && args.max_commits > 0) {
    cmdArgs.push('--max-commits', String(args.max_commits));
  }

  const result = spawnSync('node', cmdArgs, {
    encoding: 'utf-8',
    maxBuffer: 200 * 1024 * 1024,
  });
  if (result.error) { return toolError(`failed to spawn git-history scan: ${result.error.message}`); }
  if (result.status === 2) {
    return toolError(`git-history scan failed: ${(result.stderr || '').trim()}`);
  }
  try {
    const parsed = JSON.parse(result.stdout);
    return toolText(parsed);
  } catch (err: any) {
    return toolError(`could not parse scan output: ${err.message}`);
  }
}

export function handleListRules(args: any): ToolResponse {
  const rules = getAllRules();
  const filter = typeof args?.category === 'string' ? args.category.toLowerCase() : '';
  const filtered = rules.filter(r => {
    if (!filter) { return true; }
    const label = (CATEGORY_LABELS[r.category] || r.category).toLowerCase();
    return label.includes(filter);
  });
  const summary = filtered.map(r => ({
    code: r.code,
    category: CATEGORY_LABELS[r.category] || r.category,
    severity: SEVERITY_LABELS[r.severity],
    rule_type: r.ruleType,
    message: r.message,
  }));
  return toolText({
    count: summary.length,
    total_available: rules.length,
    rules: summary,
  });
}

export function handleExplainRule(args: any): ToolResponse {
  const code = typeof args?.code === 'string' ? args.code : '';
  if (!code) { return toolError('`code` must be a non-empty string (e.g. "SSRF001")'); }
  const rule = getRuleByCode(code);
  if (!rule) { return toolError(`unknown rule code: ${code}`); }
  return toolText({
    code: rule.code,
    category: CATEGORY_LABELS[rule.category] || rule.category,
    severity: SEVERITY_LABELS[rule.severity],
    rule_type: rule.ruleType,
    message: rule.message,
    suggestion: rule.suggestion,
    has_mechanical_fix: !!FIX_REGISTRY[rule.code],
    context_aware: rule.contextAware === true,
    file_patterns: rule.filePatterns
      ? {
          include: rule.filePatterns.include?.map(r => r.source),
          exclude: rule.filePatterns.exclude?.map(r => r.source),
        }
      : undefined,
  });
}

export function dispatchTool(name: string, args: unknown): ToolResponse {
  switch (name) {
    case 'scan': return handleScan(args);
    case 'security_scan_file': return handleSecurityScanFile(args);
    case 'security_scan_changes': return handleSecurityScanChanges(args);
    case 'check_deployment_security': return handleCheckDeploymentSecurity(args);
    case 'scan_git_history': return handleGitHistoryScan(args);
    case 'list_rules': return handleListRules(args);
    case 'explain_rule': return handleExplainRule(args);
    default:
      return toolError(`unknown tool: ${name}`);
  }
}

// --- Server bootstrap -----------------------------------------------------

export async function startMcpServer(): Promise<void> {
  const pkg = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')
  );
  const server = new Server(
    { name: 'caspian-security', version: pkg.version || '0.0.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (req: any) => {
    const name: string = req.params?.name;
    const args: unknown = req.params?.arguments;
    try {
      return dispatchTool(name, args) as any;
    } catch (err: any) {
      return toolError(err?.message || 'internal error') as any;
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Server is now live on stdio. MCP clients speak JSON-RPC over it.
}

if (require.main === module) {
  startMcpServer().catch((err: Error) => {
    process.stderr.write(`caspian-mcp: fatal — ${err.message}\n`);
    process.exit(1);
  });
}
