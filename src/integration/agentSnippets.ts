/**
 * Agent-integration snippet + MCP config generators.
 *
 * Single source of truth for the copy-paste text that lets any AI agent
 * (Claude Code, Cursor, Antigravity, Claude Desktop, Cline) discover and run
 * Caspian Security. Imported by BOTH the unified `caspian` CLI
 * (src/cli/caspian.ts) and the VS Code extension (src/extension.ts) so the two
 * surfaces never drift.
 *
 * Design constraint: this module writes NOTHING to any repository. Caspian has
 * no authority over other people's projects — it only *emits* text/config that
 * the user chooses to paste wherever they like, at whatever interval/event they
 * prefer. Accordingly this file has zero dependency on `vscode` or `fs`; it is
 * pure string building, safe to import from the CLI, the extension, and tests.
 */

/** Which agent the plain-language instruction block is phrased for. */
export type AgentId = 'claude' | 'cursor' | 'antigravity' | 'generic';

/** When the user wants the agent to run Caspian. */
export type TriggerMode = 'request' | 'after-edits' | 'pre-commit';

/** MCP client the config snippet targets. */
export type McpClientId = 'claude-code' | 'claude-desktop' | 'cursor' | 'antigravity' | 'cline';

export interface AgentInfo {
  id: AgentId;
  label: string;
  /** Where the user pastes the block for this agent. */
  placement: string;
}

export interface McpClientInfo {
  id: McpClientId;
  label: string;
  /** Where this client's MCP config lives. */
  configPath: string;
  /** Extra guidance (e.g. a one-liner CLI alternative). */
  note: string;
}

export interface TriggerInfo {
  id: TriggerMode;
  label: string;
}

/** The npm package name — the one identifier every invocation flows through. */
export const PACKAGE_NAME = 'caspian-security';

/** Zero-install full-workspace scan. Always correct: it scans the working tree as-is. */
export const SCAN_COMMAND =
  `npx -y ${PACKAGE_NAME} scan . --format json --fail-on error`;

/**
 * PR/pre-commit scan. `--changed-since <base>` diffs `<base>...HEAD`, so it only
 * makes sense against a *committed* base branch — not HEAD (which would be empty).
 */
export const PR_SCAN_COMMAND =
  `npx -y ${PACKAGE_NAME} scan . --changed-since origin/main --format json --fail-on error`;

export const AGENTS: AgentInfo[] = [
  { id: 'claude',      label: 'Claude Code',  placement: 'your project\'s CLAUDE.md' },
  { id: 'cursor',      label: 'Cursor',       placement: 'Cursor Project Rules (or .cursorrules)' },
  { id: 'antigravity', label: 'Antigravity',  placement: 'your Antigravity rules / memory file' },
  { id: 'generic',     label: 'Any AI agent', placement: 'the agent\'s system prompt or rules file' },
];

export const TRIGGERS: TriggerInfo[] = [
  { id: 'request',     label: 'When I ask' },
  { id: 'after-edits', label: 'After editing code' },
  { id: 'pre-commit',  label: 'Before committing' },
];

export const MCP_CLIENTS: McpClientInfo[] = [
  {
    id: 'claude-code',
    label: 'Claude Code',
    configPath: 'a .mcp.json file at your project root',
    note: 'Or run once, no file needed:\n  claude mcp add caspian-security -- npx -y caspian-security mcp',
  },
  {
    id: 'claude-desktop',
    label: 'Claude Desktop',
    configPath: 'Windows: %APPDATA%\\Claude\\claude_desktop_config.json\n' +
      '  macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json',
    note: 'Restart Claude Desktop after saving.',
  },
  {
    id: 'cursor',
    label: 'Cursor',
    configPath: 'Global: ~/.cursor/mcp.json   Project: .cursor/mcp.json',
    note: 'Enable the server in Cursor Settings → MCP after saving.',
  },
  {
    id: 'antigravity',
    label: 'Antigravity',
    configPath: 'Antigravity Settings → MCP / Plugins (mcp_config.json)',
    note: 'Add the block under "mcpServers", then reload the MCP servers.',
  },
  {
    id: 'cline',
    label: 'Cline',
    configPath: 'Cline → MCP Servers → Configure (cline_mcp_settings.json)',
    note: 'Cline reloads MCP servers automatically after saving.',
  },
];

function agentById(id: AgentId): AgentInfo {
  return AGENTS.find(a => a.id === id) ?? AGENTS[AGENTS.length - 1];
}

function triggerSentence(mode: TriggerMode): { sentence: string; command: string } {
  switch (mode) {
    case 'request':
      return { sentence: 'When I ask you to run a security check, run:', command: SCAN_COMMAND };
    case 'pre-commit':
      return {
        sentence: 'Before committing changes, run (scans only what this branch changed):',
        command: PR_SCAN_COMMAND,
      };
    case 'after-edits':
    default:
      return { sentence: 'After you finish editing code in this project, run:', command: SCAN_COMMAND };
  }
}

/**
 * Build the plain-language block the user pastes into their own agent config so
 * that any AI, mid-task, notices the line and runs Caspian. Nothing here is
 * written to disk by us — the user pastes it wherever they want.
 */
export function buildAgentInstructions(agent: AgentId = 'claude', mode: TriggerMode = 'after-edits'): string {
  const info = agentById(agent);
  const { sentence, command } = triggerSentence(mode);
  return [
    `<!-- Paste this into ${info.placement}. Caspian Security runs via npx — no setup needed in this repo. -->`,
    '',
    '## Security scanning — Caspian Security',
    '',
    'Caspian Security is a standalone security scanner (300+ rules: secrets, injection,',
    'SSRF, XSS, JWT/OAuth, deserialization, IaC misconfig for Docker/Terraform/Kubernetes,',
    'and intra-file taint tracking). It needs no configuration in this repository.',
    '',
    sentence,
    '',
    '```bash',
    command,
    '```',
    '',
    'Then read the JSON output and act on it:',
    '',
    '- Fix every finding at `"Error"` severity, then re-run the command to confirm it is clear.',
    '- Summarize any remaining `Warning`/`Info` findings for me.',
    '- Do not consider the task done (or commit) while `Error`-severity findings remain.',
    '',
    'Exit codes: `0` = clean, `1` = findings at/above the threshold, `2` = the scan failed to run.',
    '',
  ].join('\n');
}

/**
 * Idempotency markers for blocks that `caspian init` writes into rules
 * files (CLAUDE.md / AGENTS.md / .cursorrules). Everything between the
 * markers is owned by Caspian and replaced wholesale on re-run; text
 * outside them is never touched.
 */
export const CASPIAN_MARKER_START = '<!-- caspian:start -->';
export const CASPIAN_MARKER_END = '<!-- caspian:end -->';

/**
 * The in-loop rules block for agents driven by MCP tools (the spec's
 * "rules-file snippet"). Distinct from buildAgentInstructions, which
 * predates the agent-loop tools and instructs a CLI-only workflow.
 */
export function buildLoopRulesBlock(agent: AgentId = 'claude'): string {
  const cursorPreamble = agent === 'cursor'
    ? 'Caspian Security MCP tools are available. Treat a scan as part of finishing\n' +
      'a task, not an optional extra step.\n\n'
    : '';
  return [
    CASPIAN_MARKER_START,
    '## Security scanning',
    '',
    `${cursorPreamble}This project uses Caspian Security.`,
    '',
    '- After writing or editing a file that touches auth, user input, database',
    '  queries, file paths, HTTP requests, secrets, env vars, or an AI API,',
    '  call `security_scan_file` on it.',
    '- Before saying a feature is done, and before any commit, push, or deploy,',
    '  call `security_scan_changes`.',
    '- Before a first deploy or after changing database rules, auth, or env',
    '  config, call `check_deployment_security`.',
    '',
    'Fix critical and high findings before continuing. Do not add ignore rules,',
    'suppressions, or baseline entries to silence a finding.',
    '',
    'If the MCP tools are unavailable, run:',
    '`npx -y caspian-security scan . --format json --fail-on error`',
    CASPIAN_MARKER_END,
  ].join('\n');
}

/**
 * Build the MCP server config for a given client. The command shape is identical
 * across every MCP client; only the file location differs.
 */
export function buildMcpConfig(client: McpClientId = 'claude-code'): {
  json: string;
  configPath: string;
  note: string;
  label: string;
} {
  const info = MCP_CLIENTS.find(c => c.id === client) ?? MCP_CLIENTS[0];
  const json = JSON.stringify(
    {
      mcpServers: {
        'caspian-security': {
          command: 'npx',
          args: ['-y', PACKAGE_NAME, 'mcp'],
        },
      },
    },
    null,
    2,
  );
  return { json, configPath: info.configPath, note: info.note, label: info.label };
}

/**
 * Render a full, human-readable MCP setup blob (path header + JSON + note) —
 * used for CLI stdout and for the VS Code "copy" command's clipboard payload.
 */
export function formatMcpConfigForDisplay(client: McpClientId = 'claude-code'): string {
  const { json, configPath, note, label } = buildMcpConfig(client);
  return [
    `# Caspian Security — MCP server config for ${label}`,
    `# Add this to: ${configPath}`,
    '',
    json,
    '',
    `# ${note.replace(/\n/g, '\n# ')}`,
    '#',
    '# Once wired up, the assistant gets seven tools: scan, security_scan_file,',
    '# security_scan_changes, check_deployment_security, scan_git_history, list_rules, explain_rule.',
    '',
  ].join('\n');
}
