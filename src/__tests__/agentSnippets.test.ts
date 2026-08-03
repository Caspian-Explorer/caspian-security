/**
 * Agent-integration generator tests.
 *
 * These are the single source of truth for the copy-paste text used by both
 * the `caspian` CLI and the VS Code extension, so we lock the contract: every
 * agent/client variant renders, the emitted MCP config is valid JSON, and the
 * scan command matches the trigger mode.
 */

import {
  AGENTS,
  MCP_CLIENTS,
  TRIGGERS,
  SCAN_COMMAND,
  PR_SCAN_COMMAND,
  buildAgentInstructions,
  buildMcpConfig,
  formatMcpConfigForDisplay,
} from '../integration/agentSnippets';

describe('buildAgentInstructions', () => {
  it('renders a block for every agent, mentioning Caspian and the scan command', () => {
    for (const agent of AGENTS) {
      const block = buildAgentInstructions(agent.id, 'after-edits');
      expect(block).toContain('Caspian Security');
      expect(block).toContain(SCAN_COMMAND);
      // Placement note tells the user where to paste it.
      expect(block).toContain(agent.placement);
    }
  });

  it('uses the PR/changed-since command only for pre-commit mode', () => {
    const preCommit = buildAgentInstructions('claude', 'pre-commit');
    expect(preCommit).toContain(PR_SCAN_COMMAND);
    expect(preCommit).toContain('--changed-since origin/main');

    for (const mode of ['request', 'after-edits'] as const) {
      const block = buildAgentInstructions('claude', mode);
      expect(block).toContain(SCAN_COMMAND);
      expect(block).not.toContain('--changed-since');
    }
  });

  it('instructs the agent to fix Error-severity findings and re-run', () => {
    const block = buildAgentInstructions();
    expect(block).toMatch(/Error/);
    expect(block).toContain('re-run');
    expect(block).toContain('Exit codes');
  });

  it('defaults to claude / after-edits', () => {
    expect(buildAgentInstructions()).toEqual(buildAgentInstructions('claude', 'after-edits'));
  });
});

describe('buildMcpConfig', () => {
  it('emits valid JSON with the npx mcp command for every client', () => {
    for (const client of MCP_CLIENTS) {
      const { json, configPath, label } = buildMcpConfig(client.id);
      expect(label).toBe(client.label);
      expect(configPath).toBe(client.configPath);
      const parsed = JSON.parse(json);
      const server = parsed.mcpServers['caspian-security'];
      expect(server.command).toBe('npx');
      expect(server.args).toEqual(['-y', 'caspian-security', 'mcp']);
    }
  });

  it('defaults to claude-code', () => {
    expect(buildMcpConfig().label).toBe('Claude Code');
  });
});

describe('formatMcpConfigForDisplay', () => {
  it('includes the target path, valid JSON, and the current tool names', () => {
    const blob = formatMcpConfigForDisplay('cursor');
    expect(blob).toContain('.cursor/mcp.json');
    expect(blob).toContain('"mcpServers"');
    expect(blob).toContain('seven tools: scan, security_scan_file,');
    expect(blob).toContain('security_scan_changes, check_deployment_security, scan_git_history, list_rules, explain_rule');
    // The JSON block within the blob must still parse.
    const start = blob.indexOf('{');
    const end = blob.lastIndexOf('}');
    expect(() => JSON.parse(blob.slice(start, end + 1))).not.toThrow();
  });
});

describe('registries', () => {
  it('expose stable ids', () => {
    expect(AGENTS.map(a => a.id)).toEqual(['claude', 'cursor', 'antigravity', 'generic']);
    expect(TRIGGERS.map(t => t.id)).toEqual(['request', 'after-edits', 'pre-commit']);
    expect(MCP_CLIENTS.map(c => c.id)).toEqual(
      ['claude-code', 'claude-desktop', 'cursor', 'antigravity', 'cline']
    );
  });
});
