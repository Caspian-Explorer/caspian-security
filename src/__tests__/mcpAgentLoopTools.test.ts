/**
 * Tests for the agent-loop MCP tools (security_scan_file,
 * security_scan_changes, check_deployment_security), following the same
 * direct-handler pattern as mcpServer.test.ts.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import {
  handleSecurityScanFile,
  handleSecurityScanChanges,
  handleCheckDeploymentSecurity,
  handleExplainRule,
  dispatchTool,
} from '../cli/mcpServer';
import { scanFile } from '../scanRunner';
import { getAllRules } from '../rules';
import { DEFAULT_BASELINE_PATH, buildBaseline, writeBaseline } from '../baseline';

function parseText(resp: { content: Array<{ type: string; text: string }> }): any {
  const first = resp.content[0];
  expect(first?.type).toBe('text');
  return JSON.parse(first.text);
}

let tmpRoot: string;
beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-mcp-'));
  // A marker so resolveProjectRoot treats tmpRoot as the project root.
  fs.mkdirSync(path.join(tmpRoot, '.caspian'), { recursive: true });
});
afterEach(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function git(...args: string[]): void {
  execFileSync('git', ['-C', tmpRoot, ...args], { stdio: 'ignore' });
}

describe('MCP tool: security_scan_file', () => {
  it('reports a critical finding for an open rules file', () => {
    const file = path.join(tmpRoot, 'firestore.rules');
    fs.writeFileSync(file, 'allow read, write: if true;\n');
    const body = parseText(handleSecurityScanFile({ file_path: file, project_root: tmpRoot }));
    expect(body.findings.map((f: any) => f.code)).toContain('DEPLOY001');
    expect(body.findings[0].severity).toBe('critical');
    expect(body.report).toContain('DEPLOY001');
    expect(body.findings[0].line).toBe(1); // 1-based
  });

  it('excludes baselined findings', () => {
    const file = path.join(tmpRoot, 'firestore.rules');
    fs.writeFileSync(file, 'allow read, write: if true;\n');
    writeBaseline(
      path.join(tmpRoot, DEFAULT_BASELINE_PATH),
      buildBaseline(
        scanFile(path.join(tmpRoot, 'firestore.rules'), 'allow read, write: if true;\n', getAllRules()).map(i => ({ ...i, filePath: 'firestore.rules' })),
        'test'
      )
    );
    const body = parseText(handleSecurityScanFile({ file_path: file, project_root: tmpRoot }));
    expect(body.findings).toEqual([]);
    expect(body.report).toBe('No new security findings.');
  });

  it('handles unscannable file types and bad input gracefully', () => {
    const md = path.join(tmpRoot, 'notes.md');
    fs.writeFileSync(md, '# hi');
    const body = parseText(handleSecurityScanFile({ file_path: md, project_root: tmpRoot }));
    expect(body.findings).toEqual([]);

    expect((handleSecurityScanFile({}) as any).isError).toBe(true);
    expect((handleSecurityScanFile({ file_path: path.join(tmpRoot, 'nope.ts') }) as any).isError).toBe(true);
  });
});

describe('MCP tool: security_scan_changes', () => {
  it('scans working-tree changes and only reports new findings', () => {
    git('init');
    git('config', 'user.email', 't@t.invalid');
    git('config', 'user.name', 't');
    fs.writeFileSync(path.join(tmpRoot, 'clean.ts'), 'export const a = 1;\n');
    git('add', '.');
    git('commit', '-m', 'init');

    // Agent writes a new vulnerable file, uncommitted.
    fs.writeFileSync(path.join(tmpRoot, 'firestore.rules'), 'allow write: if true;\n');

    const body = parseText(handleSecurityScanChanges({ project_root: tmpRoot }));
    expect(body.changed_files).toBeGreaterThanOrEqual(1);
    expect(body.findings.map((f: any) => f.code)).toContain('DEPLOY001');
  });

  it('errors cleanly outside a git repository', () => {
    const resp = handleSecurityScanChanges({ project_root: tmpRoot });
    expect((resp as any).isError).toBe(true);
  });
});

describe('MCP tool: check_deployment_security', () => {
  it('reports open rules regardless of baseline and flags blocking', () => {
    fs.writeFileSync(path.join(tmpRoot, 'firestore.rules'), 'allow read, write: if true;\n');
    // Baseline it — ship-check must STILL report it.
    writeBaseline(
      path.join(tmpRoot, DEFAULT_BASELINE_PATH),
      buildBaseline(
        scanFile(path.join(tmpRoot, 'firestore.rules'), 'allow read, write: if true;\n', getAllRules()).map(i => ({ ...i, filePath: 'firestore.rules' })),
        'test'
      )
    );
    const body = parseText(handleCheckDeploymentSecurity({ project_root: tmpRoot }));
    expect(body.blocking).toBe(true);
    expect(body.findings.map((f: any) => f.code)).toContain('DEPLOY001');
    expect(body.report).toContain('DEPLOY001');
  });

  it('reports limited completed coverage on a clean project', () => {
    fs.writeFileSync(path.join(tmpRoot, 'app.ts'), 'export const a = 1;\n');
    const body = parseText(handleCheckDeploymentSecurity({ project_root: tmpRoot }));
    expect(body.blocking).toBe(false);
    expect(body.findings).toEqual([]);
    expect(body.report).toContain('No blocking findings in completed checks');
  });
});

describe('dispatch + explain_rule enrichment', () => {
  it('dispatches the new tool names', () => {
    for (const name of ['security_scan_file', 'security_scan_changes', 'check_deployment_security']) {
      const resp = dispatchTool(name, {});
      // Each returns a ToolResponse (error or not), never throws / unknown-tool.
      expect(resp.content[0].text).not.toMatch(/unknown tool/);
    }
  });

  it('explain_rule reports mechanical-fix availability', () => {
    const withFix = parseText(handleExplainRule({ code: 'CORS001' }));
    expect(withFix.has_mechanical_fix).toBe(true);
    const withoutFix = parseText(handleExplainRule({ code: 'DEPLOY001' }));
    expect(withoutFix.has_mechanical_fix).toBe(false);
  });
});
