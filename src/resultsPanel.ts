import * as vscode from 'vscode';
import * as fs from 'fs';
import { ResultsStore } from './resultsStore';
import { SecuritySeverity, SecurityCategory, CATEGORY_LABELS, SEVERITY_LABELS } from './types';
import { FixTracker } from './fixTracker';
import { isAllowedWebviewCommand } from './webviewUtils';

interface SerializedIssue {
  filePath: string;
  relativePath: string;
  line: number;
  column: number;
  message: string;
  severityLabel: string;
  severityValue: number;
  suggestion: string;
  code: string;
  pattern: string;
  category: string;
  categoryLabel: string;
  fixStatus: string;
  fixExplanation?: string;
  issueKey: string;
  confidenceLevel?: string;
}

export class ResultsPanel implements vscode.Disposable {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private extensionUri: vscode.Uri,
    private resultsStore: ResultsStore,
    private fixTracker?: FixTracker,
  ) {
    this.resultsStore.onDidChange(() => {
      this.refresh();
    }, null, this.disposables);

    if (this.fixTracker) {
      this.fixTracker.onDidChange(() => {
        this.refresh();
      }, null, this.disposables);
    }
  }

  show(): void {
    if (this.panel) {
      this.panel.reveal(vscode.ViewColumn.Two);
      this.sendResultsToWebview();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      'caspianSecurityResults',
      'Caspian Security Results',
      vscode.ViewColumn.Two,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [this.extensionUri],
      }
    );

    this.panel.webview.html = this.getWebviewContent();
    this.panel.webview.onDidReceiveMessage(
      (message) => this.handleMessage(message),
      null,
      this.disposables
    );

    this.panel.onDidDispose(() => {
      this.panel = undefined;
    }, null, this.disposables);

    // Send initial data after a short delay to allow webview to initialize
    setTimeout(() => this.sendResultsToWebview(), 100);
  }

  refresh(): void {
    if (this.panel) {
      this.sendResultsToWebview();
    }
  }

  private sendResultsToWebview(): void {
    if (!this.panel) { return; }

    const allResults = this.resultsStore.getAllResults();
    const serialized: SerializedIssue[] = allResults.flatMap(result =>
      result.issues.map(issue => {
        const key = this.fixTracker
          ? FixTracker.makeKey(result.relativePath, issue.code, issue.line, issue.pattern)
          : `${result.relativePath}:${issue.code}:${issue.line}:${issue.pattern}`;
        const record = this.fixTracker?.getRecord(key);
        return {
          filePath: result.filePath,
          relativePath: result.relativePath,
          line: issue.line,
          column: issue.column,
          message: issue.message,
          severityLabel: SEVERITY_LABELS[issue.severity],
          severityValue: issue.severity,
          suggestion: issue.suggestion,
          code: issue.code,
          pattern: issue.pattern,
          category: issue.category,
          categoryLabel: CATEGORY_LABELS[issue.category],
          fixStatus: record?.status ?? 'pending',
          fixExplanation: record?.aiExplanation,
          issueKey: key,
          confidenceLevel: issue.confidenceLevel,
        };
      })
    );

    const summary = this.resultsStore.getSummary();
    const fixSummary = this.fixTracker?.getSummary() ?? { total: 0, pending: 0, fixed: 0, ignored: 0, fixFailed: 0, verified: 0 };

    const projectAdvisories = this.resultsStore.getProjectAdvisories().map(a => ({
      code: a.code,
      message: a.message,
      suggestion: a.suggestion,
      category: a.category,
      categoryLabel: CATEGORY_LABELS[a.category],
    }));

    this.panel.webview.postMessage({
      type: 'updateResults',
      data: { results: serialized, summary, fixSummary, projectAdvisories },
    });
  }

  private async handleMessage(message: any): Promise<void> {
    switch (message.type) {
      case 'navigateToFile': {
        const uri = vscode.Uri.file(message.filePath);
        const line = message.line;
        const column = message.column;
        const position = new vscode.Position(line, column);
        const doc = await vscode.workspace.openTextDocument(uri);
        await vscode.window.showTextDocument(doc, {
          selection: new vscode.Range(position, position),
          viewColumn: vscode.ViewColumn.One,
        });
        break;
      }
      case 'copyToClipboard': {
        const text = this.resultsStore.toFormattedText();
        await vscode.env.clipboard.writeText(text);
        vscode.window.showInformationMessage('Caspian Security: Results copied to clipboard');
        break;
      }
      case 'exportCSV': {
        const csv = this.resultsStore.toCSV();
        const uri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file('caspian-security-results.csv'),
          filters: { 'CSV Files': ['csv'] },
        });
        if (uri) {
          fs.writeFileSync(uri.fsPath, csv, 'utf-8');
          vscode.window.showInformationMessage(`Caspian Security: Results exported to ${uri.fsPath}`);
        }
        break;
      }
      case 'exportJSON': {
        const json = this.resultsStore.toJSON();
        const uri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file('caspian-security-results.json'),
          filters: { 'JSON Files': ['json'] },
        });
        if (uri) {
          fs.writeFileSync(uri.fsPath, json, 'utf-8');
          vscode.window.showInformationMessage(`Caspian Security: Results exported to ${uri.fsPath}`);
        }
        break;
      }
      case 'exportSARIF': {
        const sarif = this.resultsStore.toSARIF();
        const uri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file('caspian-security-results.sarif'),
          filters: { 'SARIF Files': ['sarif'] },
        });
        if (uri) {
          fs.writeFileSync(uri.fsPath, sarif, 'utf-8');
          vscode.window.showInformationMessage(`Caspian Security: SARIF results exported to ${uri.fsPath}`);
        }
        break;
      }
      case 'aiFixIssue': {
        await vscode.commands.executeCommand('caspian-security.aiFixIssue', message.issueData);
        break;
      }
      case 'ignoreIssue': {
        await vscode.commands.executeCommand('caspian-security.ignoreIssue', message.issueData);
        break;
      }
      case 'resetIssueStatus': {
        if (this.fixTracker && message.issueKey) {
          this.fixTracker.resetStatus(message.issueKey);
        }
        break;
      }
      case 'openAISettings': {
        await vscode.commands.executeCommand('caspian-security.openAISettings');
        break;
      }
      case 'verifyIssue': {
        await vscode.commands.executeCommand('caspian-security.verifyIssue', message.issueData);
        break;
      }
      case 'markFalsePositive': {
        await vscode.commands.executeCommand('caspian-security.markFalsePositive', message.issueData);
        break;
      }
      case 'verifyAllFixes': {
        await vscode.commands.executeCommand('caspian-security.verifyAllFixes');
        break;
      }
      case 'ignoreAllByRule': {
        await vscode.commands.executeCommand('caspian-security.ignoreAllByRule', message.ruleCode);
        break;
      }
      case 'explainRule': {
        await vscode.commands.executeCommand('caspian-security.explainRule', message.ruleCode);
        break;
      }
      case 'runCommand': {
        if (isAllowedWebviewCommand(message.commandId)) {
          await vscode.commands.executeCommand(message.commandId);
        }
        break;
      }
      case 'copyBySeverity': {
        const targetSeverity: number = message.severity;
        const labelMap: Record<number, string> = { 0: 'Info', 1: 'Warning', 2: 'Error' };
        const label = labelMap[targetSeverity] ?? 'Unknown';
        const lines: string[] = [];
        lines.push(`Caspian Security \u2014 ${label}s`);
        lines.push('='.repeat(50));
        for (const result of this.resultsStore.getAllResults()) {
          const filtered = result.issues.filter(i => (i.severity as number) === targetSeverity);
          if (filtered.length === 0) { continue; }
          lines.push(`--- ${result.relativePath} (${filtered.length} issue(s)) ---`);
          for (const issue of filtered) {
            lines.push(`  [${label}] ${issue.code} (Line ${issue.line + 1}): ${issue.message}`);
            lines.push(`    Suggestion: ${issue.suggestion}`);
          }
          lines.push('');
        }
        await vscode.env.clipboard.writeText(lines.join('\n'));
        vscode.window.showInformationMessage(`Caspian Security: ${label}s copied to clipboard`);
        break;
      }
    }
  }

  private getWebviewContent(): string {
    const nonce = getNonce();

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <title>Caspian Security Results</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--vscode-editor-background);
      color: var(--vscode-editor-foreground);
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size, 13px);
      padding: 0;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
      background: var(--vscode-sideBar-background, var(--vscode-editor-background));
    }
    .header h1 {
      font-size: 16px;
      font-weight: 600;
    }
    .header-actions {
      display: flex;
      gap: 6px;
    }

    .btn {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      padding: 5px 10px;
      cursor: pointer;
      font-size: 12px;
      border-radius: 2px;
    }
    .btn:hover { background: var(--vscode-button-hoverBackground); }
    .btn svg { vertical-align: middle; fill: currentColor; }
    .btn-secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    .btn-secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
    .btn-icon { padding: 5px 7px; line-height: 1; }

    .dropdown { position: relative; display: inline-block; }
    .dropdown-menu {
      display: none;
      position: absolute;
      top: 100%;
      right: 0;
      z-index: 100;
      min-width: 180px;
      background: var(--vscode-menu-background, var(--vscode-editor-background));
      border: 1px solid var(--vscode-menu-border, var(--vscode-panel-border));
      border-radius: 2px;
      box-shadow: 0 4px 8px rgba(0,0,0,0.3);
      margin-top: 2px;
    }
    .dropdown-menu.open { display: block; }
    .dropdown-item {
      display: block;
      width: 100%;
      padding: 6px 12px;
      background: none;
      border: none;
      color: var(--vscode-menu-foreground, var(--vscode-editor-foreground));
      font-size: 12px;
      font-family: inherit;
      text-align: left;
      cursor: pointer;
      white-space: nowrap;
    }
    .dropdown-item:hover {
      background: var(--vscode-menu-selectionBackground, var(--vscode-list-hoverBackground));
      color: var(--vscode-menu-selectionForeground, var(--vscode-editor-foreground));
    }
    .dropdown-separator {
      height: 1px;
      background: var(--vscode-menu-separatorBackground, var(--vscode-panel-border));
      margin: 4px 0;
    }

    .summary {
      padding: 10px 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }
    .summary-item { display: flex; gap: 4px; align-items: center; }
    .summary-count { font-weight: 600; color: var(--vscode-editor-foreground); }

    .fix-progress {
      padding: 6px 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
      display: none;
      gap: 10px;
      align-items: center;
    }
    .fix-progress-bar {
      flex: 1;
      height: 6px;
      background: var(--vscode-input-background);
      border-radius: 3px;
      overflow: hidden;
    }
    .fix-progress-fill {
      height: 100%;
      background: var(--vscode-progressBar-background, #0078d4);
      transition: width 0.3s;
    }
    .fix-progress-text {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      white-space: nowrap;
    }

    .filters {
      padding: 8px 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }
    .filter-group { display: flex; gap: 6px; align-items: center; }
    .filter-group-search { flex: 1; min-width: 160px; }
    .filter-group select, .filter-group input[type="text"] {
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border, rgba(128,128,128,0.35));
      padding: 3px 6px;
      font-size: 12px;
      font-family: inherit;
      border-radius: 4px;
    }
    .filter-group-search input[type="text"] { width: 100%; box-sizing: border-box; }
    .sev-dropdown { position: relative; }
    .sev-btn {
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border, rgba(128,128,128,0.35));
      padding: 3px 6px;
      font-size: 12px;
      font-family: inherit;
      border-radius: 4px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 4px;
      white-space: nowrap;
    }
    .sev-menu {
      display: none;
      position: absolute;
      top: calc(100% + 2px);
      left: 0;
      z-index: 200;
      background: var(--vscode-dropdown-background, var(--vscode-input-background));
      border: 1px solid var(--vscode-input-border, rgba(128,128,128,0.35));
      border-radius: 4px;
      padding: 4px 0;
      min-width: 140px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    .sev-menu.open { display: block; }
    .sev-menu label {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 5px 10px;
      cursor: pointer;
      font-size: 12px;
      color: var(--vscode-input-foreground);
      white-space: nowrap;
      user-select: none;
    }
    .sev-menu label:hover { background: var(--vscode-list-hoverBackground); }

    .results-info {
      padding: 6px 16px;
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      border-bottom: 1px solid var(--vscode-panel-border);
    }

    .results-container {
      overflow: auto;
      max-height: calc(100vh - 260px);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    thead { position: sticky; top: 0; z-index: 1; }
    th {
      background: var(--vscode-editorGroupHeader-tabsBackground, var(--vscode-editor-background));
      border-bottom: 2px solid var(--vscode-panel-border);
      padding: 6px 10px;
      text-align: left;
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      color: var(--vscode-descriptionForeground);
      white-space: nowrap;
      cursor: pointer;
      user-select: none;
    }
    th:hover { color: var(--vscode-editor-foreground); }
    th.no-sort { cursor: default; }
    th.no-sort:hover { color: var(--vscode-descriptionForeground); }
    td {
      padding: 5px 10px;
      border-bottom: 1px solid var(--vscode-panel-border);
      vertical-align: top;
    }
    tr.issue-row { cursor: pointer; }
    tr.issue-row:hover { background: var(--vscode-list-hoverBackground); }

    .severity-error { color: var(--vscode-errorForeground, #f44336); font-weight: 600; }
    .severity-warning { color: var(--vscode-editorWarning-foreground, #ff9800); font-weight: 600; }
    .severity-info { color: var(--vscode-editorInfo-foreground, #2196f3); }

    .code-cell { font-family: var(--vscode-editor-fontFamily, monospace); font-weight: 600; }
    .file-cell { max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .message-cell { min-width: 200px; }
    .actions-cell { white-space: nowrap; }

    .suggestion-row td {
      padding: 2px 10px 8px 10px;
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      border-bottom: 1px solid var(--vscode-panel-border);
    }

    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: var(--vscode-descriptionForeground);
    }
    .empty-state h2 { font-size: 16px; margin-bottom: 8px; font-weight: 500; }
    .empty-state p { font-size: 13px; }

    .advisories-section {
      border-top: 2px solid var(--vscode-panel-border);
      margin-top: 8px;
      display: none;
    }
    .advisories-header {
      padding: 10px 16px;
      font-size: 13px;
      font-weight: 600;
      color: var(--vscode-descriptionForeground);
      cursor: pointer;
      user-select: none;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .advisories-header:hover { color: var(--vscode-editor-foreground); }
    .advisories-toggle { font-size: 10px; }
    .advisories-badge {
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
      padding: 1px 6px;
      border-radius: 8px;
      font-size: 11px;
      font-weight: 600;
    }
    .advisories-list {
      padding: 0 16px 12px 16px;
    }
    .advisory-item {
      padding: 8px 12px;
      margin-bottom: 4px;
      background: var(--vscode-input-background);
      border-radius: 4px;
      border-left: 3px solid var(--vscode-editorInfo-foreground, #2196f3);
    }
    .advisory-code {
      font-family: var(--vscode-editor-fontFamily, monospace);
      font-weight: 600;
      font-size: 11px;
      color: var(--vscode-editorInfo-foreground, #2196f3);
    }
    .advisory-category {
      font-size: 10px;
      color: var(--vscode-descriptionForeground);
      margin-left: 8px;
    }
    .advisory-message { font-size: 12px; margin-top: 2px; }
    .advisory-suggestion {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      margin-top: 4px;
    }

    .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
    .dot-error { background: var(--vscode-errorForeground, #f44336); }
    .dot-warning { background: var(--vscode-editorWarning-foreground, #ff9800); }
    .dot-info { background: var(--vscode-editorInfo-foreground, #2196f3); }

    .btn-fix {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      padding: 2px 8px;
      cursor: pointer;
      font-size: 11px;
      border-radius: 2px;
      margin-right: 4px;
    }
    .btn-fix:hover { background: var(--vscode-button-hoverBackground); }
    .btn-ignore {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border: none;
      padding: 2px 8px;
      cursor: pointer;
      font-size: 11px;
      border-radius: 2px;
    }
    .btn-ignore:hover { background: var(--vscode-button-secondaryHoverBackground); }
    .btn-fp {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border: 1px solid var(--vscode-descriptionForeground);
      padding: 2px 8px;
      cursor: pointer;
      font-size: 11px;
      border-radius: 2px;
    }
    .btn-fp:hover { background: var(--vscode-button-secondaryHoverBackground); }
    .btn-why {
      background: transparent;
      color: var(--vscode-textLink-foreground, #3794ff);
      border: none;
      padding: 2px 6px;
      cursor: pointer;
      font-size: 10px;
      text-decoration: underline;
    }
    .btn-why:hover { color: var(--vscode-textLink-activeForeground, #3794ff); }
    .btn-ignore-all {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border: none;
      padding: 2px 8px;
      cursor: pointer;
      font-size: 10px;
      border-radius: 2px;
    }
    .btn-ignore-all:hover { background: var(--vscode-button-secondaryHoverBackground); }
    .btn-reset {
      background: transparent;
      color: var(--vscode-descriptionForeground);
      border: none;
      padding: 2px 6px;
      cursor: pointer;
      font-size: 10px;
      text-decoration: underline;
    }
    .status-fixed { color: #4caf50; font-weight: 600; font-size: 11px; }
    .status-ignored { color: var(--vscode-descriptionForeground); font-size: 11px; }
    .status-failed { color: var(--vscode-errorForeground, #f44336); font-size: 11px; }
    .status-verified { color: #4caf50; font-weight: 600; font-size: 11px; }
    .confidence-badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; margin-right: 4px; }
    .confidence-critical { background: #f44336; color: white; }
    .confidence-safe { background: #4caf50; color: white; }
    .confidence-verify { background: #ff9800; color: white; }
    .btn-verify {
      background: #4caf50;
      color: white;
      border: none;
      padding: 2px 8px;
      cursor: pointer;
      font-size: 11px;
      border-radius: 2px;
      margin-right: 4px;
    }
    .btn-verify:hover { background: #45a049; }
    .btn-verify-all {
      background: #4caf50;
      color: white;
      border: none;
      padding: 4px 12px;
      cursor: pointer;
      font-size: 12px;
      border-radius: 3px;
    }
    .btn-verify-all:hover { background: #45a049; }

    tr.issue-row.row-fixed { opacity: 0.6; }
    tr.issue-row.row-ignored { opacity: 0.5; }
    tr.suggestion-row.row-fixed { opacity: 0.6; }
    tr.suggestion-row.row-ignored { opacity: 0.5; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Caspian Security Results</h1>
    <div class="header-actions">
      <button class="btn btn-verify-all" id="btn-verify-all" title="Verify all fixed issues" style="display:none;">Verify All Fixes</button>
      <div class="dropdown" id="dropdown-run">
        <button class="btn btn-secondary" id="btn-run" title="Run security scan"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 256 256"><path d="M232.4,114.49l-144-88A16,16,0,0,0,64,39.87V216.13a15.86,15.86,0,0,0,8.12,13.82,16.09,16.09,0,0,0,16.2-.3l144-88A15.74,15.74,0,0,0,232.4,114.49ZM80,197.57V58.43L191.27,128Z"/></svg> Run <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 256 256"><path d="M213.66,101.66l-80,80a8,8,0,0,1-11.32,0l-80-80A8,8,0,0,1,53.66,90.34L128,164.69l74.34-74.35a8,8,0,0,1,11.32,11.32Z"/></svg></button>
        <div class="dropdown-menu" id="menu-run">
          <button class="dropdown-item" id="run-check">Run Security Check</button>
          <button class="dropdown-item" id="run-check-file">Check Current File</button>
          <button class="dropdown-item" id="run-check-workspace">Check Entire Workspace</button>
          <div class="dropdown-separator"></div>
          <button class="dropdown-item" id="run-uncommitted">Scan Uncommitted Files</button>
        </div>
      </div>
      <div class="dropdown" id="dropdown-copy">
        <button class="btn btn-secondary" id="btn-copy-menu" title="Copy results to clipboard"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 256 256"><path d="M216,32H88a8,8,0,0,0-8,8V80H40a8,8,0,0,0-8,8V216a8,8,0,0,0,8,8H168a8,8,0,0,0,8-8V176h40a8,8,0,0,0,8-8V40A8,8,0,0,0,216,32Zm-56,176H48V96H160Zm48-48H176V88a8,8,0,0,0-8-8H96V48H208Z"/></svg> Copy <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 256 256"><path d="M213.66,101.66l-80,80a8,8,0,0,1-11.32,0l-80-80A8,8,0,0,1,53.66,90.34L128,164.69l74.34-74.35a8,8,0,0,1,11.32,11.32Z"/></svg></button>
        <div class="dropdown-menu" id="menu-copy">
          <button class="dropdown-item" id="copy-all">Copy All</button>
          <div class="dropdown-separator"></div>
          <button class="dropdown-item" id="copy-errors">Copy Errors</button>
          <button class="dropdown-item" id="copy-warnings">Copy Warnings</button>
          <button class="dropdown-item" id="copy-info">Copy Info</button>
        </div>
      </div>
      <div class="dropdown" id="dropdown-export">
        <button class="btn btn-secondary" id="btn-export" title="Export results"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 256 256"><path d="M224,152v56a16,16,0,0,1-16,16H48a16,16,0,0,1-16-16V152a8,8,0,0,1,16,0v56H208V152a8,8,0,0,1,16,0Zm-101.66,5.66a8,8,0,0,0,11.32,0l40-40a8,8,0,0,0-11.32-11.32L136,132.69V40a8,8,0,0,0-16,0v92.69L93.66,106.34a8,8,0,0,0-11.32,11.32Z"/></svg> Export <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 256 256"><path d="M213.66,101.66l-80,80a8,8,0,0,1-11.32,0l-80-80A8,8,0,0,1,53.66,90.34L128,164.69l74.34-74.35a8,8,0,0,1,11.32,11.32Z"/></svg></button>
        <div class="dropdown-menu" id="menu-export">
          <button class="dropdown-item" id="export-csv">Export CSV</button>
          <button class="dropdown-item" id="export-json">Export JSON</button>
          <button class="dropdown-item" id="export-sarif">Export SARIF (GitHub)</button>
        </div>
      </div>
      <button class="btn btn-secondary btn-icon" id="btn-tasks" title="Security Tasks"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256"><path d="M224,128a8,8,0,0,1-8,8H136a8,8,0,0,1,0-16h80A8,8,0,0,1,224,128ZM136,72h80a8,8,0,0,0,0-16H136a8,8,0,0,0,0,16Zm80,112H136a8,8,0,0,0,0,16h80a8,8,0,0,0,0-16ZM82.34,42.34,56,68.69,45.66,58.34A8,8,0,0,0,34.34,69.66l16,16a8,8,0,0,0,11.32,0l32-32A8,8,0,0,0,82.34,42.34Zm0,85.66L56,154.35l-10.34-10a8,8,0,0,0-11.32,11.31l16,16a8,8,0,0,0,11.32,0l32-32a8,8,0,0,0-11.32-11.32Zm0,86L56,240.35l-10.34-10a8,8,0,0,0-11.32,11.31l16,16a8,8,0,0,0,11.32,0l32-32A8,8,0,0,0,82.34,213.66Z"/></svg> Tasks</button>
      <button class="btn btn-secondary btn-icon" id="btn-ai-settings" title="AI Settings"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 256 256"><path d="M128,80a48,48,0,1,0,48,48A48.05,48.05,0,0,0,128,80Zm0,80a32,32,0,1,1,32-32A32,32,0,0,1,128,160Zm88-29.84q.06-2.16,0-4.32l14.92-18.64a8,8,0,0,0,1.48-7.06,107.21,107.21,0,0,0-10.88-26.25,8,8,0,0,0-6-3.93l-23.72-2.64q-1.48-1.56-3-3L186,40.54a8,8,0,0,0-3.94-6,107.71,107.71,0,0,0-26.25-10.87,8,8,0,0,0-7.06,1.49L130.16,40Q128,40,125.84,40L107.2,25.11a8,8,0,0,0-7.06-1.48A107.6,107.6,0,0,0,73.89,34.51a8,8,0,0,0-3.93,6L67.32,64.27q-1.56,1.49-3,3L40.54,70a8,8,0,0,0-6,3.94,107.71,107.71,0,0,0-10.87,26.25,8,8,0,0,0,1.49,7.06L40,125.84Q40,128,40,130.16L25.11,148.8a8,8,0,0,0-1.48,7.06,107.21,107.21,0,0,0,10.88,26.25,8,8,0,0,0,6,3.93l23.72,2.64q1.49,1.56,3,3L70,215.46a8,8,0,0,0,3.94,6,107.71,107.71,0,0,0,26.25,10.87,8,8,0,0,0,7.06-1.49L125.84,216q2.16.06,4.32,0l18.64,14.92a8,8,0,0,0,7.06,1.48,107.21,107.21,0,0,0,26.25-10.88,8,8,0,0,0,3.93-6l2.64-23.72q1.56-1.48,3-3L215.46,186a8,8,0,0,0,6-3.94,107.71,107.71,0,0,0,10.87-26.25,8,8,0,0,0-1.49-7.06Zm-16.1-6.5a73.93,73.93,0,0,1,0,8.68,8,8,0,0,0,1.74,5.48l14.19,17.73a91.57,91.57,0,0,1-6.23,15L187,173.11a8,8,0,0,0-5.1,2.64,74.11,74.11,0,0,1-6.14,6.14,8,8,0,0,0-2.64,5.1l-2.51,22.58a91.32,91.32,0,0,1-15,6.23l-17.74-14.19a8,8,0,0,0-5-1.75h-.48a73.93,73.93,0,0,1-8.68,0,8,8,0,0,0-5.48,1.74L100.45,215.8a91.57,91.57,0,0,1-15-6.23L82.89,187a8,8,0,0,0-2.64-5.1,74.11,74.11,0,0,1-6.14-6.14,8,8,0,0,0-5.1-2.64L46.43,170.6a91.32,91.32,0,0,1-6.23-15l14.19-17.74a8,8,0,0,0,1.74-5.48,73.93,73.93,0,0,1,0-8.68,8,8,0,0,0-1.74-5.48L40.2,100.45a91.57,91.57,0,0,1,6.23-15L69,82.89a8,8,0,0,0,5.1-2.64,74.11,74.11,0,0,1,6.14-6.14A8,8,0,0,0,82.89,69L85.4,46.43a91.32,91.32,0,0,1,15-6.23l17.74,14.19a8,8,0,0,0,5.48,1.74,73.93,73.93,0,0,1,8.68,0,8,8,0,0,0,5.48-1.74L155.55,40.2a91.57,91.57,0,0,1,15,6.23L173.11,69a8,8,0,0,0,2.64,5.1,74.11,74.11,0,0,1,6.14,6.14,8,8,0,0,0,5.1,2.64l22.58,2.51a91.32,91.32,0,0,1,6.23,15l-14.19,17.74A8,8,0,0,0,199.86,123.66Z"/></svg></button>
    </div>
  </div>

  <div class="summary" id="summary">
    <span class="summary-item">No scan results yet</span>
  </div>

  <div class="fix-progress" id="fix-progress">
    <div class="fix-progress-bar">
      <div class="fix-progress-fill" id="fix-progress-fill"></div>
    </div>
    <span class="fix-progress-text" id="fix-progress-text"></span>
  </div>

  <div class="filters">
    <div class="filter-group">
      <div class="sev-dropdown" id="sev-dropdown">
        <button class="sev-btn" id="sev-btn" type="button">
          <span id="sev-btn-label">All Severities</span>
          <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 256 256"><path d="M213.66,101.66l-80,80a8,8,0,0,1-11.32,0l-80-80A8,8,0,0,1,53.66,90.34L128,164.69l74.34-74.35a8,8,0,0,1,11.32,11.32Z"/></svg>
        </button>
        <div class="sev-menu" id="sev-menu">
          <label><input type="checkbox" id="sev-error" checked><span class="dot dot-error"></span>Error</label>
          <label><input type="checkbox" id="sev-warning" checked><span class="dot dot-warning"></span>Warning</label>
          <label><input type="checkbox" id="sev-info" checked><span class="dot dot-info"></span>Info</label>
        </div>
      </div>
    </div>
    <div class="filter-group">
      <select id="filter-category"><option value="all">All Categories</option></select>
    </div>
    <div class="filter-group">
      <select id="filter-file"><option value="all">All Files</option></select>
    </div>
    <div class="filter-group">
      <select id="filter-fixstatus">
        <option value="all">All Statuses</option>
        <option value="pending">Pending</option>
        <option value="fixed">Fixed</option>
        <option value="verified">Verified</option>
        <option value="ignored">Ignored</option>
        <option value="fix-failed">Fix Failed</option>
      </select>
    </div>
    <div class="filter-group filter-group-search">
      <input type="text" id="filter-search" placeholder="Filter by message, code, file...">
    </div>
  </div>

  <div class="results-info" id="results-info">Showing 0 results</div>

  <div class="results-container">
    <table>
      <thead>
        <tr>
          <th data-sort="severityValue">Severity</th>
          <th data-sort="code">Code</th>
          <th data-sort="relativePath">File</th>
          <th data-sort="line">Line</th>
          <th data-sort="message">Message</th>
          <th class="no-sort">Actions</th>
        </tr>
      </thead>
      <tbody id="results-body"></tbody>
    </table>
    <div class="empty-state" id="empty-state">
      <h2>No results yet</h2>
      <p>Run a security scan to see results here.</p>
    </div>
  </div>

  <div class="advisories-section" id="advisories-section">
    <div class="advisories-header" id="advisories-header">
      <span class="advisories-toggle" id="advisories-toggle">&#9660;</span>
      Security Best Practice Advisories
      <span class="advisories-badge" id="advisories-count">0</span>
    </div>
    <div class="advisories-list" id="advisories-list"></div>
  </div>

<script nonce="${nonce}">
(function() {
  const vscode = acquireVsCodeApi();
  let allResults = [];
  let filteredResults = [];
  let sortField = 'severityValue';
  let sortAsc = false;

  const sevError = document.getElementById('sev-error');
  const sevWarning = document.getElementById('sev-warning');
  const sevInfo = document.getElementById('sev-info');
  const sevBtn = document.getElementById('sev-btn');
  const sevBtnLabel = document.getElementById('sev-btn-label');
  const sevMenu = document.getElementById('sev-menu');
  const categorySelect = document.getElementById('filter-category');
  const fileSelect = document.getElementById('filter-file');
  const fixStatusSelect = document.getElementById('filter-fixstatus');
  const searchInput = document.getElementById('filter-search');
  const resultsBody = document.getElementById('results-body');
  const resultsInfo = document.getElementById('results-info');
  const summaryEl = document.getElementById('summary');
  const emptyState = document.getElementById('empty-state');

  function updateSevBtn() {
    const on = [];
    if (sevError.checked) on.push('Error');
    if (sevWarning.checked) on.push('Warning');
    if (sevInfo.checked) on.push('Info');
    sevBtnLabel.textContent = on.length === 3 ? 'All Severities' : on.length === 0 ? 'Severity' : on.join(', ');
  }

  sevBtn.addEventListener('click', e => { e.stopPropagation(); sevMenu.classList.toggle('open'); });
  document.addEventListener('click', () => sevMenu.classList.remove('open'));
  sevMenu.addEventListener('click', e => e.stopPropagation());

  // Event listeners for filters
  sevError.addEventListener('change', () => { updateSevBtn(); applyFilters(); });
  sevWarning.addEventListener('change', () => { updateSevBtn(); applyFilters(); });
  sevInfo.addEventListener('change', () => { updateSevBtn(); applyFilters(); });
  categorySelect.addEventListener('change', applyFilters);
  fileSelect.addEventListener('change', applyFilters);
  fixStatusSelect.addEventListener('change', applyFilters);
  searchInput.addEventListener('input', applyFilters);

  // Sort on column click
  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const field = th.getAttribute('data-sort');
      if (sortField === field) {
        sortAsc = !sortAsc;
      } else {
        sortField = field;
        sortAsc = true;
      }
      applyFilters();
    });
  });

  // Button handlers
  document.getElementById('btn-ai-settings').addEventListener('click', () => {
    vscode.postMessage({ type: 'openAISettings' });
  });
  document.getElementById('btn-tasks').addEventListener('click', () => {
    vscode.postMessage({ type: 'runCommand', commandId: 'caspian-security.showTaskDashboard' });
  });
  document.getElementById('btn-verify-all').addEventListener('click', () => {
    vscode.postMessage({ type: 'verifyAllFixes' });
  });

  // Dropdown toggle logic
  function toggleDropdown(menuId) {
    document.querySelectorAll('.dropdown-menu').forEach(m => {
      if (m.id !== menuId) { m.classList.remove('open'); }
    });
    document.getElementById(menuId).classList.toggle('open');
  }
  document.addEventListener('click', e => {
    if (!e.target.closest('.dropdown')) {
      document.querySelectorAll('.dropdown-menu').forEach(m => m.classList.remove('open'));
    }
  });
  document.getElementById('btn-run').addEventListener('click', e => { e.stopPropagation(); toggleDropdown('menu-run'); });
  document.getElementById('btn-copy-menu').addEventListener('click', e => { e.stopPropagation(); toggleDropdown('menu-copy'); });
  document.getElementById('btn-export').addEventListener('click', e => { e.stopPropagation(); toggleDropdown('menu-export'); });

  // Run items
  document.getElementById('run-check').addEventListener('click', () => { document.getElementById('menu-run').classList.remove('open'); vscode.postMessage({ type: 'runCommand', commandId: 'caspian-security.runCheck' }); });
  document.getElementById('run-check-file').addEventListener('click', () => { document.getElementById('menu-run').classList.remove('open'); vscode.postMessage({ type: 'runCommand', commandId: 'caspian-security.runCheckFile' }); });
  document.getElementById('run-check-workspace').addEventListener('click', () => { document.getElementById('menu-run').classList.remove('open'); vscode.postMessage({ type: 'runCommand', commandId: 'caspian-security.runCheckWorkspace' }); });
  document.getElementById('run-uncommitted').addEventListener('click', () => { document.getElementById('menu-run').classList.remove('open'); vscode.postMessage({ type: 'runCommand', commandId: 'caspian-security.runCheckUncommitted' }); });

  // Copy items
  document.getElementById('copy-all').addEventListener('click', () => { document.getElementById('menu-copy').classList.remove('open'); vscode.postMessage({ type: 'copyToClipboard' }); });
  document.getElementById('copy-errors').addEventListener('click', () => { document.getElementById('menu-copy').classList.remove('open'); vscode.postMessage({ type: 'copyBySeverity', severity: 2 }); });
  document.getElementById('copy-warnings').addEventListener('click', () => { document.getElementById('menu-copy').classList.remove('open'); vscode.postMessage({ type: 'copyBySeverity', severity: 1 }); });
  document.getElementById('copy-info').addEventListener('click', () => { document.getElementById('menu-copy').classList.remove('open'); vscode.postMessage({ type: 'copyBySeverity', severity: 0 }); });

  // Export items
  document.getElementById('export-csv').addEventListener('click', () => { document.getElementById('menu-export').classList.remove('open'); vscode.postMessage({ type: 'exportCSV' }); });
  document.getElementById('export-json').addEventListener('click', () => { document.getElementById('menu-export').classList.remove('open'); vscode.postMessage({ type: 'exportJSON' }); });
  document.getElementById('export-sarif').addEventListener('click', () => { document.getElementById('menu-export').classList.remove('open'); vscode.postMessage({ type: 'exportSARIF' }); });

  // Advisories toggle
  let advisoriesExpanded = true;
  const advisoriesHeader = document.getElementById('advisories-header');
  advisoriesHeader.addEventListener('click', () => {
    advisoriesExpanded = !advisoriesExpanded;
    document.getElementById('advisories-list').style.display = advisoriesExpanded ? 'block' : 'none';
    document.getElementById('advisories-toggle').innerHTML = advisoriesExpanded ? '&#9660;' : '&#9654;';
  });

  // Receive data from extension
  window.addEventListener('message', event => {
    const msg = event.data;
    if (msg.type === 'updateResults') {
      allResults = msg.data.results;
      updateDropdowns();
      applyFilters();
      renderSummary(msg.data.summary);
      renderFixProgress(msg.data.fixSummary);
      renderAdvisories(msg.data.projectAdvisories || []);

      // Show/hide the Verify All Fixes button
      const hasFixedIssues = allResults.some(r => r.fixStatus === 'fixed');
      document.getElementById('btn-verify-all').style.display = hasFixedIssues ? 'inline-block' : 'none';
    }
  });

  function updateDropdowns() {
    const categories = new Set();
    const files = new Set();
    for (const item of allResults) {
      categories.add(item.categoryLabel);
      files.add(item.relativePath);
    }

    const currentCat = categorySelect.value;
    categorySelect.innerHTML = '<option value="all">All Categories</option>';
    Array.from(categories).sort().forEach(cat => {
      const opt = document.createElement('option');
      opt.value = cat;
      opt.textContent = cat;
      categorySelect.appendChild(opt);
    });
    categorySelect.value = categories.has(currentCat) ? currentCat : 'all';

    const currentFile = fileSelect.value;
    fileSelect.innerHTML = '<option value="all">All Files</option>';
    Array.from(files).sort().forEach(f => {
      const opt = document.createElement('option');
      opt.value = f;
      opt.textContent = f;
      fileSelect.appendChild(opt);
    });
    fileSelect.value = files.has(currentFile) ? currentFile : 'all';
  }

  function applyFilters() {
    const activeSeverities = new Set();
    if (sevError.checked) activeSeverities.add('Error');
    if (sevWarning.checked) activeSeverities.add('Warning');
    if (sevInfo.checked) activeSeverities.add('Info');

    const selectedCategory = categorySelect.value;
    const selectedFile = fileSelect.value;
    const selectedFixStatus = fixStatusSelect.value;
    const searchText = searchInput.value.toLowerCase();

    filteredResults = allResults.filter(item => {
      if (!activeSeverities.has(item.severityLabel)) return false;
      if (selectedCategory !== 'all' && item.categoryLabel !== selectedCategory) return false;
      if (selectedFile !== 'all' && item.relativePath !== selectedFile) return false;
      if (selectedFixStatus !== 'all' && item.fixStatus !== selectedFixStatus) return false;
      if (searchText) {
        const haystack = (item.message + ' ' + item.code + ' ' + item.relativePath + ' ' + item.suggestion + ' ' + item.categoryLabel).toLowerCase();
        if (!haystack.includes(searchText)) return false;
      }
      return true;
    });

    // Sort
    filteredResults.sort((a, b) => {
      let va = a[sortField];
      let vb = b[sortField];
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      return 0;
    });

    renderTable();
    resultsInfo.textContent = 'Showing ' + filteredResults.length + ' of ' + allResults.length + ' results';
    emptyState.style.display = filteredResults.length === 0 ? 'block' : 'none';
    if (filteredResults.length === 0 && allResults.length > 0) {
      emptyState.querySelector('h2').textContent = 'No matching results';
      emptyState.querySelector('p').textContent = 'Try adjusting your filters.';
    } else if (allResults.length === 0) {
      emptyState.querySelector('h2').textContent = 'No results yet';
      emptyState.querySelector('p').textContent = 'Run a security scan to see results here.';
    }
  }

  function renderConfidenceBadge(confidenceLevel) {
    if (!confidenceLevel) return '';
    if (confidenceLevel === 'critical') return '<span class="confidence-badge confidence-critical">Critical</span>';
    if (confidenceLevel === 'safe') return '<span class="confidence-badge confidence-safe">Safe</span>';
    if (confidenceLevel === 'verify-needed') return '<span class="confidence-badge confidence-verify">Verify Needed</span>';
    return '';
  }

  function renderActionsCell(item) {
    const badge = renderConfidenceBadge(item.confidenceLevel);
    if (item.fixStatus === 'verified') {
      return badge + '<span class="status-verified">Verified ✓</span> <button class="btn-reset" data-key="' + escapeAttr(item.issueKey) + '">reset</button>';
    }
    if (item.fixStatus === 'fixed') {
      return badge + '<span class="status-fixed">Fixed</span> <button class="btn-verify" data-key="' + escapeAttr(item.issueKey) + '">Verify</button> <button class="btn-reset" data-key="' + escapeAttr(item.issueKey) + '">reset</button>';
    }
    if (item.fixStatus === 'ignored') {
      return badge + '<span class="status-ignored">Ignored</span> <button class="btn-reset" data-key="' + escapeAttr(item.issueKey) + '">reset</button>';
    }
    if (item.fixStatus === 'fix-failed') {
      return badge + '<span class="status-failed">Fix Failed</span> <button class="btn-fix" data-key="' + escapeAttr(item.issueKey) + '">Retry</button>';
    }
    // pending
    return badge + '<button class="btn-fix" data-key="' + escapeAttr(item.issueKey) + '">AI Fix</button>'
      + '<button class="btn-verify" data-key="' + escapeAttr(item.issueKey) + '">Verify</button>'
      + '<button class="btn-ignore" data-key="' + escapeAttr(item.issueKey) + '">Ignore</button>'
      + '<button class="btn-fp" data-key="' + escapeAttr(item.issueKey) + '">False Positive</button>'
      + '<button class="btn-ignore-all" data-code="' + escapeAttr(item.code) + '">Ignore All ' + escapeHtml(item.code) + '</button>'
      + '<button class="btn-why" data-code="' + escapeAttr(item.code) + '" data-msg="' + escapeAttr(item.message) + '">Why?</button>';
  }

  // Cap how many findings are rendered at once. Rendering tens of
  // thousands of rows froze the webview on large scans; the cap grows
  // via the "Show more" row.
  let renderLimit = 500;

  function renderTable() {
    const visibleResults = filteredResults.slice(0, renderLimit);
    let html = visibleResults.map(item => {
      const sevClass = 'severity-' + item.severityLabel.toLowerCase();
      const rowClass = item.fixStatus === 'fixed' ? ' row-fixed'
        : item.fixStatus === 'ignored' ? ' row-ignored'
        : '';
      return '<tr class="issue-row' + rowClass + '" data-file="' + escapeAttr(item.filePath) + '" data-line="' + item.line + '" data-col="' + item.column + '">'
        + '<td class="' + sevClass + '">' + escapeHtml(item.severityLabel) + '</td>'
        + '<td class="code-cell">' + escapeHtml(item.code) + '</td>'
        + '<td class="file-cell" title="' + escapeAttr(item.filePath) + '">' + escapeHtml(item.relativePath) + '</td>'
        + '<td>' + (item.line + 1) + '</td>'
        + '<td class="message-cell">' + escapeHtml(item.message) + '</td>'
        + '<td class="actions-cell">' + renderActionsCell(item) + '</td>'
        + '</tr>'
        + '<tr class="suggestion-row' + rowClass + '" data-file="' + escapeAttr(item.filePath) + '" data-line="' + item.line + '" data-col="' + item.column + '">'
        + '<td colspan="6">Suggestion: ' + escapeHtml(item.suggestion)
        + (item.fixExplanation ? '<br>AI Explanation: ' + escapeHtml(item.fixExplanation) : '')
        + '</td>'
        + '</tr>';
    }).join('');

    if (filteredResults.length > renderLimit) {
      const remaining = filteredResults.length - renderLimit;
      html += '<tr class="show-more-row"><td colspan="6">'
        + '<button id="btn-show-more">Show ' + Math.min(remaining, 1000) + ' more (' + remaining + ' hidden)</button>'
        + '</td></tr>';
    }

    resultsBody.innerHTML = html;
  }

  // One delegated click listener for the whole table — attaching a
  // listener per row/button made large result sets sluggish and leaked
  // handlers on every re-render.
  resultsBody.addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (btn) {
      e.stopPropagation();
      if (btn.id === 'btn-show-more') {
        renderLimit += 1000;
        renderTable();
        return;
      }
      const key = btn.getAttribute('data-key');
      const code = btn.getAttribute('data-code');
      const item = key ? findItemByKey(key) : null;

      if (btn.classList.contains('btn-fix') && item) {
        vscode.postMessage({
          type: 'aiFixIssue',
          issueData: {
            filePath: item.filePath, relativePath: item.relativePath,
            line: item.line, column: item.column, code: item.code,
            pattern: item.pattern, message: item.message,
            suggestion: item.suggestion, category: item.categoryLabel,
            severity: item.severityLabel,
          }
        });
      } else if (btn.classList.contains('btn-ignore') && item) {
        vscode.postMessage({
          type: 'ignoreIssue',
          issueData: {
            filePath: item.filePath, relativePath: item.relativePath,
            line: item.line, code: item.code, pattern: item.pattern,
          }
        });
      } else if (btn.classList.contains('btn-reset')) {
        vscode.postMessage({ type: 'resetIssueStatus', issueKey: key });
      } else if (btn.classList.contains('btn-verify') && item) {
        vscode.postMessage({
          type: 'verifyIssue',
          issueData: {
            filePath: item.filePath, relativePath: item.relativePath,
            line: item.line, code: item.code, pattern: item.pattern,
          }
        });
      } else if (btn.classList.contains('btn-fp') && item) {
        vscode.postMessage({
          type: 'markFalsePositive',
          issueData: {
            filePath: item.filePath, relativePath: item.relativePath,
            line: item.line, code: item.code, pattern: item.pattern,
          }
        });
      } else if (btn.classList.contains('btn-ignore-all')) {
        vscode.postMessage({ type: 'ignoreAllByRule', ruleCode: code });
      } else if (btn.classList.contains('btn-why')) {
        vscode.postMessage({ type: 'explainRule', ruleCode: code });
      }
      return;
    }

    // Navigate on row click (buttons handled above)
    const row = e.target.closest('tr.issue-row, tr.suggestion-row');
    if (row) {
      const file = row.getAttribute('data-file');
      const line = parseInt(row.getAttribute('data-line'));
      const col = parseInt(row.getAttribute('data-col'));
      if (file) {
        vscode.postMessage({ type: 'navigateToFile', filePath: file, line: line, column: col });
      }
    }
  });

  function findItemByKey(key) {
    return allResults.find(r => r.issueKey === key) || filteredResults.find(r => r.issueKey === key);
  }

  function renderSummary(summary) {
    if (!summary) return;
    const parts = [];
    parts.push('<span class="summary-item"><span class="summary-count">' + summary.totalIssues + '</span> issue(s) in <span class="summary-count">' + summary.totalFiles + '</span> file(s)</span>');

    if (summary.bySeverity['Error']) {
      parts.push('<span class="summary-item"><span class="dot dot-error"></span><span class="summary-count">' + summary.bySeverity['Error'] + '</span> Error</span>');
    }
    if (summary.bySeverity['Warning']) {
      parts.push('<span class="summary-item"><span class="dot dot-warning"></span><span class="summary-count">' + summary.bySeverity['Warning'] + '</span> Warning</span>');
    }
    if (summary.bySeverity['Info']) {
      parts.push('<span class="summary-item"><span class="dot dot-info"></span><span class="summary-count">' + summary.bySeverity['Info'] + '</span> Info</span>');
    }

    if (summary.scanDuration > 0) {
      parts.push('<span class="summary-item">Scanned in ' + (summary.scanDuration / 1000).toFixed(1) + 's</span>');
    }
    if (summary.scanType) {
      parts.push('<span class="summary-item">Scan type: ' + escapeHtml(summary.scanType) + '</span>');
    }

    summaryEl.innerHTML = parts.join('');
  }

  function renderFixProgress(fixSummary) {
    const el = document.getElementById('fix-progress');
    if (!fixSummary || fixSummary.total === 0) {
      el.style.display = 'none';
      return;
    }
    el.style.display = 'flex';
    const resolved = fixSummary.fixed + fixSummary.ignored + (fixSummary.verified || 0);
    const total = allResults.length || fixSummary.total;
    const pct = total > 0 ? Math.round((resolved / total) * 100) : 0;
    document.getElementById('fix-progress-fill').style.width = pct + '%';
    document.getElementById('fix-progress-text').textContent =
      resolved + '/' + total + ' resolved (' + fixSummary.fixed + ' fixed'
      + (fixSummary.verified > 0 ? ', ' + fixSummary.verified + ' verified' : '')
      + ', ' + fixSummary.ignored + ' ignored'
      + (fixSummary.fixFailed > 0 ? ', ' + fixSummary.fixFailed + ' failed' : '')
      + ')';
  }

  function renderAdvisories(advisories) {
    const section = document.getElementById('advisories-section');
    const list = document.getElementById('advisories-list');
    const countBadge = document.getElementById('advisories-count');

    if (!advisories || advisories.length === 0) {
      section.style.display = 'none';
      return;
    }

    section.style.display = 'block';
    countBadge.textContent = advisories.length;

    list.innerHTML = advisories.map(function(a) {
      return '<div class="advisory-item">'
        + '<span class="advisory-code">' + escapeHtml(a.code) + '</span>'
        + '<span class="advisory-category">' + escapeHtml(a.categoryLabel) + '</span>'
        + '<div class="advisory-message">' + escapeHtml(a.message) + '</div>'
        + '<div class="advisory-suggestion">' + escapeHtml(a.suggestion) + '</div>'
        + '</div>';
    }).join('');
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s || '';
    return div.innerHTML;
  }

  function escapeAttr(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
})();
</script>
</body>
</html>`;
  }

  dispose(): void {
    this.panel?.dispose();
    this.disposables.forEach(d => d.dispose());
    this.disposables = [];
  }
}

function getNonce(): string {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
