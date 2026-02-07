import * as vscode from 'vscode';
import * as fs from 'fs';
import { ResultsStore } from './resultsStore';
import { SecuritySeverity, SecurityCategory, CATEGORY_LABELS, SEVERITY_LABELS } from './types';
import { FixTracker } from './fixTracker';

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
    .btn-secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    .btn-secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }

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
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
    }
    .filter-group { display: flex; gap: 6px; align-items: center; }
    .filter-group label { font-size: 11px; color: var(--vscode-descriptionForeground); white-space: nowrap; }
    .filter-group select, .filter-group input[type="text"] {
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border, transparent);
      padding: 3px 6px;
      font-size: 12px;
      font-family: inherit;
      border-radius: 2px;
    }
    .filter-group input[type="text"] { width: 200px; }
    .checkbox-group { display: flex; gap: 8px; align-items: center; }
    .checkbox-group label {
      display: flex; gap: 3px; align-items: center; font-size: 12px;
      color: var(--vscode-editor-foreground); cursor: pointer;
    }

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
      <button class="btn" id="btn-ai-settings" title="Configure AI provider">AI Settings</button>
      <button class="btn btn-secondary" id="btn-copy" title="Copy all results to clipboard">Copy All</button>
      <button class="btn btn-secondary" id="btn-csv" title="Export results as CSV">Export CSV</button>
      <button class="btn btn-secondary" id="btn-json" title="Export results as JSON">Export JSON</button>
      <button class="btn btn-secondary" id="btn-sarif" title="Export SARIF for GitHub Security">Export SARIF</button>
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
      <label>Severity:</label>
      <div class="checkbox-group">
        <label><input type="checkbox" id="sev-error" checked> <span class="dot dot-error"></span>Error</label>
        <label><input type="checkbox" id="sev-warning" checked> <span class="dot dot-warning"></span>Warning</label>
        <label><input type="checkbox" id="sev-info" checked> <span class="dot dot-info"></span>Info</label>
      </div>
    </div>
    <div class="filter-group">
      <label for="filter-category">Category:</label>
      <select id="filter-category"><option value="all">All Categories</option></select>
    </div>
    <div class="filter-group">
      <label for="filter-file">File:</label>
      <select id="filter-file"><option value="all">All Files</option></select>
    </div>
    <div class="filter-group">
      <label for="filter-fixstatus">Status:</label>
      <select id="filter-fixstatus">
        <option value="all">All</option>
        <option value="pending">Pending</option>
        <option value="fixed">Fixed</option>
        <option value="verified">Verified</option>
        <option value="ignored">Ignored</option>
        <option value="fix-failed">Fix Failed</option>
      </select>
    </div>
    <div class="filter-group">
      <label for="filter-search">Search:</label>
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
  const categorySelect = document.getElementById('filter-category');
  const fileSelect = document.getElementById('filter-file');
  const fixStatusSelect = document.getElementById('filter-fixstatus');
  const searchInput = document.getElementById('filter-search');
  const resultsBody = document.getElementById('results-body');
  const resultsInfo = document.getElementById('results-info');
  const summaryEl = document.getElementById('summary');
  const emptyState = document.getElementById('empty-state');

  // Event listeners for filters
  sevError.addEventListener('change', applyFilters);
  sevWarning.addEventListener('change', applyFilters);
  sevInfo.addEventListener('change', applyFilters);
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
  document.getElementById('btn-copy').addEventListener('click', () => {
    vscode.postMessage({ type: 'copyToClipboard' });
  });
  document.getElementById('btn-csv').addEventListener('click', () => {
    vscode.postMessage({ type: 'exportCSV' });
  });
  document.getElementById('btn-json').addEventListener('click', () => {
    vscode.postMessage({ type: 'exportJSON' });
  });
  document.getElementById('btn-sarif').addEventListener('click', () => {
    vscode.postMessage({ type: 'exportSARIF' });
  });

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
      + '<button class="btn-ignore" data-key="' + escapeAttr(item.issueKey) + '">Ignore</button>';
  }

  function renderTable() {
    const html = filteredResults.map(item => {
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

    resultsBody.innerHTML = html;

    // Navigate on row click (but not on button clicks)
    resultsBody.querySelectorAll('tr.issue-row, tr.suggestion-row').forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('.btn-fix') || e.target.closest('.btn-ignore') || e.target.closest('.btn-reset') || e.target.closest('.btn-verify')) return;
        const file = row.getAttribute('data-file');
        const line = parseInt(row.getAttribute('data-line'));
        const col = parseInt(row.getAttribute('data-col'));
        if (file) {
          vscode.postMessage({ type: 'navigateToFile', filePath: file, line: line, column: col });
        }
      });
    });

    // AI Fix buttons
    resultsBody.querySelectorAll('.btn-fix').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const key = btn.getAttribute('data-key');
        const item = findItemByKey(key);
        if (item) {
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
        }
      });
    });

    // Ignore buttons
    resultsBody.querySelectorAll('.btn-ignore').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const key = btn.getAttribute('data-key');
        const item = findItemByKey(key);
        if (item) {
          vscode.postMessage({
            type: 'ignoreIssue',
            issueData: {
              filePath: item.filePath, relativePath: item.relativePath,
              line: item.line, code: item.code, pattern: item.pattern,
            }
          });
        }
      });
    });

    // Reset buttons
    resultsBody.querySelectorAll('.btn-reset').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const key = btn.getAttribute('data-key');
        vscode.postMessage({ type: 'resetIssueStatus', issueKey: key });
      });
    });

    // Verify buttons
    resultsBody.querySelectorAll('.btn-verify').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const key = btn.getAttribute('data-key');
        const item = findItemByKey(key);
        if (item) {
          vscode.postMessage({
            type: 'verifyIssue',
            issueData: {
              filePath: item.filePath, relativePath: item.relativePath,
              line: item.line, code: item.code, pattern: item.pattern,
            }
          });
        }
      });
    });
  }

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
