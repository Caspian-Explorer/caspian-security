import * as vscode from 'vscode';
import * as fs from 'fs';
import { ResultsStore } from './resultsStore';
import { SecuritySeverity, SecurityCategory, CATEGORY_LABELS, SEVERITY_LABELS } from './types';

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
}

export class ResultsPanel implements vscode.Disposable {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private extensionUri: vscode.Uri,
    private resultsStore: ResultsStore,
  ) {
    this.resultsStore.onDidChange(() => {
      this.refresh();
    }, null, this.disposables);
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
      result.issues.map(issue => ({
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
      }))
    );

    const summary = this.resultsStore.getSummary();

    this.panel.webview.postMessage({
      type: 'updateResults',
      data: { results: serialized, summary },
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
      max-height: calc(100vh - 220px);
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

    .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
    .dot-error { background: var(--vscode-errorForeground, #f44336); }
    .dot-warning { background: var(--vscode-editorWarning-foreground, #ff9800); }
    .dot-info { background: var(--vscode-editorInfo-foreground, #2196f3); }
  </style>
</head>
<body>
  <div class="header">
    <h1>Caspian Security Results</h1>
    <div class="header-actions">
      <button class="btn btn-secondary" id="btn-copy" title="Copy all results to clipboard">Copy All</button>
      <button class="btn btn-secondary" id="btn-csv" title="Export results as CSV">Export CSV</button>
      <button class="btn btn-secondary" id="btn-json" title="Export results as JSON">Export JSON</button>
    </div>
  </div>

  <div class="summary" id="summary">
    <span class="summary-item">No scan results yet</span>
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
        </tr>
      </thead>
      <tbody id="results-body"></tbody>
    </table>
    <div class="empty-state" id="empty-state">
      <h2>No results yet</h2>
      <p>Run a security scan to see results here.</p>
    </div>
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
  document.getElementById('btn-copy').addEventListener('click', () => {
    vscode.postMessage({ type: 'copyToClipboard' });
  });
  document.getElementById('btn-csv').addEventListener('click', () => {
    vscode.postMessage({ type: 'exportCSV' });
  });
  document.getElementById('btn-json').addEventListener('click', () => {
    vscode.postMessage({ type: 'exportJSON' });
  });

  // Receive data from extension
  window.addEventListener('message', event => {
    const msg = event.data;
    if (msg.type === 'updateResults') {
      allResults = msg.data.results;
      updateDropdowns();
      applyFilters();
      renderSummary(msg.data.summary);
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
    const searchText = searchInput.value.toLowerCase();

    filteredResults = allResults.filter(item => {
      if (!activeSeverities.has(item.severityLabel)) return false;
      if (selectedCategory !== 'all' && item.categoryLabel !== selectedCategory) return false;
      if (selectedFile !== 'all' && item.relativePath !== selectedFile) return false;
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

  function renderTable() {
    const html = filteredResults.map(item => {
      const sevClass = 'severity-' + item.severityLabel.toLowerCase();
      return '<tr class="issue-row" data-file="' + escapeAttr(item.filePath) + '" data-line="' + item.line + '" data-col="' + item.column + '">'
        + '<td class="' + sevClass + '">' + escapeHtml(item.severityLabel) + '</td>'
        + '<td class="code-cell">' + escapeHtml(item.code) + '</td>'
        + '<td class="file-cell" title="' + escapeAttr(item.filePath) + '">' + escapeHtml(item.relativePath) + '</td>'
        + '<td>' + (item.line + 1) + '</td>'
        + '<td class="message-cell">' + escapeHtml(item.message) + '</td>'
        + '</tr>'
        + '<tr class="suggestion-row" data-file="' + escapeAttr(item.filePath) + '" data-line="' + item.line + '" data-col="' + item.column + '">'
        + '<td colspan="5">Suggestion: ' + escapeHtml(item.suggestion) + '</td>'
        + '</tr>';
    }).join('');

    resultsBody.innerHTML = html;

    resultsBody.querySelectorAll('tr').forEach(row => {
      row.addEventListener('click', () => {
        const file = row.getAttribute('data-file');
        const line = parseInt(row.getAttribute('data-line'));
        const col = parseInt(row.getAttribute('data-col'));
        if (file) {
          vscode.postMessage({ type: 'navigateToFile', filePath: file, line: line, column: col });
        }
      });
    });
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
