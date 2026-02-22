import * as vscode from 'vscode';
import { RuleIntelligenceStore } from './ruleIntelligence';
import { FixPatternMemory } from './fixPatternMemory';
import { CodebaseProfile } from './codebaseProfile';
import { ScanHistoryStore } from './scanHistoryStore';
import { generateInsights, Insight } from './scanInsights';

export class LearningPanel implements vscode.Disposable {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private extensionUri: vscode.Uri,
    private ruleIntelligence: RuleIntelligenceStore,
    private fixPatternMemory: FixPatternMemory,
    private codebaseProfile: CodebaseProfile,
    private scanHistory: ScanHistoryStore,
  ) {
    this.ruleIntelligence.onDidChange(() => {
      this.refresh();
    }, null, this.disposables);
  }

  show(): void {
    if (this.panel) {
      this.panel.reveal(vscode.ViewColumn.Two);
      this.sendData();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      'caspianLearningDashboard',
      'Caspian Learning Dashboard',
      vscode.ViewColumn.Two,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    this.panel.onDidDispose(() => {
      this.panel = undefined;
    }, null, this.disposables);

    this.panel.webview.onDidReceiveMessage(
      (msg) => this.handleMessage(msg),
      null,
      this.disposables
    );

    this.panel.webview.html = this.getHtml();
    this.sendData();
  }

  refresh(): void {
    if (this.panel) {
      this.sendData();
    }
  }

  private sendData(): void {
    if (!this.panel) { return; }

    const insights = generateInsights(
      this.ruleIntelligence, this.fixPatternMemory,
      this.codebaseProfile, this.scanHistory
    );

    const allStats = this.ruleIntelligence.getAllStats();
    const ruleRows = Object.values(allStats).map(s => ({
      ruleCode: s.ruleCode,
      detections: s.detections,
      fpRate: this.ruleIntelligence.getFalsePositiveRate(s.ruleCode),
      effectiveness: this.ruleIntelligence.getEffectivenessScore(s.ruleCode),
      aiFixSuccess: this.ruleIntelligence.getAIFixSuccessRate(s.ruleCode),
      fixed: s.fixed,
      ignored: s.ignored,
      falsePositives: s.falsePositives,
      verified: s.verified,
      fixFailed: s.fixFailed,
    }));

    const patternStats = this.fixPatternMemory.getPatternStats();
    const patterns = this.fixPatternMemory.getAllPatterns().slice(0, 20).map(p => ({
      ruleCode: p.ruleCode,
      languageId: p.languageId,
      originalBefore: p.originalBefore,
      originalAfter: p.originalAfter,
      timesApplied: p.timesApplied,
      timesSucceeded: p.timesSucceeded,
      successRate: p.timesApplied > 0 ? Math.round((p.timesSucceeded / p.timesApplied) * 100) : 0,
    }));

    const hotZones = this.codebaseProfile.getHotZones();
    const postureTrend = this.codebaseProfile.getPostureTrend();
    const regressions = this.codebaseProfile.getUnacknowledgedRegressions();

    this.panel.webview.postMessage({
      type: 'update',
      data: {
        overview: {
          totalScans: this.ruleIntelligence.getTotalScans(),
          totalObservations: this.ruleIntelligence.getTotalObservations(),
          totalPatterns: patternStats.total,
          patternSuccessRate: Math.round(patternStats.avgSuccessRate * 100),
          totalRules: ruleRows.length,
        },
        ruleRows,
        insights: insights.map(i => ({
          type: i.type,
          severity: i.severity,
          title: i.title,
          detail: i.detail,
          actionLabel: i.actionLabel,
          actionCommand: i.actionCommand,
        })),
        patterns,
        hotZones,
        postureTrend: postureTrend.slice(-20),
        regressions,
      },
    });
  }

  private handleMessage(msg: any): void {
    switch (msg.command) {
      case 'runAction':
        if (msg.actionCommand) {
          vscode.commands.executeCommand(msg.actionCommand);
        }
        break;
      case 'resetLearning':
        this.ruleIntelligence.clearAll();
        this.fixPatternMemory.clearAll();
        this.codebaseProfile.clearAll();
        vscode.window.showInformationMessage('Caspian Security: All learning data has been reset.');
        this.sendData();
        break;
      case 'exportLearning':
        this.exportLearningData();
        break;
    }
  }

  private async exportLearningData(): Promise<void> {
    const data = {
      ruleIntelligence: this.ruleIntelligence.exportData(),
      fixPatterns: this.fixPatternMemory.exportData(),
      codebaseProfile: this.codebaseProfile.exportData(),
    };

    const uri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file('caspian-learning-data.json'),
      filters: { 'JSON Files': ['json'] },
    });

    if (uri) {
      const fs = await import('fs');
      fs.writeFileSync(uri.fsPath, JSON.stringify(data, null, 2), 'utf-8');
      vscode.window.showInformationMessage(`Learning data exported to ${uri.fsPath}`);
    }
  }

  private getHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Caspian Learning Dashboard</title>
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); background: var(--vscode-editor-background); padding: 16px; margin: 0; }
  h1 { font-size: 1.4em; margin: 0 0 16px; }
  h2 { font-size: 1.1em; margin: 20px 0 10px; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 4px; }
  .overview { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }
  .stat-card { background: var(--vscode-editorWidget-background); border: 1px solid var(--vscode-panel-border); border-radius: 6px; padding: 12px 16px; min-width: 120px; }
  .stat-card .value { font-size: 1.6em; font-weight: bold; color: var(--vscode-textLink-foreground); }
  .stat-card .label { font-size: 0.85em; color: var(--vscode-descriptionForeground); margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--vscode-panel-border); }
  th { background: var(--vscode-editorWidget-background); font-weight: 600; cursor: pointer; user-select: none; }
  th:hover { color: var(--vscode-textLink-foreground); }
  .bar { display: inline-block; height: 12px; border-radius: 2px; min-width: 2px; }
  .bar-green { background: #4caf50; }
  .bar-red { background: #f44336; }
  .bar-orange { background: #ff9800; }
  .bar-blue { background: #2196f3; }
  .insight { padding: 10px 14px; margin: 6px 0; border-radius: 6px; border-left: 4px solid; }
  .insight-warning { border-color: #f44336; background: rgba(244,67,54,0.08); }
  .insight-suggestion { border-color: #ff9800; background: rgba(255,152,0,0.08); }
  .insight-celebration { border-color: #4caf50; background: rgba(76,175,80,0.08); }
  .insight-info { border-color: #2196f3; background: rgba(33,150,243,0.08); }
  .insight .title { font-weight: 600; margin-bottom: 4px; }
  .insight .detail { font-size: 0.9em; color: var(--vscode-descriptionForeground); }
  .insight .action-btn { margin-top: 6px; padding: 3px 10px; background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; border-radius: 3px; cursor: pointer; font-size: 0.85em; }
  .insight .action-btn:hover { background: var(--vscode-button-hoverBackground); }
  .pattern-card { background: var(--vscode-editorWidget-background); border: 1px solid var(--vscode-panel-border); border-radius: 6px; padding: 10px; margin: 6px 0; }
  .pattern-card code { font-family: var(--vscode-editor-font-family); font-size: 0.85em; }
  .pattern-card .before { color: #f44336; }
  .pattern-card .after { color: #4caf50; }
  .controls { margin-top: 24px; display: flex; gap: 10px; }
  .controls button { padding: 6px 14px; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); border: none; border-radius: 4px; cursor: pointer; }
  .controls button:hover { background: var(--vscode-button-secondaryHoverBackground); }
  .controls button.danger { background: #f44336; color: white; }
  .empty { color: var(--vscode-descriptionForeground); font-style: italic; padding: 10px 0; }
</style>
</head>
<body>
<h1>Caspian Learning Dashboard</h1>

<div class="overview" id="overview"></div>

<h2>Active Insights</h2>
<div id="insights"><div class="empty">No insights yet. Run some scans and interact with findings.</div></div>

<h2>Rule Effectiveness</h2>
<div style="overflow-x:auto"><table id="ruleTable">
  <thead><tr>
    <th data-sort="ruleCode">Rule</th>
    <th data-sort="detections">Detections</th>
    <th data-sort="fpRate">FP Rate</th>
    <th data-sort="effectiveness">Effectiveness</th>
    <th data-sort="aiFixSuccess">AI Fix Rate</th>
    <th>Actions</th>
  </tr></thead>
  <tbody></tbody>
</table></div>

<h2>Fix Pattern Library</h2>
<div id="patterns"><div class="empty">No fix patterns learned yet.</div></div>

<h2>Codebase Hot Zones</h2>
<div id="hotZones"><div class="empty">Not enough data yet.</div></div>

<h2>Security Trend</h2>
<div id="trend"><div class="empty">Run more scans to see trends.</div></div>

<div class="controls">
  <button onclick="exportLearning()">Export Learning Data</button>
  <button class="danger" onclick="resetLearning()">Reset All Learning</button>
</div>

<script>
const vscode = acquireVsCodeApi();
let currentData = null;
let sortKey = 'detections';
let sortAsc = false;

window.addEventListener('message', e => {
  if (e.data.type === 'update') {
    currentData = e.data.data;
    render();
  }
});

function render() {
  if (!currentData) return;
  renderOverview(currentData.overview);
  renderInsights(currentData.insights);
  renderRuleTable(currentData.ruleRows);
  renderPatterns(currentData.patterns);
  renderHotZones(currentData.hotZones);
  renderTrend(currentData.postureTrend);
}

function renderOverview(o) {
  document.getElementById('overview').innerHTML =
    card(o.totalScans, 'Scans Analyzed') +
    card(o.totalObservations, 'Observations') +
    card(o.totalRules, 'Rules Tracked') +
    card(o.totalPatterns, 'Fix Patterns') +
    card(o.patternSuccessRate + '%', 'Pattern Success');
}

function card(value, label) {
  return '<div class="stat-card"><div class="value">' + value + '</div><div class="label">' + label + '</div></div>';
}

function renderInsights(insights) {
  const el = document.getElementById('insights');
  if (!insights.length) { el.innerHTML = '<div class="empty">No insights yet. Run some scans and interact with findings.</div>'; return; }
  el.innerHTML = insights.map(i => {
    let html = '<div class="insight insight-' + i.severity + '">';
    html += '<div class="title">' + esc(i.title) + '</div>';
    html += '<div class="detail">' + esc(i.detail) + '</div>';
    if (i.actionLabel && i.actionCommand) {
      html += '<button class="action-btn" onclick="runAction(\\''+i.actionCommand+'\\')">'+esc(i.actionLabel)+'</button>';
    }
    html += '</div>';
    return html;
  }).join('');
}

function renderRuleTable(rows) {
  rows.sort((a,b) => {
    const av = a[sortKey], bv = b[sortKey];
    return sortAsc ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1);
  });
  const tbody = document.querySelector('#ruleTable tbody');
  tbody.innerHTML = rows.map(r => {
    const fpPct = Math.round(r.fpRate * 100);
    const effPct = Math.round(r.effectiveness * 100);
    const aiPct = Math.round(r.aiFixSuccess * 100);
    return '<tr>' +
      '<td><strong>' + esc(r.ruleCode) + '</strong></td>' +
      '<td>' + r.detections + '</td>' +
      '<td>' + bar(fpPct, fpPct > 60 ? 'red' : fpPct > 30 ? 'orange' : 'green') + ' ' + fpPct + '%</td>' +
      '<td>' + bar(effPct, effPct > 60 ? 'green' : effPct > 30 ? 'orange' : 'red') + ' ' + effPct + '%</td>' +
      '<td>' + bar(aiPct, 'blue') + ' ' + aiPct + '%</td>' +
      '<td>' + r.fixed + 'F ' + r.ignored + 'I ' + r.falsePositives + 'FP ' + r.verified + 'V</td>' +
      '</tr>';
  }).join('');
}

function bar(pct, color) {
  return '<span class="bar bar-' + color + '" style="width:' + Math.max(2, pct * 0.6) + 'px"></span>';
}

function renderPatterns(patterns) {
  const el = document.getElementById('patterns');
  if (!patterns.length) { el.innerHTML = '<div class="empty">No fix patterns learned yet.</div>'; return; }
  el.innerHTML = patterns.map(p =>
    '<div class="pattern-card">' +
    '<strong>' + esc(p.ruleCode) + '</strong> (' + p.languageId + ') — ' +
    p.timesApplied + 'x applied, ' + p.successRate + '% success<br>' +
    '<code class="before">- ' + esc(p.originalBefore) + '</code><br>' +
    '<code class="after">+ ' + esc(p.originalAfter) + '</code>' +
    '</div>'
  ).join('');
}

function renderHotZones(zones) {
  const el = document.getElementById('hotZones');
  if (!zones.length) { el.innerHTML = '<div class="empty">Not enough data yet.</div>'; return; }
  el.innerHTML = '<table><tr><th>Zone</th><th>Confirmed</th><th>Total</th><th>Risk</th></tr>' +
    zones.map(z =>
      '<tr><td>' + esc(z.directory) + '</td><td>' + z.confirmedIssues +
      '</td><td>' + z.totalDetections + '</td><td>' +
      bar(Math.round(z.riskScore*100), z.riskScore > 0.5 ? 'red' : 'orange') + ' ' +
      Math.round(z.riskScore*100) + '%</td></tr>'
    ).join('') + '</table>';
}

function renderTrend(snapshots) {
  const el = document.getElementById('trend');
  if (!snapshots.length) { el.innerHTML = '<div class="empty">Run more scans to see trends.</div>'; return; }
  const max = Math.max(...snapshots.map(s => s.totalIssues), 1);
  el.innerHTML = '<div style="display:flex;align-items:end;gap:3px;height:80px;">' +
    snapshots.map(s => {
      const h = Math.max(2, (s.totalIssues / max) * 70);
      const color = s.totalIssues > (max * 0.7) ? '#f44336' : s.totalIssues > (max * 0.4) ? '#ff9800' : '#4caf50';
      return '<div style="width:14px;height:'+h+'px;background:'+color+';border-radius:2px 2px 0 0" title="'+s.totalIssues+' issues"></div>';
    }).join('') + '</div>';
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function runAction(cmd) { vscode.postMessage({ command: 'runAction', actionCommand: cmd }); }
function resetLearning() {
  if (confirm('Reset all learning data? This cannot be undone.')) {
    vscode.postMessage({ command: 'resetLearning' });
  }
}
function exportLearning() { vscode.postMessage({ command: 'exportLearning' }); }

document.querySelectorAll('#ruleTable th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (sortKey === key) { sortAsc = !sortAsc; } else { sortKey = key; sortAsc = false; }
    if (currentData) renderRuleTable(currentData.ruleRows);
  });
});
</script>
</body></html>`;
  }

  dispose(): void {
    this.panel?.dispose();
    for (const d of this.disposables) { d.dispose(); }
  }
}
