import * as vscode from 'vscode';
import { TaskStore } from './taskStore';
import { getTaskDefinition } from './taskCatalog';
import {
  TaskStatus,
  TaskInterval,
  INTERVAL_LABELS,
} from './taskTypes';
import { CATEGORY_LABELS, SecurityCategory } from './types';

export class TaskDetailPanel implements vscode.Disposable {
  private panel: vscode.WebviewPanel | undefined;
  private currentTaskId: string | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private extensionUri: vscode.Uri,
    private taskStore: TaskStore,
  ) {
    this.taskStore.onDidChange(() => {
      this.refresh();
    }, null, this.disposables);
  }

  show(taskId: string): void {
    this.currentTaskId = taskId;

    if (this.panel) {
      this.panel.reveal(vscode.ViewColumn.Two);
      this.sendData();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      'caspianTaskDetail',
      'Task Detail',
      vscode.ViewColumn.Two,
      { enableScripts: true, retainContextWhenHidden: true },
    );

    this.panel.onDidDispose(() => {
      this.panel = undefined;
    }, null, this.disposables);

    this.panel.webview.onDidReceiveMessage(
      (msg) => this.handleMessage(msg),
      null,
      this.disposables,
    );

    this.panel.webview.html = this.getHtml();
    this.sendData();
  }

  refresh(): void {
    if (this.panel && this.currentTaskId) {
      this.sendData();
    }
  }

  private sendData(): void {
    if (!this.panel || !this.currentTaskId) { return; }

    const instance = this.taskStore.getInstance(this.currentTaskId);
    const def = getTaskDefinition(this.currentTaskId);

    if (!instance || !def) {
      this.panel.webview.postMessage({ type: 'noTask' });
      return;
    }

    this.panel.title = def.title;

    const fmt = (iso: string | null): string | null => {
      if (!iso) { return null; }
      return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    };

    this.panel.webview.postMessage({
      type: 'update',
      data: {
        taskId: def.id,
        title: def.title,
        description: def.description,
        status: instance.status,
        priority: def.priority,
        categoryLabel: CATEGORY_LABELS[def.category as SecurityCategory] || def.category,
        intervalLabel: INTERVAL_LABELS[(instance.intervalOverride || def.defaultInterval) as TaskInterval],
        lastCompletedAt: fmt(instance.lastCompletedAt),
        nextDueAt: fmt(instance.nextDueAt),
        createdAt: fmt(instance.createdAt),
        snoozeUntil: fmt(instance.snoozeUntil),
        dismissedAt: fmt(instance.dismissedAt),
        completionCount: instance.completionCount,
        relatedRuleCodes: def.relatedRuleCodes || [],
        autoCompleteTrigger: def.autoCompleteTrigger,
      },
    });
  }

  private async handleMessage(msg: { command: string; durationMs?: number }): Promise<void> {
    if (!this.currentTaskId) { return; }
    const def = getTaskDefinition(this.currentTaskId);
    const title = def?.title || this.currentTaskId;

    switch (msg.command) {
      case 'markCompleted':
        this.taskStore.markCompleted(this.currentTaskId);
        vscode.window.showInformationMessage(`Caspian Security: "${title}" marked complete.`);
        break;

      case 'snooze': {
        if (!msg.durationMs) { return; }
        this.taskStore.markSnoozed(this.currentTaskId, new Date(Date.now() + msg.durationMs));
        const labels: Record<number, string> = {
          3600000: '1 hour',
          14400000: '4 hours',
          86400000: '1 day',
          259200000: '3 days',
          604800000: '1 week',
        };
        vscode.window.showInformationMessage(
          `Caspian Security: "${title}" snoozed for ${labels[msg.durationMs] || 'a while'}.`,
        );
        break;
      }

      case 'changeInterval': {
        const instance = this.taskStore.getInstance(this.currentTaskId);
        const currentInterval = instance?.intervalOverride || def?.defaultInterval || TaskInterval.Monthly;
        const items = Object.values(TaskInterval).map(interval => ({
          label: INTERVAL_LABELS[interval],
          description: interval === currentInterval ? '(current)' : undefined,
          interval,
        }));
        const picked = await vscode.window.showQuickPick(items, {
          placeHolder: `Set recurrence interval for "${title}"`,
        });
        if (picked) {
          this.taskStore.setInterval(
            this.currentTaskId,
            (picked as { label: string; interval: TaskInterval }).interval,
          );
          vscode.window.showInformationMessage(
            `Caspian Security: "${title}" interval set to ${picked.label}.`,
          );
        }
        break;
      }

      case 'dismiss':
        this.taskStore.markDismissed(this.currentTaskId);
        vscode.window.showInformationMessage(`Caspian Security: "${title}" dismissed.`);
        break;

      case 'reinstate':
        this.taskStore.reinstateTask(this.currentTaskId);
        vscode.window.showInformationMessage(`Caspian Security: "${title}" reinstated.`);
        break;
    }
  }

  private getHtml(): string {
    const nonce = getNonce();
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<title>Task Detail</title>
<style>
  body {
    font-family: var(--vscode-font-family);
    color: var(--vscode-foreground);
    background: var(--vscode-editor-background);
    padding: 24px;
    margin: 0;
    max-width: 720px;
  }

  .header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 24px;
  }

  h1 { font-size: 1.4em; margin: 0; line-height: 1.3; }
  h2 { font-size: 1.05em; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 6px; margin: 24px 0 12px; color: var(--vscode-descriptionForeground); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }

  .status-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.75em;
    font-weight: 600;
    text-transform: uppercase;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .status-overdue { background: rgba(244,67,54,0.15); color: #f44336; }
  .status-pending { background: rgba(255,152,0,0.15); color: #ff9800; }
  .status-completed { background: rgba(76,175,80,0.15); color: #4caf50; }
  .status-snoozed { background: rgba(33,150,243,0.15); color: #2196f3; }
  .status-dismissed { background: rgba(158,158,158,0.15); color: #9e9e9e; }

  .description {
    background: var(--vscode-editorWidget-background);
    border: 1px solid var(--vscode-panel-border);
    border-radius: 6px;
    padding: 14px 16px;
    line-height: 1.6;
    font-size: 0.95em;
  }

  .details-table {
    width: 100%;
    border-collapse: collapse;
  }
  .details-table td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--vscode-panel-border);
    font-size: 0.92em;
  }
  .details-table .label {
    font-weight: 600;
    width: 160px;
    color: var(--vscode-descriptionForeground);
  }
  .details-table .value {
    color: var(--vscode-foreground);
  }

  .rule-code {
    display: inline-block;
    background: var(--vscode-badge-background);
    color: var(--vscode-badge-foreground);
    padding: 1px 7px;
    border-radius: 3px;
    font-size: 0.85em;
    margin: 1px 3px 1px 0;
    font-family: var(--vscode-editor-font-family);
  }

  .actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin: 12px 0;
  }

  .btn {
    padding: 7px 18px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.9em;
    font-family: var(--vscode-font-family);
  }
  .btn-primary { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
  .btn-primary:hover { background: var(--vscode-button-hoverBackground); }
  .btn-secondary { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
  .btn-secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
  .btn-danger { background: rgba(244,67,54,0.12); color: #f44336; }
  .btn-danger:hover { background: rgba(244,67,54,0.22); }

  .snooze-options {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 10px;
    padding: 12px;
    background: var(--vscode-editorWidget-background);
    border: 1px solid var(--vscode-panel-border);
    border-radius: 6px;
  }
  .btn-small {
    padding: 5px 14px;
    font-size: 0.85em;
  }

  .empty-state {
    text-align: center;
    color: var(--vscode-descriptionForeground);
    padding: 60px 20px;
    font-style: italic;
  }

  .hidden { display: none !important; }
</style>
</head>
<body>

<div id="content" class="hidden">
  <div class="header">
    <span class="status-badge" id="statusBadge"></span>
    <h1 id="taskTitle"></h1>
  </div>

  <h2>Description</h2>
  <div class="description" id="taskDescription"></div>

  <h2>Details</h2>
  <table class="details-table">
    <tr><td class="label">Status</td><td class="value" id="detailStatus"></td></tr>
    <tr><td class="label">Priority</td><td class="value" id="detailPriority"></td></tr>
    <tr><td class="label">Interval</td><td class="value" id="detailInterval"></td></tr>
    <tr><td class="label">Category</td><td class="value" id="detailCategory"></td></tr>
    <tr><td class="label">Last Completed</td><td class="value" id="detailLastCompleted"></td></tr>
    <tr><td class="label">Next Due</td><td class="value" id="detailNextDue"></td></tr>
    <tr><td class="label">Created</td><td class="value" id="detailCreated"></td></tr>
    <tr><td class="label">Times Completed</td><td class="value" id="detailCompletionCount"></td></tr>
    <tr id="relatedRulesRow"><td class="label">Related Rules</td><td class="value" id="detailRelatedRules"></td></tr>
    <tr id="snoozeUntilRow" class="hidden"><td class="label">Snoozed Until</td><td class="value" id="detailSnoozeUntil"></td></tr>
    <tr id="dismissedAtRow" class="hidden"><td class="label">Dismissed At</td><td class="value" id="detailDismissedAt"></td></tr>
  </table>

  <h2>Actions</h2>
  <div class="actions">
    <button class="btn btn-primary" id="btnComplete" onclick="markCompleted()">Mark Complete</button>
    <button class="btn btn-secondary" id="btnSnooze" onclick="toggleSnooze()">Snooze</button>
    <button class="btn btn-secondary" id="btnInterval" onclick="changeInterval()">Change Interval</button>
    <button class="btn btn-danger" id="btnDismiss" onclick="dismiss()">Dismiss</button>
    <button class="btn btn-secondary hidden" id="btnReinstate" onclick="reinstate()">Reinstate</button>
  </div>
  <div class="snooze-options hidden" id="snoozeOptions">
    <button class="btn btn-secondary btn-small" onclick="snooze(3600000)">1 hour</button>
    <button class="btn btn-secondary btn-small" onclick="snooze(14400000)">4 hours</button>
    <button class="btn btn-secondary btn-small" onclick="snooze(86400000)">1 day</button>
    <button class="btn btn-secondary btn-small" onclick="snooze(259200000)">3 days</button>
    <button class="btn btn-secondary btn-small" onclick="snooze(604800000)">1 week</button>
  </div>
</div>

<div id="emptyState" class="empty-state">
  Task not found.
</div>

<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
let snoozeVisible = false;

window.addEventListener('message', function(e) {
  if (e.data.type === 'update') {
    document.getElementById('content').classList.remove('hidden');
    document.getElementById('emptyState').classList.add('hidden');
    render(e.data.data);
  } else if (e.data.type === 'noTask') {
    document.getElementById('content').classList.add('hidden');
    document.getElementById('emptyState').classList.remove('hidden');
  }
});

function render(d) {
  document.getElementById('taskTitle').textContent = d.title;
  document.getElementById('taskDescription').textContent = d.description;

  var badge = document.getElementById('statusBadge');
  badge.textContent = d.status.charAt(0).toUpperCase() + d.status.slice(1);
  badge.className = 'status-badge status-' + d.status;

  document.getElementById('detailStatus').textContent = d.status.charAt(0).toUpperCase() + d.status.slice(1);
  document.getElementById('detailPriority').textContent = d.priority + ' / 10';
  document.getElementById('detailInterval').textContent = d.intervalLabel;
  document.getElementById('detailCategory').textContent = d.categoryLabel;
  document.getElementById('detailLastCompleted').textContent = d.lastCompletedAt || 'Never';
  document.getElementById('detailNextDue').textContent = d.nextDueAt;
  document.getElementById('detailCreated').textContent = d.createdAt;
  document.getElementById('detailCompletionCount').textContent = String(d.completionCount);

  var rulesRow = document.getElementById('relatedRulesRow');
  var rulesCell = document.getElementById('detailRelatedRules');
  if (d.relatedRuleCodes && d.relatedRuleCodes.length > 0) {
    rulesRow.classList.remove('hidden');
    rulesCell.innerHTML = d.relatedRuleCodes.map(function(c) {
      return '<span class="rule-code">' + esc(c) + '</span>';
    }).join(' ');
  } else {
    rulesRow.classList.add('hidden');
  }

  var snoozeRow = document.getElementById('snoozeUntilRow');
  if (d.snoozeUntil) {
    snoozeRow.classList.remove('hidden');
    document.getElementById('detailSnoozeUntil').textContent = d.snoozeUntil;
  } else {
    snoozeRow.classList.add('hidden');
  }

  var dismissedRow = document.getElementById('dismissedAtRow');
  if (d.dismissedAt) {
    dismissedRow.classList.remove('hidden');
    document.getElementById('detailDismissedAt').textContent = d.dismissedAt;
  } else {
    dismissedRow.classList.add('hidden');
  }

  var isDismissed = d.status === 'dismissed';
  toggle('btnComplete', !isDismissed);
  toggle('btnSnooze', !isDismissed);
  toggle('btnInterval', !isDismissed);
  toggle('btnDismiss', !isDismissed);
  toggle('btnReinstate', isDismissed);

  if (d.status === 'completed') {
    document.getElementById('btnComplete').textContent = 'Mark Complete Again';
  } else {
    document.getElementById('btnComplete').textContent = 'Mark Complete';
  }

  snoozeVisible = false;
  document.getElementById('snoozeOptions').classList.add('hidden');
}

function toggle(id, show) {
  var el = document.getElementById(id);
  if (show) { el.classList.remove('hidden'); } else { el.classList.add('hidden'); }
}

function esc(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function markCompleted() {
  vscode.postMessage({ command: 'markCompleted' });
}

function toggleSnooze() {
  snoozeVisible = !snoozeVisible;
  var el = document.getElementById('snoozeOptions');
  if (snoozeVisible) { el.classList.remove('hidden'); } else { el.classList.add('hidden'); }
}

function snooze(ms) {
  vscode.postMessage({ command: 'snooze', durationMs: ms });
}

function changeInterval() {
  vscode.postMessage({ command: 'changeInterval' });
}

function dismiss() {
  vscode.postMessage({ command: 'dismiss' });
}

function reinstate() {
  vscode.postMessage({ command: 'reinstate' });
}
</script>
</body>
</html>`;
  }

  dispose(): void {
    this.panel?.dispose();
    for (const d of this.disposables) { d.dispose(); }
  }
}

function getNonce(): string {
  let text = '';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}
