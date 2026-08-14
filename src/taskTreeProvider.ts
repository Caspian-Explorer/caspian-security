import * as vscode from 'vscode';
import { TaskStore } from './taskStore';
import { getTaskDefinition } from './taskCatalog';
import {
  TaskInstance,
  TaskStatus,
  INTERVAL_LABELS,
  TaskInterval,
} from './taskTypes';
import { CATEGORY_LABELS, SecurityCategory } from './types';
import { getNonce } from './webviewUtils';

/** Which surface the checklist UI is rendered into. */
type TaskSurface = 'sidebar' | 'tab';

interface TaskGroup {
  label: string;
  icon: string;
  colorClass: string;
  tasks: TaskViewData[];
}

interface TaskViewData {
  taskId: string;
  title: string;
  meta: string;
  status: string;
  priority: number;
}

export class TaskChecklistViewProvider implements vscode.WebviewViewProvider, vscode.Disposable {
  public static readonly viewType = 'caspianSecurityTasks';
  private view?: vscode.WebviewView;
  private tabPanel?: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private extensionUri: vscode.Uri,
    private taskStore: TaskStore,
  ) {
    this.disposables.push(
      this.taskStore.onDidChange(() => {
        this.refresh();
      })
    );
  }

  resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this.extensionUri],
    };
    webviewView.webview.html = this.getHtml('sidebar');
    webviewView.webview.onDidReceiveMessage(
      (msg) => this.handleMessage(msg),
      null,
      this.disposables,
    );
    this.sendData();
  }

  /**
   * Open the checklist as a full editor tab. The sidebar view is cramped, so
   * this promotes the same UI into the main editor area. Reveals the existing
   * tab instead of opening a duplicate.
   */
  openTab(): void {
    if (this.tabPanel) {
      this.tabPanel.reveal(vscode.ViewColumn.One);
      this.sendData();
      return;
    }

    this.tabPanel = vscode.window.createWebviewPanel(
      'caspianSecurityTaskDashboard',
      'Security Tasks',
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [this.extensionUri],
      },
    );

    this.tabPanel.onDidDispose(() => {
      this.tabPanel = undefined;
    }, null, this.disposables);

    this.tabPanel.webview.onDidReceiveMessage(
      (msg) => this.handleMessage(msg),
      null,
      this.disposables,
    );

    this.tabPanel.webview.html = this.getHtml('tab');
    this.sendData();
  }

  refresh(): void {
    this.sendData();
  }

  /** Push the current task groups to every live surface (sidebar + editor tab). */
  private sendData(): void {
    const groups = this.buildGroups();
    const msg = { type: 'update', groups };
    this.view?.webview.postMessage(msg);
    this.tabPanel?.webview.postMessage(msg);
  }

  private handleMessage(msg: { command: string; taskId?: string }): void {
    switch (msg.command) {
      case 'showDetail':
        if (msg.taskId) {
          vscode.commands.executeCommand('caspian-security.showTaskDetail', msg.taskId);
        }
        break;
    }
  }

  private buildGroups(): TaskGroup[] {
    const buckets: Record<string, TaskViewData[]> = {
      overdue: [],
      pending: [],
      completed: [],
      snoozed: [],
      dismissed: [],
    };

    for (const instance of this.taskStore.getAllInstances()) {
      const def = getTaskDefinition(instance.taskId);
      const title = def?.title || instance.taskId;
      const interval = INTERVAL_LABELS[(instance.intervalOverride || def?.defaultInterval || TaskInterval.Monthly) as TaskInterval];
      const category = def?.category
        ? CATEGORY_LABELS[def.category as SecurityCategory] || def.category
        : '';

      let meta = '';
      switch (instance.status) {
        case TaskStatus.Overdue:
          meta = `Overdue ${this.fmtDate(instance.nextDueAt)}`;
          break;
        case TaskStatus.Snoozed:
          meta = instance.snoozeUntil
            ? `Snoozed until ${this.fmtDate(instance.snoozeUntil)}`
            : 'Snoozed';
          break;
        case TaskStatus.Completed:
          meta = instance.lastCompletedAt
            ? `Done ${this.fmtDate(instance.lastCompletedAt)}`
            : 'Completed';
          break;
        case TaskStatus.Dismissed:
          meta = instance.dismissedAt
            ? `Dismissed ${this.fmtDate(instance.dismissedAt)}`
            : 'Dismissed';
          break;
        default:
          meta = `Due ${this.fmtDate(instance.nextDueAt)}`;
          break;
      }

      meta += ` · ${interval}`;
      if (category) { meta += ` · ${category}`; }

      const data: TaskViewData = {
        taskId: instance.taskId,
        title,
        meta,
        status: instance.status,
        priority: def?.priority || 0,
      };

      switch (instance.status) {
        case TaskStatus.Overdue: buckets.overdue.push(data); break;
        case TaskStatus.Pending: buckets.pending.push(data); break;
        case TaskStatus.Completed: buckets.completed.push(data); break;
        case TaskStatus.Snoozed: buckets.snoozed.push(data); break;
        case TaskStatus.Dismissed: buckets.dismissed.push(data); break;
      }
    }

    for (const key of Object.keys(buckets)) {
      buckets[key].sort((a, b) => b.priority - a.priority);
    }

    const groups: TaskGroup[] = [];
    if (buckets.overdue.length > 0) {
      groups.push({ label: 'Overdue', icon: '\u26A0', colorClass: 'status-overdue', tasks: buckets.overdue });
    }
    if (buckets.pending.length > 0) {
      groups.push({ label: 'Pending', icon: '\u25CB', colorClass: 'status-pending', tasks: buckets.pending });
    }
    if (buckets.completed.length > 0) {
      groups.push({ label: 'Completed', icon: '\u2713', colorClass: 'status-completed', tasks: buckets.completed });
    }
    if (buckets.snoozed.length > 0) {
      groups.push({ label: 'Snoozed', icon: '\u23F0', colorClass: 'status-snoozed', tasks: buckets.snoozed });
    }
    if (buckets.dismissed.length > 0) {
      groups.push({ label: 'Dismissed', icon: '\u2298', colorClass: 'status-dismissed', tasks: buckets.dismissed });
    }
    return groups;
  }

  private fmtDate(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }

  private getHtml(surface: TaskSurface): string {
    const nonce = getNonce();
    return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--vscode-font-family);
  font-size: var(--vscode-font-size);
  color: var(--vscode-foreground);
  background: transparent;
  padding: 0;
}

/* ── Groups ── */
.group { margin-bottom: 4px; }
.group-header {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  cursor: pointer;
  user-select: none;
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--vscode-foreground);
}
.group-header:hover { background: var(--vscode-list-hoverBackground); }

.chevron {
  display: inline-block;
  font-size: 12px;
  transition: transform 0.15s;
}
.group.collapsed .chevron { transform: rotate(-90deg); }
.group.collapsed .group-items { display: none; }

.group-icon { font-size: 13px; line-height: 1; }
.group-count {
  margin-left: auto;
  font-size: 11px;
  font-weight: normal;
  color: var(--vscode-descriptionForeground);
  background: var(--vscode-badge-background);
  color: var(--vscode-badge-foreground);
  padding: 0 6px;
  border-radius: 8px;
  min-width: 18px;
  text-align: center;
}

/* Status colors */
.status-overdue .group-icon { color: var(--vscode-errorForeground); }
.status-pending .group-icon { color: var(--vscode-foreground); opacity: 0.7; }
.status-completed .group-icon { color: var(--vscode-testing-iconPassed, #73c991); }
.status-snoozed .group-icon { color: var(--vscode-editorWarning-foreground); }
.status-dismissed .group-icon { color: var(--vscode-descriptionForeground); }

/* ── Task items ── */
.task-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 5px 8px 5px 20px;
  cursor: pointer;
  border-radius: 3px;
}
.task-item:hover { background: var(--vscode-list-hoverBackground); }
.task-item:active { background: var(--vscode-list-activeSelectionBackground); }

.task-icon {
  flex-shrink: 0;
  font-size: 13px;
  line-height: 20px;
  width: 16px;
  text-align: center;
}
.task-item .status-overdue { color: var(--vscode-errorForeground); }
.task-item .status-pending { color: var(--vscode-foreground); opacity: 0.6; }
.task-item .status-completed { color: var(--vscode-testing-iconPassed, #73c991); }
.task-item .status-snoozed { color: var(--vscode-editorWarning-foreground); }
.task-item .status-dismissed { color: var(--vscode-descriptionForeground); }

.task-content {
  flex: 1;
  min-width: 0;
  overflow: hidden;
}
.task-title {
  font-size: 13px;
  line-height: 20px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  color: var(--vscode-foreground);
}
.task-meta {
  font-size: 11px;
  line-height: 16px;
  color: var(--vscode-descriptionForeground);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ── Empty state ── */
.empty-state {
  padding: 16px;
  text-align: center;
  color: var(--vscode-descriptionForeground);
  font-size: 12px;
}

/* ── Editor tab surface ──
   The sidebar is transparent and truncates with ellipsis to survive the narrow
   column; neither is right once the same UI has the full editor width. */
body[data-surface="tab"] {
  background: var(--vscode-editor-background);
  padding: 16px 0;
}
body[data-surface="tab"] #root { max-width: 900px; margin: 0 auto; }
body[data-surface="tab"] .group { margin-bottom: 12px; }
body[data-surface="tab"] .group-header { padding: 8px 12px; font-size: 12px; }
body[data-surface="tab"] .task-item { padding: 8px 12px 8px 28px; }
body[data-surface="tab"] .task-title,
body[data-surface="tab"] .task-meta {
  white-space: normal;
  overflow: visible;
  text-overflow: clip;
}
body[data-surface="tab"] .empty-state { padding: 32px; }
</style>
</head>
<body data-surface="${surface}">
<div id="root"></div>
<script nonce="${nonce}">
(function() {
  const vscode = acquireVsCodeApi();
  const root = document.getElementById('root');

  // Track collapsed state
  const collapsedGroups = {};

  window.addEventListener('message', e => {
    if (e.data.type === 'update') {
      render(e.data.groups);
    }
  });

  function render(groups) {
    if (!groups || groups.length === 0) {
      root.innerHTML = '<div class="empty-state">No security tasks configured.</div>';
      return;
    }

    root.innerHTML = '';
    for (const g of groups) {
      const groupEl = document.createElement('div');
      groupEl.className = 'group' + (collapsedGroups[g.label] ? ' collapsed' : '');

      // Header
      const header = document.createElement('div');
      header.className = 'group-header ' + g.colorClass;
      header.innerHTML =
        '<span class="chevron">&#9662;</span>' +
        '<span class="group-icon">' + escHtml(g.icon) + '</span>' +
        '<span>' + escHtml(g.label) + '</span>' +
        '<span class="group-count">' + g.tasks.length + '</span>';
      header.addEventListener('click', () => {
        collapsedGroups[g.label] = !collapsedGroups[g.label];
        groupEl.classList.toggle('collapsed');
      });
      groupEl.appendChild(header);

      // Items
      const items = document.createElement('div');
      items.className = 'group-items';
      for (const t of g.tasks) {
        const item = document.createElement('div');
        item.className = 'task-item';
        item.innerHTML =
          '<span class="task-icon ' + statusClass(t.status) + '">' + escHtml(g.icon) + '</span>' +
          '<div class="task-content">' +
            '<div class="task-title">' + escHtml(t.title) + '</div>' +
            '<div class="task-meta">' + escHtml(t.meta) + '</div>' +
          '</div>';
        item.addEventListener('click', () => {
          vscode.postMessage({ command: 'showDetail', taskId: t.taskId });
        });
        items.appendChild(item);
      }
      groupEl.appendChild(items);
      root.appendChild(groupEl);
    }
  }

  function statusClass(s) {
    return 'status-' + s;
  }

  function escHtml(s) {
    const el = document.createElement('span');
    el.textContent = s;
    return el.innerHTML;
  }
})();
</script>
</body>
</html>`;
  }

  dispose(): void {
    this.tabPanel?.dispose();
    this.tabPanel = undefined;
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
