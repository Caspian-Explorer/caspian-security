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

type TreeElement = StatusGroupItem | TaskTreeItem;

class StatusGroupItem extends vscode.TreeItem {
  public readonly taskIds: string[];

  constructor(
    statusLabel: string,
    taskIds: string[],
  ) {
    super(statusLabel, vscode.TreeItemCollapsibleState.Expanded);
    this.taskIds = taskIds;
    this.description = `${taskIds.length}`;
    this.contextValue = 'taskStatusGroup';
  }
}

class TaskTreeItem extends vscode.TreeItem {
  public readonly taskId: string;

  constructor(
    taskId: string,
    instance: TaskInstance,
  ) {
    const def = getTaskDefinition(taskId);
    super(def?.title || taskId, vscode.TreeItemCollapsibleState.None);
    this.taskId = taskId;

    this.description = this.buildDescription(instance);
    this.tooltip = this.buildTooltip(instance);
    this.contextValue = `task-${instance.status}`;
    this.command = {
      command: 'caspian-security.showTaskDetail',
      title: 'Show Task Details',
      arguments: [taskId],
    };

    switch (instance.status) {
      case TaskStatus.Overdue:
        this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
        break;
      case TaskStatus.Pending:
        this.iconPath = new vscode.ThemeIcon('circle-outline');
        break;
      case TaskStatus.Completed:
        this.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
        break;
      case TaskStatus.Snoozed:
        this.iconPath = new vscode.ThemeIcon('clock');
        break;
      case TaskStatus.Dismissed:
        this.iconPath = new vscode.ThemeIcon('circle-slash');
        break;
    }
  }

  private buildDescription(instance: TaskInstance): string {
    if (instance.status === TaskStatus.Overdue) {
      return `Overdue since ${new Date(instance.nextDueAt).toLocaleDateString()}`;
    }
    if (instance.status === TaskStatus.Snoozed && instance.snoozeUntil) {
      return `Snoozed until ${new Date(instance.snoozeUntil).toLocaleDateString()}`;
    }
    if (instance.status === TaskStatus.Completed && instance.lastCompletedAt) {
      return `Done ${new Date(instance.lastCompletedAt).toLocaleDateString()}`;
    }
    return `Due ${new Date(instance.nextDueAt).toLocaleDateString()}`;
  }

  private buildTooltip(instance: TaskInstance): string {
    const def = getTaskDefinition(this.taskId);
    const lines = [
      def?.title || this.taskId,
    ];
    if (def?.category) {
      lines.push(`Category: ${CATEGORY_LABELS[def.category as SecurityCategory] || def.category}`);
    }
    lines.push('');
    if (def?.description) {
      lines.push(def.description);
    }
    lines.push('');
    lines.push(`Status: ${instance.status}`);
    lines.push(`Due: ${new Date(instance.nextDueAt).toLocaleString()}`);
    lines.push(`Interval: ${INTERVAL_LABELS[(instance.intervalOverride || def?.defaultInterval || TaskInterval.Monthly) as TaskInterval]}`);
    lines.push(`Completed ${instance.completionCount} time(s)`);
    return lines.join('\n');
  }
}

export class TaskTreeProvider implements vscode.TreeDataProvider<TreeElement>, vscode.Disposable {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeElement | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private disposables: vscode.Disposable[] = [];

  constructor(private taskStore: TaskStore) {
    this.disposables.push(
      this.taskStore.onDidChange(() => {
        this._onDidChangeTreeData.fire();
      })
    );
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeElement): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeElement): TreeElement[] {
    if (!element) {
      return this.getStatusGroups();
    }

    if (element instanceof StatusGroupItem) {
      return element.taskIds.map(id => {
        const instance = this.taskStore.getInstance(id)!;
        return new TaskTreeItem(id, instance);
      });
    }

    return [];
  }

  private getStatusGroups(): StatusGroupItem[] {
    const groups: Record<string, string[]> = {
      overdue: [],
      pending: [],
      completed: [],
      snoozed: [],
      dismissed: [],
    };

    for (const instance of this.taskStore.getAllInstances()) {
      switch (instance.status) {
        case TaskStatus.Overdue: groups.overdue.push(instance.taskId); break;
        case TaskStatus.Pending: groups.pending.push(instance.taskId); break;
        case TaskStatus.Completed: groups.completed.push(instance.taskId); break;
        case TaskStatus.Snoozed: groups.snoozed.push(instance.taskId); break;
        case TaskStatus.Dismissed: groups.dismissed.push(instance.taskId); break;
      }
    }

    for (const key of Object.keys(groups)) {
      groups[key].sort((a, b) => {
        const defA = getTaskDefinition(a);
        const defB = getTaskDefinition(b);
        return (defB?.priority || 0) - (defA?.priority || 0);
      });
    }

    const result: StatusGroupItem[] = [];
    if (groups.overdue.length > 0) {
      result.push(new StatusGroupItem('$(warning) Overdue', groups.overdue));
    }
    if (groups.pending.length > 0) {
      result.push(new StatusGroupItem('$(circle-outline) Pending', groups.pending));
    }
    if (groups.completed.length > 0) {
      result.push(new StatusGroupItem('$(check) Completed', groups.completed));
    }
    if (groups.snoozed.length > 0) {
      result.push(new StatusGroupItem('$(clock) Snoozed', groups.snoozed));
    }
    if (groups.dismissed.length > 0) {
      result.push(new StatusGroupItem('$(circle-slash) Dismissed', groups.dismissed));
    }

    return result;
  }

  dispose(): void {
    this._onDidChangeTreeData.dispose();
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
