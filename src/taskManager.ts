import * as vscode from 'vscode';
import { TaskStore } from './taskStore';
import { SECURITY_TASK_CATALOG, getTaskDefinition } from './taskCatalog';
import {
  AutoCompleteTrigger,
  TaskStatus,
  TaskInterval,
  INTERVAL_LABELS,
} from './taskTypes';
import { ConfigManager } from './configManager';

export class TaskManager implements vscode.Disposable {
  private checkTimer: ReturnType<typeof setInterval> | undefined;

  constructor(
    private taskStore: TaskStore,
    private configManager: ConfigManager,
  ) {}

  startScheduler(): void {
    this.checkAndNotify();
    this.checkTimer = setInterval(() => {
      this.checkAndNotify();
    }, 15 * 60 * 1000);
  }

  onWorkspaceScanCompleted(): void {
    this.autoCompleteTasks(AutoCompleteTrigger.WorkspaceScan);
  }

  onDependencyCheckCompleted(): void {
    this.autoCompleteTasks(AutoCompleteTrigger.DependencyCheck);
  }

  onFullScanCompleted(): void {
    this.autoCompleteTasks(AutoCompleteTrigger.FullScan);
  }

  async showTaskActions(taskId: string): Promise<void> {
    const def = getTaskDefinition(taskId);
    const instance = this.taskStore.getInstance(taskId);
    if (!def || !instance) { return; }

    const items: vscode.QuickPickItem[] = [
      { label: '$(check) Mark Completed', description: 'Mark this task as done' },
      { label: '$(clock) Snooze', description: 'Remind me later' },
      { label: '$(gear) Change Interval', description: `Currently: ${INTERVAL_LABELS[instance.intervalOverride || def.defaultInterval]}` },
    ];

    if (instance.status !== TaskStatus.Dismissed) {
      items.push({ label: '$(x) Dismiss', description: 'Do not track this task for this project' });
    } else {
      items.push({ label: '$(refresh) Reinstate', description: 'Re-enable this dismissed task' });
    }

    const picked = await vscode.window.showQuickPick(items, {
      title: def.title,
      placeHolder: def.description,
    });

    if (!picked) { return; }

    if (picked.label.includes('Mark Completed')) {
      this.taskStore.markCompleted(taskId);
      vscode.window.showInformationMessage(`Caspian Security: "${def.title}" marked complete.`);
    } else if (picked.label.includes('Snooze')) {
      await this.showSnoozeOptions(taskId, def.title);
    } else if (picked.label.includes('Change Interval')) {
      await this.showIntervalPicker(taskId, def.title, instance.intervalOverride || def.defaultInterval);
    } else if (picked.label.includes('Dismiss')) {
      this.taskStore.markDismissed(taskId);
      vscode.window.showInformationMessage(`Caspian Security: "${def.title}" dismissed.`);
    } else if (picked.label.includes('Reinstate')) {
      this.taskStore.reinstateTask(taskId);
      vscode.window.showInformationMessage(`Caspian Security: "${def.title}" reinstated.`);
    }
  }

  private async showSnoozeOptions(taskId: string, title: string): Promise<void> {
    const options = [
      { label: '1 hour', ms: 60 * 60 * 1000 },
      { label: '4 hours', ms: 4 * 60 * 60 * 1000 },
      { label: '1 day', ms: 24 * 60 * 60 * 1000 },
      { label: '3 days', ms: 3 * 24 * 60 * 60 * 1000 },
      { label: '1 week', ms: 7 * 24 * 60 * 60 * 1000 },
    ];

    const picked = await vscode.window.showQuickPick(
      options.map(o => ({ label: o.label })),
      { placeHolder: `Snooze "${title}" for...` }
    );

    if (!picked) { return; }
    const option = options.find(o => o.label === picked.label);
    if (option) {
      this.taskStore.markSnoozed(taskId, new Date(Date.now() + option.ms));
      vscode.window.showInformationMessage(`Caspian Security: "${title}" snoozed for ${option.label}.`);
    }
  }

  private async showIntervalPicker(taskId: string, title: string, currentInterval: TaskInterval): Promise<void> {
    const items = Object.values(TaskInterval).map(interval => ({
      label: INTERVAL_LABELS[interval],
      description: interval === currentInterval ? '(current)' : undefined,
      interval,
    }));

    const picked = await vscode.window.showQuickPick(items, {
      placeHolder: `Set recurrence interval for "${title}"`,
    });

    if (picked) {
      this.taskStore.setInterval(taskId, (picked as { label: string; interval: TaskInterval }).interval);
      vscode.window.showInformationMessage(
        `Caspian Security: "${title}" interval set to ${picked.label}.`
      );
    }
  }

  private autoCompleteTasks(trigger: AutoCompleteTrigger): void {
    const tasksEnabled = this.configManager.get<boolean>('enableTaskManagement', true);
    if (!tasksEnabled) { return; }

    const matchingTasks = SECURITY_TASK_CATALOG.filter(
      t => t.autoCompleteTrigger === trigger
    );

    let completedCount = 0;
    for (const def of matchingTasks) {
      const instance = this.taskStore.getInstance(def.id);
      if (!instance) { continue; }
      if (instance.status === TaskStatus.Dismissed || instance.status === TaskStatus.Snoozed) { continue; }
      if (instance.status === TaskStatus.Overdue || instance.status === TaskStatus.Pending) {
        this.taskStore.markCompleted(def.id);
        completedCount++;
      }
    }

    if (completedCount > 0) {
      vscode.window.showInformationMessage(
        `Caspian Security: ${completedCount} security task(s) auto-completed.`
      );
    }
  }

  private checkAndNotify(): void {
    const tasksEnabled = this.configManager.get<boolean>('enableTaskManagement', true);
    if (!tasksEnabled) { return; }

    const showReminders = this.configManager.get<boolean>('taskReminders', true);
    const newlyOverdue = this.taskStore.updateOverdueStatuses();

    if (showReminders && newlyOverdue.length > 0) {
      const taskNames = newlyOverdue
        .map(id => getTaskDefinition(id)?.title)
        .filter(Boolean)
        .slice(0, 3);

      const suffix = newlyOverdue.length > 3
        ? ` and ${newlyOverdue.length - 3} more`
        : '';

      vscode.window.showWarningMessage(
        `Caspian Security: ${newlyOverdue.length} security task(s) overdue: ${taskNames.join(', ')}${suffix}`,
        'Show Tasks'
      ).then(choice => {
        if (choice === 'Show Tasks') {
          vscode.commands.executeCommand('caspian-security.showTaskDashboard');
        }
      });
    }
  }

  dispose(): void {
    if (this.checkTimer) {
      clearInterval(this.checkTimer);
    }
  }
}
