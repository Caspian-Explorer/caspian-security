import * as vscode from 'vscode';
import { TaskManager } from './taskManager';
import { TaskStore } from './taskStore';
import { TaskTreeProvider } from './taskTreeProvider';
import { TaskDetailPanel } from './taskDetailPanel';

export function registerTaskCommands(
  context: vscode.ExtensionContext,
  taskManager: TaskManager,
  taskStore: TaskStore,
  treeProvider: TaskTreeProvider,
  taskDetailPanel: TaskDetailPanel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.taskAction', (taskId: string) => {
      taskDetailPanel.show(taskId);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.showTaskDetail', (taskId: string) => {
      taskDetailPanel.show(taskId);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.showTaskDashboard', () => {
      vscode.commands.executeCommand('caspianSecurityTasks.focus');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.refreshTasks', () => {
      taskStore.updateOverdueStatuses();
      treeProvider.refresh();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.completeAllOverdue', async () => {
      const overdue = taskStore.getOverdueTasks();
      if (overdue.length === 0) {
        vscode.window.showInformationMessage('Caspian Security: No overdue tasks.');
        return;
      }

      const confirm = await vscode.window.showWarningMessage(
        `Mark all ${overdue.length} overdue task(s) as completed?`,
        'Yes', 'No'
      );
      if (confirm === 'Yes') {
        for (const inst of overdue) {
          taskStore.markCompleted(inst.taskId);
        }
        vscode.window.showInformationMessage(
          `Caspian Security: ${overdue.length} task(s) marked complete.`
        );
      }
    })
  );
}
