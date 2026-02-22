import * as vscode from 'vscode';
import { PersistenceManager } from './persistenceManager';
import {
  TaskInstance,
  TaskStoreData,
  TaskStatus,
  TaskInterval,
  INTERVAL_MS,
} from './taskTypes';
import { SECURITY_TASK_CATALOG, getTaskDefinition } from './taskCatalog';

const STORE_FILE = 'security-tasks.json';

export class TaskStore implements vscode.Disposable {
  private instances: Map<string, TaskInstance> = new Map();
  private persistence: PersistenceManager;
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  constructor() {
    this.persistence = PersistenceManager.getInstance();
  }

  async load(): Promise<void> {
    const store = await this.persistence.readStore<TaskStoreData>(
      STORE_FILE,
      { version: 1, instances: {} }
    );
    this.instances = new Map(Object.entries(store.instances));
  }

  initializeFromCatalog(): void {
    const now = new Date().toISOString();
    let changed = false;

    for (const def of SECURITY_TASK_CATALOG) {
      if (!this.instances.has(def.id)) {
        const intervalMs = INTERVAL_MS[def.defaultInterval];
        this.instances.set(def.id, {
          taskId: def.id,
          status: TaskStatus.Pending,
          lastCompletedAt: null,
          nextDueAt: new Date(Date.now() + intervalMs).toISOString(),
          snoozeUntil: null,
          intervalOverride: null,
          createdAt: now,
          dismissedAt: null,
          completionCount: 0,
        });
        changed = true;
      }
    }

    if (changed) {
      this.save();
    }
  }

  getInstance(taskId: string): TaskInstance | undefined {
    return this.instances.get(taskId);
  }

  getAllInstances(): TaskInstance[] {
    return Array.from(this.instances.values());
  }

  markCompleted(taskId: string): void {
    const instance = this.instances.get(taskId);
    if (!instance) { return; }

    const def = getTaskDefinition(taskId);
    const interval = instance.intervalOverride || def?.defaultInterval || TaskInterval.Monthly;
    const intervalMs = INTERVAL_MS[interval];

    instance.status = TaskStatus.Completed;
    instance.lastCompletedAt = new Date().toISOString();
    instance.nextDueAt = new Date(Date.now() + intervalMs).toISOString();
    instance.snoozeUntil = null;
    instance.completionCount += 1;

    this.save();
    this._onDidChange.fire();
  }

  markSnoozed(taskId: string, snoozeUntil: Date): void {
    const instance = this.instances.get(taskId);
    if (!instance) { return; }

    instance.status = TaskStatus.Snoozed;
    instance.snoozeUntil = snoozeUntil.toISOString();

    this.save();
    this._onDidChange.fire();
  }

  markDismissed(taskId: string): void {
    const instance = this.instances.get(taskId);
    if (!instance) { return; }

    instance.status = TaskStatus.Dismissed;
    instance.dismissedAt = new Date().toISOString();

    this.save();
    this._onDidChange.fire();
  }

  reinstateTask(taskId: string): void {
    const instance = this.instances.get(taskId);
    if (!instance) { return; }

    instance.status = TaskStatus.Pending;
    instance.dismissedAt = null;
    instance.snoozeUntil = null;

    this.save();
    this._onDidChange.fire();
  }

  setInterval(taskId: string, interval: TaskInterval): void {
    const instance = this.instances.get(taskId);
    if (!instance) { return; }

    instance.intervalOverride = interval;

    const intervalMs = INTERVAL_MS[interval];
    const base = instance.lastCompletedAt
      ? new Date(instance.lastCompletedAt).getTime()
      : Date.now();
    instance.nextDueAt = new Date(base + intervalMs).toISOString();

    this.save();
    this._onDidChange.fire();
  }

  updateOverdueStatuses(): string[] {
    const now = Date.now();
    const newlyOverdue: string[] = [];

    for (const [taskId, instance] of this.instances) {
      if (instance.status === TaskStatus.Dismissed) { continue; }

      if (instance.status === TaskStatus.Snoozed && instance.snoozeUntil) {
        if (new Date(instance.snoozeUntil).getTime() <= now) {
          instance.snoozeUntil = null;
          instance.status = TaskStatus.Pending;
        } else {
          continue;
        }
      }

      if (
        (instance.status === TaskStatus.Pending || instance.status === TaskStatus.Completed) &&
        new Date(instance.nextDueAt).getTime() <= now
      ) {
        newlyOverdue.push(taskId);
        instance.status = TaskStatus.Overdue;
      }
    }

    if (newlyOverdue.length > 0) {
      this.save();
      this._onDidChange.fire();
    }

    return newlyOverdue;
  }

  getOverdueTasks(): TaskInstance[] {
    return this.getAllInstances().filter(i => i.status === TaskStatus.Overdue);
  }

  getDueSoonTasks(withinMs: number = 24 * 60 * 60 * 1000): TaskInstance[] {
    const cutoff = Date.now() + withinMs;
    return this.getAllInstances().filter(i =>
      (i.status === TaskStatus.Pending || i.status === TaskStatus.Completed) &&
      new Date(i.nextDueAt).getTime() <= cutoff
    );
  }

  getSummary(): { total: number; overdue: number; pending: number; completed: number; snoozed: number; dismissed: number } {
    let overdue = 0, pending = 0, completed = 0, snoozed = 0, dismissed = 0;
    for (const i of this.instances.values()) {
      switch (i.status) {
        case TaskStatus.Overdue: overdue++; break;
        case TaskStatus.Pending: pending++; break;
        case TaskStatus.Completed: completed++; break;
        case TaskStatus.Snoozed: snoozed++; break;
        case TaskStatus.Dismissed: dismissed++; break;
      }
    }
    return { total: this.instances.size, overdue, pending, completed, snoozed, dismissed };
  }

  private save(): void {
    const store: TaskStoreData = {
      version: 1,
      instances: Object.fromEntries(this.instances),
    };
    this.persistence.scheduleWrite(STORE_FILE, store, 1000);
  }

  dispose(): void {
    this._onDidChange.dispose();
  }
}
