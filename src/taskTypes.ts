import { SecurityCategory } from './types';

export enum TaskInterval {
  Daily = 'daily',
  Weekly = 'weekly',
  Biweekly = 'biweekly',
  Monthly = 'monthly',
  Quarterly = 'quarterly',
}

export enum TaskStatus {
  Pending = 'pending',
  Completed = 'completed',
  Overdue = 'overdue',
  Snoozed = 'snoozed',
  Dismissed = 'dismissed',
}

export enum AutoCompleteTrigger {
  WorkspaceScan = 'workspace-scan',
  DependencyCheck = 'dependency-check',
  FullScan = 'full-scan',
  Manual = 'manual',
}

export interface SecurityTaskDefinition {
  id: string;
  title: string;
  description: string;
  category: SecurityCategory;
  defaultInterval: TaskInterval;
  autoCompleteTrigger: AutoCompleteTrigger;
  relatedRuleCodes?: string[];
  priority: number;
}

export interface TaskInstance {
  taskId: string;
  status: TaskStatus;
  lastCompletedAt: string | null;
  nextDueAt: string;
  snoozeUntil: string | null;
  intervalOverride: TaskInterval | null;
  createdAt: string;
  dismissedAt: string | null;
  completionCount: number;
}

export interface TaskStoreData {
  version: 1;
  instances: Record<string, TaskInstance>;
}

export const INTERVAL_MS: Record<TaskInterval, number> = {
  [TaskInterval.Daily]: 24 * 60 * 60 * 1000,
  [TaskInterval.Weekly]: 7 * 24 * 60 * 60 * 1000,
  [TaskInterval.Biweekly]: 14 * 24 * 60 * 60 * 1000,
  [TaskInterval.Monthly]: 30 * 24 * 60 * 60 * 1000,
  [TaskInterval.Quarterly]: 90 * 24 * 60 * 60 * 1000,
};

export const INTERVAL_LABELS: Record<TaskInterval, string> = {
  [TaskInterval.Daily]: 'Daily',
  [TaskInterval.Weekly]: 'Weekly',
  [TaskInterval.Biweekly]: 'Every 2 weeks',
  [TaskInterval.Monthly]: 'Monthly',
  [TaskInterval.Quarterly]: 'Quarterly',
};
