import * as vscode from 'vscode';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { SecurityIssue } from './types';
import { PersistenceManager } from './persistenceManager';
import { FileStateTracker } from './fileStateTracker';

export interface FalsePositiveDismissal {
  id: string;
  ruleCode: string;
  relativePath: string;
  line: number;
  pattern: string;
  contentHashAtDismissal: string;
  dismissedAt: string;
  reason?: string;
}

export interface FalsePositiveStoreData {
  version: 1;
  dismissals: Record<string, FalsePositiveDismissal>;
}

const STORE_FILE = 'false-positives.json';

export class FalsePositiveStore implements vscode.Disposable {
  private dismissals: Map<string, FalsePositiveDismissal> = new Map();
  private persistence: PersistenceManager;
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  constructor(private fileStateTracker: FileStateTracker) {
    this.persistence = PersistenceManager.getInstance();
  }

  async load(): Promise<void> {
    const store = await this.persistence.readStore<FalsePositiveStoreData>(
      STORE_FILE,
      { version: 1, dismissals: {} }
    );
    this.dismissals = new Map(Object.entries(store.dismissals));
  }

  static makeKey(relativePath: string, ruleCode: string, line: number, pattern: string): string {
    return `${relativePath}:${ruleCode}:${line}:${pattern}`;
  }

  async dismiss(
    relativePath: string,
    fsPath: string,
    ruleCode: string,
    line: number,
    pattern: string,
    reason?: string
  ): Promise<void> {
    const contentHash = this.fileStateTracker.getContentHash(relativePath)
      || this.computeFileHash(fsPath);

    const id = FalsePositiveStore.makeKey(relativePath, ruleCode, line, pattern);

    this.dismissals.set(id, {
      id,
      ruleCode,
      relativePath,
      line,
      pattern,
      contentHashAtDismissal: contentHash,
      dismissedAt: new Date().toISOString(),
      reason,
    });

    this.save();
    this._onDidChange.fire();
  }

  isDismissed(
    relativePath: string,
    ruleCode: string,
    line: number,
    pattern: string
  ): boolean {
    const key = FalsePositiveStore.makeKey(relativePath, ruleCode, line, pattern);
    const dismissal = this.dismissals.get(key);
    if (!dismissal) { return false; }

    // Check if file has changed since dismissal
    const currentHash = this.fileStateTracker.getContentHash(relativePath);
    if (!currentHash) { return false; }

    if (currentHash !== dismissal.contentHashAtDismissal) {
      // File has changed — re-report the finding
      return false;
    }

    return true;
  }

  filterFalsePositives(
    relativePath: string,
    issues: SecurityIssue[]
  ): SecurityIssue[] {
    return issues.filter(
      issue => !this.isDismissed(relativePath, issue.code, issue.line, issue.pattern)
    );
  }

  revoke(relativePath: string, ruleCode: string, line: number, pattern: string): void {
    const key = FalsePositiveStore.makeKey(relativePath, ruleCode, line, pattern);
    if (this.dismissals.delete(key)) {
      this.save();
      this._onDidChange.fire();
    }
  }

  invalidateFile(relativePath: string): void {
    let changed = false;
    for (const [key, dismissal] of this.dismissals) {
      if (dismissal.relativePath === relativePath) {
        this.dismissals.delete(key);
        changed = true;
      }
    }
    if (changed) {
      this.save();
      this._onDidChange.fire();
    }
  }

  getAllDismissals(): FalsePositiveDismissal[] {
    return Array.from(this.dismissals.values());
  }

  getDismissalsForFile(relativePath: string): FalsePositiveDismissal[] {
    return this.getAllDismissals().filter(d => d.relativePath === relativePath);
  }

  clearAll(): void {
    this.dismissals.clear();
    this.save();
    this._onDidChange.fire();
  }

  private save(): void {
    const store: FalsePositiveStoreData = {
      version: 1,
      dismissals: Object.fromEntries(this.dismissals),
    };
    this.persistence.scheduleWrite(STORE_FILE, store, 1000);
  }

  private computeFileHash(fsPath: string): string {
    const content = fs.readFileSync(fsPath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  dispose(): void {
    this._onDidChange.dispose();
  }
}
