import * as vscode from 'vscode';

export enum FixStatus {
  Pending = 'pending',
  Fixed = 'fixed',
  Ignored = 'ignored',
  FixFailed = 'fix-failed',
}

export interface FixRecord {
  issueKey: string;
  filePath: string;
  relativePath: string;
  issueCode: string;
  issueLine: number;
  issuePattern: string;
  status: FixStatus;
  fixedAt?: string;
  ignoredAt?: string;
  aiExplanation?: string;
  aiProvider?: string;
}

export interface FixTrackerSummary {
  total: number;
  pending: number;
  fixed: number;
  ignored: number;
  fixFailed: number;
}

const STORAGE_KEY = 'caspianSecurity.fixTracker';

export class FixTracker implements vscode.Disposable {
  private records: Map<string, FixRecord> = new Map();
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  constructor(private workspaceState: vscode.Memento) {
    this.load();
  }

  static makeKey(relativePath: string, code: string, line: number, pattern: string): string {
    return `${relativePath}:${code}:${line}:${pattern}`;
  }

  getStatus(key: string): FixStatus {
    return this.records.get(key)?.status ?? FixStatus.Pending;
  }

  getRecord(key: string): FixRecord | undefined {
    return this.records.get(key);
  }

  markFixed(
    key: string,
    filePath: string,
    relativePath: string,
    code: string,
    line: number,
    pattern: string,
    explanation: string,
    provider: string
  ): void {
    this.records.set(key, {
      issueKey: key,
      filePath,
      relativePath,
      issueCode: code,
      issueLine: line,
      issuePattern: pattern,
      status: FixStatus.Fixed,
      fixedAt: new Date().toISOString(),
      aiExplanation: explanation,
      aiProvider: provider,
    });
    this.save();
    this._onDidChange.fire();
  }

  markIgnored(
    key: string,
    filePath: string,
    relativePath: string,
    code: string,
    line: number,
    pattern: string
  ): void {
    this.records.set(key, {
      issueKey: key,
      filePath,
      relativePath,
      issueCode: code,
      issueLine: line,
      issuePattern: pattern,
      status: FixStatus.Ignored,
      ignoredAt: new Date().toISOString(),
    });
    this.save();
    this._onDidChange.fire();
  }

  markFixFailed(key: string): void {
    const existing = this.records.get(key);
    if (existing) {
      existing.status = FixStatus.FixFailed;
      this.save();
      this._onDidChange.fire();
    }
  }

  resetStatus(key: string): void {
    this.records.delete(key);
    this.save();
    this._onDidChange.fire();
  }

  clearAll(): void {
    this.records.clear();
    this.save();
    this._onDidChange.fire();
  }

  getSummary(): FixTrackerSummary {
    let pending = 0;
    let fixed = 0;
    let ignored = 0;
    let fixFailed = 0;
    for (const r of this.records.values()) {
      switch (r.status) {
        case FixStatus.Fixed:
          fixed++;
          break;
        case FixStatus.Ignored:
          ignored++;
          break;
        case FixStatus.FixFailed:
          fixFailed++;
          break;
        default:
          pending++;
          break;
      }
    }
    return { total: this.records.size, pending, fixed, ignored, fixFailed };
  }

  getAllRecords(): FixRecord[] {
    return Array.from(this.records.values());
  }

  private load(): void {
    const data = this.workspaceState.get<Record<string, FixRecord>>(STORAGE_KEY, {});
    this.records = new Map(Object.entries(data));
  }

  private save(): void {
    const obj: Record<string, FixRecord> = {};
    for (const [k, v] of this.records) {
      obj[k] = v;
    }
    this.workspaceState.update(STORAGE_KEY, obj);
  }

  dispose(): void {
    this._onDidChange.dispose();
  }
}
