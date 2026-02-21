import * as vscode from 'vscode';
import { PersistenceManager } from './persistenceManager';

export interface ScanHistoryEntry {
  id: string;
  timestamp: string;
  scanType: string;
  duration: number;
  totalFiles: number;
  totalIssues: number;
  falsePositivesFiltered: number;
  filesSkippedUnchanged: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
}

export interface ScanHistoryData {
  version: 1;
  entries: ScanHistoryEntry[];
}

const STORE_FILE = 'scan-history.json';
const MAX_ENTRIES = 50;

export class ScanHistoryStore implements vscode.Disposable {
  private entries: ScanHistoryEntry[] = [];
  private persistence: PersistenceManager;

  constructor() {
    this.persistence = PersistenceManager.getInstance();
  }

  async load(): Promise<void> {
    const store = await this.persistence.readStore<ScanHistoryData>(
      STORE_FILE,
      { version: 1, entries: [] }
    );
    this.entries = store.entries;
  }

  async recordScan(entry: Omit<ScanHistoryEntry, 'id'>): Promise<void> {
    const newEntry: ScanHistoryEntry = {
      ...entry,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    };
    this.entries.push(newEntry);

    if (this.entries.length > MAX_ENTRIES) {
      this.entries = this.entries.slice(-MAX_ENTRIES);
    }

    await this.persistence.writeStore(STORE_FILE, {
      version: 1,
      entries: this.entries,
    });
  }

  getEntries(): ScanHistoryEntry[] {
    return [...this.entries];
  }

  getLastScan(): ScanHistoryEntry | undefined {
    return this.entries.length > 0 ? this.entries[this.entries.length - 1] : undefined;
  }

  dispose(): void { }
}
