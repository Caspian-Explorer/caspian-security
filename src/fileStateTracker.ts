import * as vscode from 'vscode';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { SecurityIssue } from './types';
import { PersistenceManager } from './persistenceManager';

export interface FileState {
  relativePath: string;
  mtime: number;
  size: number;
  contentHash: string;
  lastScannedAt: string;
  languageId: string;
  cachedIssues: SecurityIssue[];
}

export interface FileStateStore {
  version: 1;
  files: Record<string, FileState>;
}

export enum FileChangeStatus {
  Unchanged = 'unchanged',
  Modified = 'modified',
  New = 'new',
  Deleted = 'deleted',
}

const STORE_FILE = 'file-state.json';

export class FileStateTracker implements vscode.Disposable {
  private states: Map<string, FileState> = new Map();
  private dirty = false;
  private persistence: PersistenceManager;
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  constructor() {
    this.persistence = PersistenceManager.getInstance();
  }

  async load(): Promise<void> {
    const store = await this.persistence.readStore<FileStateStore>(
      STORE_FILE,
      { version: 1, files: {} }
    );
    this.states = new Map(Object.entries(store.files));
  }

  async getFileChangeStatus(relativePath: string, fsPath: string): Promise<FileChangeStatus> {
    const existing = this.states.get(relativePath);
    if (!existing) {
      return FileChangeStatus.New;
    }

    try {
      const stat = fs.statSync(fsPath);
      const mtime = stat.mtimeMs;
      const size = stat.size;

      // Fast path: mtime and size both match
      if (mtime === existing.mtime && size === existing.size) {
        return FileChangeStatus.Unchanged;
      }

      // Size changed — definitely modified
      if (size !== existing.size) {
        return FileChangeStatus.Modified;
      }

      // mtime changed but size same — hash to verify (e.g. git checkout)
      const hash = this.computeHash(fsPath);
      if (hash === existing.contentHash) {
        // Content identical despite mtime change; update stored mtime
        existing.mtime = mtime;
        this.markDirty();
        return FileChangeStatus.Unchanged;
      }

      return FileChangeStatus.Modified;
    } catch {
      return FileChangeStatus.Deleted;
    }
  }

  async recordScan(
    relativePath: string,
    fsPath: string,
    languageId: string,
    issues: SecurityIssue[]
  ): Promise<void> {
    try {
      const stat = fs.statSync(fsPath);
      const hash = this.computeHash(fsPath);

      this.states.set(relativePath, {
        relativePath,
        mtime: stat.mtimeMs,
        size: stat.size,
        contentHash: hash,
        lastScannedAt: new Date().toISOString(),
        languageId,
        cachedIssues: issues,
      });
      this.markDirty();
    } catch (error) {
      console.error(`FileStateTracker: Failed to record scan for ${relativePath}:`, error);
    }
  }

  getCachedIssues(relativePath: string): SecurityIssue[] | undefined {
    return this.states.get(relativePath)?.cachedIssues;
  }

  getContentHash(relativePath: string): string | undefined {
    return this.states.get(relativePath)?.contentHash;
  }

  getLastScannedAt(relativePath: string): string | undefined {
    return this.states.get(relativePath)?.lastScannedAt;
  }

  getAllStates(): Map<string, FileState> {
    return this.states;
  }

  removeFile(relativePath: string): void {
    if (this.states.delete(relativePath)) {
      this.markDirty();
    }
  }

  async save(): Promise<void> {
    if (!this.dirty) { return; }
    const store: FileStateStore = {
      version: 1,
      files: Object.fromEntries(this.states),
    };
    await this.persistence.writeStore(STORE_FILE, store);
    this.dirty = false;
  }

  private computeHash(fsPath: string): string {
    const content = fs.readFileSync(fsPath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  private markDirty(): void {
    this.dirty = true;
    this.persistence.scheduleWrite(
      STORE_FILE,
      { version: 1, files: Object.fromEntries(this.states) },
      2000
    );
  }

  dispose(): void {
    this._onDidChange.dispose();
  }
}
