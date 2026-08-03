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
  /**
   * True only when the file was scanned during THIS session. Entries
   * restored from disk have empty `cachedIssues` (issues are never
   * persisted — see buildSerialisableStore), so their cache must not be
   * treated as "zero issues": that would silently report stale-clean
   * results for every unchanged file after a restart.
   */
  sessionScanned: boolean;
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
    // Cached issues are intentionally NOT restored: persisting them risked
    // leaking matched text (e.g. hardcoded secrets) across sessions. The
    // change-detection cache (hash/mtime/size) is the only thing we carry
    // forward; issues repopulate as each file is scanned this session.
    this.states = new Map(
      Object.entries(store.files).map(([k, s]) => [
        k,
        { ...s, cachedIssues: [], sessionScanned: false },
      ])
    );
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
    issues: SecurityIssue[],
    text?: string
  ): Promise<void> {
    try {
      const stat = fs.statSync(fsPath);
      // Hash the already-loaded document text when the caller has it —
      // re-reading the file from disk just to hash it doubled the I/O of
      // every scan.
      const hash = text !== undefined
        ? crypto.createHash('sha256').update(text, 'utf-8').digest('hex')
        : this.computeHash(fsPath);

      this.states.set(relativePath, {
        relativePath,
        mtime: stat.mtimeMs,
        size: stat.size,
        contentHash: hash,
        lastScannedAt: new Date().toISOString(),
        languageId,
        cachedIssues: issues,
        sessionScanned: true,
      });
      this.markDirty();
    } catch (error) {
      console.error(`FileStateTracker: Failed to record scan for ${relativePath}:`, error);
    }
  }

  /**
   * Returns cached issues only for files scanned during this session.
   * Entries restored from a previous session return `undefined` so the
   * caller re-scans them — their issues were never persisted.
   */
  getCachedIssues(relativePath: string): SecurityIssue[] | undefined {
    const state = this.states.get(relativePath);
    if (!state || !state.sessionScanned) {
      return undefined;
    }
    return state.cachedIssues;
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
    await this.persistence.writeStore(STORE_FILE, this.buildSerialisableStore());
    this.dirty = false;
  }

  /**
   * Produce the on-disk representation of the tracker. `cachedIssues` is
   * deliberately dropped: issues carry `pattern` (the raw matched text
   * from the user's source, e.g. `password = "hunter2"`) plus positional
   * metadata. Persisting that verbatim risks leaking matched secrets to
   * local disk backups / cloud sync of the VS Code data dir. The
   * change-detection cache (hash/mtime/size) is kept — it is what actually
   * drives the skip-unchanged-files optimisation.
   */
  private buildSerialisableStore(): FileStateStore {
    const files: Record<string, FileState> = {};
    for (const [key, state] of this.states) {
      files[key] = { ...state, cachedIssues: [], sessionScanned: false };
    }
    return { version: 1, files };
  }

  private computeHash(fsPath: string): string {
    const content = fs.readFileSync(fsPath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  private markDirty(): void {
    this.dirty = true;
    // Pass a supplier so the (potentially large) store is snapshotted once
    // when the debounced write fires, not on every scanned file.
    this.persistence.scheduleWrite(
      STORE_FILE,
      () => this.buildSerialisableStore(),
      2000
    );
  }

  dispose(): void {
    this._onDidChange.dispose();
  }
}

