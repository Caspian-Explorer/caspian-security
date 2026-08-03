import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export class PersistenceManager implements vscode.Disposable {
  private static instance: PersistenceManager;
  private storageDir: string;
  private writeTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();
  private pendingData: Map<string, () => unknown> = new Map();

  private constructor(storageUri: vscode.Uri) {
    this.storageDir = storageUri.fsPath;
    this.ensureStorageDir();
  }

  static initialize(storageUri: vscode.Uri): PersistenceManager {
    PersistenceManager.instance = new PersistenceManager(storageUri);
    return PersistenceManager.instance;
  }

  static getInstance(): PersistenceManager {
    if (!PersistenceManager.instance) {
      throw new Error('PersistenceManager not initialized. Call initialize() first.');
    }
    return PersistenceManager.instance;
  }

  async readStore<T>(filename: string, defaultValue: T): Promise<T> {
    const filePath = path.join(this.storageDir, filename);
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return JSON.parse(content) as T;
    } catch {
      return defaultValue;
    }
  }

  async writeStore<T>(filename: string, data: T): Promise<void> {
    const filePath = path.join(this.storageDir, filename);
    try {
      this.ensureStorageDir();
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
    } catch (error) {
      console.error(`PersistenceManager: Failed to write ${filename}:`, error);
    }
  }

  /**
   * Debounced write. `data` may be the value itself or a supplier that is
   * invoked only when the write actually happens — pass a supplier for
   * large stores so repeated schedule calls don't snapshot on every call.
   */
  scheduleWrite<T>(filename: string, data: T | (() => T), delayMs: number = 2000): void {
    const existing = this.writeTimers.get(filename);
    if (existing) {
      clearTimeout(existing);
    }
    const supplier = (typeof data === 'function' ? data : () => data) as () => T;
    this.pendingData.set(filename, supplier);
    const timer = setTimeout(() => {
      this.writeTimers.delete(filename);
      this.pendingData.delete(filename);
      this.writeStore(filename, supplier());
    }, delayMs);
    this.writeTimers.set(filename, timer);
  }

  private ensureStorageDir(): void {
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }
  }

  dispose(): void {
    // Flush all pending writes synchronously so debounced data (learning
    // stores, file-state cache, dismissals) survives extension shutdown.
    for (const timer of this.writeTimers.values()) {
      clearTimeout(timer);
    }
    this.writeTimers.clear();
    for (const [filename, supplier] of this.pendingData) {
      try {
        this.ensureStorageDir();
        fs.writeFileSync(
          path.join(this.storageDir, filename),
          JSON.stringify(supplier(), null, 2),
          'utf-8'
        );
      } catch (error) {
        console.error(`PersistenceManager: Failed to flush ${filename} on dispose:`, error);
      }
    }
    this.pendingData.clear();
  }
}
