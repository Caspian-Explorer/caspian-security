import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export class PersistenceManager implements vscode.Disposable {
  private static instance: PersistenceManager;
  private storageDir: string;
  private writeTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

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

  scheduleWrite<T>(filename: string, data: T, delayMs: number = 2000): void {
    const existing = this.writeTimers.get(filename);
    if (existing) {
      clearTimeout(existing);
    }
    const timer = setTimeout(() => {
      this.writeStore(filename, data);
      this.writeTimers.delete(filename);
    }, delayMs);
    this.writeTimers.set(filename, timer);
  }

  private ensureStorageDir(): void {
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }
  }

  dispose(): void {
    // Flush all pending writes synchronously
    for (const [filename, timer] of this.writeTimers) {
      clearTimeout(timer);
    }
    this.writeTimers.clear();
  }
}
