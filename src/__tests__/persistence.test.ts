/**
 * Regression tests for the persistence layer:
 *
 * 1. PersistenceManager.dispose() must FLUSH pending debounced writes —
 *    it used to just cancel them, losing up to 2s of learning data on
 *    every VS Code shutdown.
 * 2. FileStateTracker must never serve cached issues for entries restored
 *    from disk. Issues are deliberately not persisted, so after a restart
 *    the cache held `[]` for every file — and the workspace scan reported
 *    every unchanged file as CLEAN without scanning it (silent false
 *    negative across the whole workspace).
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Uri } from 'vscode';
import { PersistenceManager } from '../persistenceManager';
import { FileStateTracker, FileChangeStatus } from '../fileStateTracker';
import { SecurityIssue, SecuritySeverity, SecurityCategory } from '../types';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-persist-'));
}

function sampleIssue(): SecurityIssue {
  return {
    line: 0, column: 6, message: 'Hardcoded credential',
    severity: SecuritySeverity.Error, suggestion: 'Use env vars',
    code: 'CRED001', pattern: 'password = "x"',
    category: SecurityCategory.SecretsCredentials,
  };
}

describe('PersistenceManager', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
    PersistenceManager.initialize(Uri.file(dir) as never);
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('flushes pending debounced writes on dispose instead of dropping them', () => {
    const pm = PersistenceManager.getInstance();
    pm.scheduleWrite('pending.json', { value: 42 }, 60_000);
    // Nothing written yet — the debounce window is long.
    expect(fs.existsSync(path.join(dir, 'pending.json'))).toBe(false);

    pm.dispose();

    const written = JSON.parse(fs.readFileSync(path.join(dir, 'pending.json'), 'utf-8'));
    expect(written).toEqual({ value: 42 });
  });

  it('invokes a data supplier only at write time and flushes its latest value', () => {
    const pm = PersistenceManager.getInstance();
    let calls = 0;
    const state = { n: 0 };
    const supplier = () => { calls++; return { n: state.n }; };

    pm.scheduleWrite('supplied.json', supplier, 60_000);
    pm.scheduleWrite('supplied.json', supplier, 60_000);
    state.n = 7;
    expect(calls).toBe(0); // not snapshotted eagerly

    pm.dispose();
    expect(calls).toBe(1);
    const written = JSON.parse(fs.readFileSync(path.join(dir, 'supplied.json'), 'utf-8'));
    expect(written).toEqual({ n: 7 });
  });

  it('writes and reads a store round-trip', async () => {
    const pm = PersistenceManager.getInstance();
    await pm.writeStore('store.json', { a: 1 });
    const back = await pm.readStore('store.json', { a: 0 });
    expect(back).toEqual({ a: 1 });
  });
});

describe('FileStateTracker restart behaviour', () => {
  let dir: string;
  let watchedFile: string;

  beforeEach(() => {
    dir = makeTempDir();
    PersistenceManager.initialize(Uri.file(dir) as never);
    watchedFile = path.join(dir, 'app.js');
    fs.writeFileSync(watchedFile, 'const password = "hunter2";\n');
  });

  afterEach(() => {
    PersistenceManager.getInstance().dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('serves cached issues for files scanned in the SAME session', async () => {
    const tracker = new FileStateTracker();
    await tracker.recordScan('app.js', watchedFile, 'javascript', [sampleIssue()]);
    expect(tracker.getCachedIssues('app.js')).toHaveLength(1);
  });

  it('does NOT serve cached issues for entries restored from disk (restart simulation)', async () => {
    // Session 1: scan and persist.
    const session1 = new FileStateTracker();
    await session1.recordScan('app.js', watchedFile, 'javascript', [sampleIssue()]);
    await session1.save();

    // Session 2 (VS Code restart): load the persisted state.
    const session2 = new FileStateTracker();
    await session2.load();

    // The file is unchanged on disk...
    const status = await session2.getFileChangeStatus('app.js', watchedFile);
    expect(status).toBe(FileChangeStatus.Unchanged);

    // ...but its issues were never persisted, so the cache MUST miss and
    // force a real re-scan. Returning [] here made every unchanged file
    // appear clean after a restart.
    expect(session2.getCachedIssues('app.js')).toBeUndefined();
  });

  it('serves cached issues again after the file is re-scanned post-restart', async () => {
    const session1 = new FileStateTracker();
    await session1.recordScan('app.js', watchedFile, 'javascript', [sampleIssue()]);
    await session1.save();

    const session2 = new FileStateTracker();
    await session2.load();
    await session2.recordScan('app.js', watchedFile, 'javascript', [sampleIssue()]);
    expect(session2.getCachedIssues('app.js')).toHaveLength(1);
  });

  it('detects content changes even when file size is unchanged', async () => {
    const tracker = new FileStateTracker();
    await tracker.recordScan('app.js', watchedFile, 'javascript', []);
    // Same length, different content — mtime may or may not tick, so
    // rewrite with a delay-independent content change.
    const original = fs.readFileSync(watchedFile, 'utf-8');
    fs.writeFileSync(watchedFile, original.replace('hunter2', 'hunter3'));
    // Force the mtime forward so the size-equal path must fall back to hashing.
    fs.utimesSync(watchedFile, new Date(), new Date(Date.now() + 2000));
    const status = await tracker.getFileChangeStatus('app.js', watchedFile);
    expect(status).toBe(FileChangeStatus.Modified);
  });

  it('hashes provided text instead of re-reading the file when given', async () => {
    const tracker = new FileStateTracker();
    const text = fs.readFileSync(watchedFile, 'utf-8');
    await tracker.recordScan('app.js', watchedFile, 'javascript', [], text);
    const status = await tracker.getFileChangeStatus('app.js', watchedFile);
    expect(status).toBe(FileChangeStatus.Unchanged);
  });
});
