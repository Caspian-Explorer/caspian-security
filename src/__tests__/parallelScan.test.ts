/**
 * Tests for the parallel workspace scan. The key guarantee is that
 * running across worker threads produces exactly the same findings as
 * the synchronous scan (order-independent), and that the fallbacks
 * (small file sets, concurrency 1) behave.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  runWorkspaceScan,
  runWorkspaceScanParallel,
  chunkEvenly,
} from '../scanRunner';
import { scanFileBatch } from '../scanWorker';

function makeWorkspace(fileCount: number): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-parallel-'));
  fs.mkdirSync(path.join(dir, 'src'));
  for (let i = 0; i < fileCount; i++) {
    const vulnerable = i % 3 === 0;
    const body = vulnerable
      ? `const password = "hardcoded_secret_${i}";\napp.get("/x", (req, res) => res.send(req.query.q));\n`
      : `export function f${i}(a, b) {\n  return a + b;\n}\n`;
    fs.writeFileSync(path.join(dir, 'src', `mod${i}.js`), body);
  }
  return dir;
}

function sortedKeys(results: { relativePath: string; issues: { code: string; line: number }[] }[]): string[] {
  return results
    .flatMap(r => r.issues.map(i => `${r.relativePath}:${i.line}:${i.code}`))
    .sort();
}

describe('chunkEvenly', () => {
  it('splits into at most n contiguous chunks covering all items', () => {
    const items = Array.from({ length: 10 }, (_, i) => i);
    const chunks = chunkEvenly(items, 3);
    expect(chunks.length).toBeLessThanOrEqual(3);
    expect(chunks.flat()).toEqual(items);
  });

  it('returns a single chunk for n<=1', () => {
    expect(chunkEvenly([1, 2, 3], 1)).toEqual([[1, 2, 3]]);
  });

  it('returns [] for an empty list', () => {
    expect(chunkEvenly([], 4)).toEqual([]);
  });
});

describe('scanFileBatch (worker body)', () => {
  it('scans a file list and reports findings + skips', () => {
    const dir = makeWorkspace(4);
    try {
      const files = fs.readdirSync(path.join(dir, 'src')).map(f => path.join(dir, 'src', f));
      const res = scanFileBatch({ files, workspace: dir, maxFileSize: 500_000, runTaint: false });
      expect(res.results.length).toBeGreaterThan(0);
      expect(res.results.some(r => r.issues.some(i => i.code.startsWith('CRED')))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('runWorkspaceScanParallel', () => {
  it('falls back to inline scan below the parallel threshold', async () => {
    const dir = makeWorkspace(6);
    try {
      const sync = runWorkspaceScan({ workspace: dir, runTaint: false });
      const par = await runWorkspaceScanParallel({ workspace: dir, runTaint: false });
      expect(par.filesScanned).toBe(sync.filesScanned);
      expect(sortedKeys(par.results)).toEqual(sortedKeys(sync.results));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('produces identical findings to the sync scan when workers run', async () => {
    // Force the worker path with a low threshold and >1 concurrency. If the
    // compiled worker isn't present (running from ts-jest), the function
    // transparently falls back to sync — either way the RESULT must match.
    const dir = makeWorkspace(60);
    try {
      const sync = runWorkspaceScan({ workspace: dir, runTaint: false });
      const par = await runWorkspaceScanParallel({
        workspace: dir, runTaint: false,
        concurrency: 4, minFilesForParallel: 10,
      });
      expect(par.filesScanned).toBe(sync.filesScanned);
      expect(par.totalIssues).toBe(sync.totalIssues);
      expect(sortedKeys(par.results)).toEqual(sortedKeys(sync.results));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns results sorted by path deterministically', async () => {
    const dir = makeWorkspace(30);
    try {
      const par = await runWorkspaceScanParallel({
        workspace: dir, runTaint: false, concurrency: 4, minFilesForParallel: 5,
      });
      const paths = par.results.map(r => r.filePath);
      expect(paths).toEqual([...paths].sort((a, b) => a.localeCompare(b)));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
