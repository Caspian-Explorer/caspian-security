import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { getChangedFilesSince } from '../gitDiff';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

describe('getChangedFilesSince', () => {
  it('returns an empty set when diffing HEAD against itself', () => {
    // HEAD...HEAD is trivially empty — a useful invariant to pin down
    // because it proves the parse is working on a successful run.
    const result = getChangedFilesSince(REPO_ROOT, 'HEAD');
    expect(result.ref).toBe('HEAD');
    expect(result.diffCount).toBe(0);
    expect(result.files.size).toBe(0);
  });

  it('returns absolute paths when there is a diff', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-diff-fixture-'));
    const git = (...args: string[]) => execFileSync('git', ['-C', tmp, ...args], { stdio: 'pipe' });
    try {
      git('init');
      git('config', 'user.name', 'Caspian Test');
      git('config', 'user.email', 'test@example.invalid');
      fs.writeFileSync(path.join(tmp, 'app.ts'), 'const value = 1;\n');
      git('add', '.');
      git('commit', '-m', 'base');
      fs.writeFileSync(path.join(tmp, 'app.ts'), 'const value = 2;\n');
      git('add', '.');
      git('commit', '-m', 'change');
      const result = getChangedFilesSince(tmp, 'HEAD~1');
      expect(result.diffCount).toBe(1);
      expect([...result.files]).toEqual([path.join(tmp, 'app.ts')]);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('throws a clear error for a non-existent ref', () => {
    expect(() => getChangedFilesSince(REPO_ROOT, 'definitely-not-a-ref-xxzzyy')).toThrow(
      /(may not exist|unknown revision|not a git repo)/,
    );
  });

  it('throws a clear error for a non-git directory', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-not-a-repo-'));
    try {
      expect(() => getChangedFilesSince(tmp, 'HEAD')).toThrow(
        /(may not exist|not a git repo|exited with code)/,
      );
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
