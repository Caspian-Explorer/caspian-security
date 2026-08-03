/**
 * Unit tests for the Claude Code hook logic. The process-level contract
 * (stdin/stdout/exit codes) is exercised end-to-end against the bundles;
 * here we pin the pure decision functions the bundles are built from.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseHookInput, extractWriteContent, extractFilePath } from '../hooks/hookIO';
import { decideWriteGuard } from '../hooks/preWriteGuard';
import {
  emptyState,
  applyLoopGuard,
  recordBlocks,
  findingKey,
  loadSessionState,
  saveSessionState,
  MAX_BLOCKS_PER_FINDING,
  MAX_BLOCKS_PER_SESSION,
} from '../hooks/sessionState';

describe('hookIO parsing', () => {
  it('parseHookInput tolerates garbage', () => {
    expect(parseHookInput('not json')).toEqual({});
    expect(parseHookInput('42')).toEqual({});
    expect(parseHookInput('{"tool_name":"Write"}').tool_name).toBe('Write');
  });

  it('extractWriteContent handles Write, Edit, and MultiEdit shapes', () => {
    expect(extractWriteContent({ content: 'abc' })).toBe('abc');
    expect(extractWriteContent({ old_string: 'x', new_string: 'y' })).toBe('y');
    expect(extractWriteContent({
      edits: [{ old_string: 'a', new_string: 'b' }, { old_string: 'c', new_string: 'd' }],
    })).toBe('b\nd');
    expect(extractWriteContent(undefined)).toBe('');
  });

  it('extractFilePath requires a non-empty string', () => {
    expect(extractFilePath({ file_path: '/a/b.ts' })).toBe('/a/b.ts');
    expect(extractFilePath({ file_path: '' })).toBeNull();
    expect(extractFilePath({})).toBeNull();
  });
});

describe('decideWriteGuard', () => {
  const cwd = '/tmp/project';

  it('denies a live provider credential in any write shape', () => {
    const key = 'sk_live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2';
    const write = decideWriteGuard({
      tool_name: 'Write', cwd,
      tool_input: { file_path: `${cwd}/pay.ts`, content: `const k = "${key}";` },
    });
    expect(write?.decision).toBe('deny');
    expect(write?.reason).toContain('live credential');

    const edit = decideWriteGuard({
      tool_name: 'Edit', cwd,
      tool_input: { file_path: `${cwd}/pay.ts`, old_string: 'x', new_string: `const k = "${key}";` },
    });
    expect(edit?.decision).toBe('deny');
  });

  it('does not deny a Stripe TEST key (warning severity)', () => {
    // Concatenated so secret scanners don't flag this fixture as a real key.
    const testKey = 'sk_test_' + 'a1B2c3D4e5F6g7H8i9J0k1L2';
    const result = decideWriteGuard({
      tool_name: 'Write', cwd,
      tool_input: { file_path: `${cwd}/pay.ts`, content: `const k = "${testKey}";` },
    });
    expect(result).toBeNull();
  });

  it('denies wide-open platform rules only in matching file types', () => {
    const rules = decideWriteGuard({
      tool_name: 'Write', cwd,
      tool_input: { file_path: `${cwd}/firestore.rules`, content: 'allow write: if true;' },
    });
    expect(rules?.decision).toBe('deny');

    const ts = decideWriteGuard({
      tool_name: 'Write', cwd,
      tool_input: { file_path: `${cwd}/note.ts`, content: '// allow write: if true;' },
    });
    expect(ts).toBeNull();
  });

  it('asks (not denies) for Caspian guardrail files', () => {
    for (const file of ['caspian.config.json', '.caspianignore', '.caspian/baseline.json']) {
      const result = decideWriteGuard({
        tool_name: 'Edit', cwd,
        tool_input: { file_path: `${cwd}/${file}`, old_string: 'a', new_string: 'b' },
      });
      expect(result?.decision).toBe('ask');
    }
  });

  it('ignores non-write tools and writes without a path', () => {
    expect(decideWriteGuard({ tool_name: 'Bash', cwd, tool_input: { command: 'ls' } })).toBeNull();
    expect(decideWriteGuard({ tool_name: 'Write', cwd, tool_input: {} })).toBeNull();
  });
});

describe('session-state loop guard', () => {
  const finding = (file: string, code: string) => ({ relativePath: file, code });

  it('downgrades a finding after MAX_BLOCKS_PER_FINDING blocks', () => {
    const state = emptyState();
    const f = finding('a.ts', 'X001');
    for (let i = 0; i < MAX_BLOCKS_PER_FINDING; i++) {
      const { blockable } = applyLoopGuard(state, [f]);
      expect(blockable).toHaveLength(1);
      recordBlocks(state, blockable);
    }
    const { blockable, downgraded } = applyLoopGuard(state, [f]);
    expect(blockable).toHaveLength(0);
    expect(downgraded).toHaveLength(1);
  });

  it('downgrades everything past the session cap', () => {
    const state = emptyState();
    state.totalBlocks = MAX_BLOCKS_PER_SESSION;
    const { blockable, downgraded } = applyLoopGuard(state, [finding('b.ts', 'X002')]);
    expect(blockable).toHaveLength(0);
    expect(downgraded).toHaveLength(1);
  });

  it('tracks findings independently by file::code', () => {
    const state = emptyState();
    recordBlocks(state, [finding('a.ts', 'X001')]);
    expect(state.blocks[findingKey('a.ts', 'X001')]).toBe(1);
    const { blockable } = applyLoopGuard(state, [finding('a.ts', 'X002'), finding('b.ts', 'X001')]);
    expect(blockable).toHaveLength(2);
  });

  it('round-trips through disk and tolerates a corrupt state file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-state-'));
    const prev = process.env.CLAUDE_PLUGIN_DATA;
    process.env.CLAUDE_PLUGIN_DATA = dir;
    try {
      const state = emptyState();
      recordBlocks(state, [finding('a.ts', 'X001')]);
      saveSessionState('sess-1', state);
      const loaded = loadSessionState('sess-1');
      expect(loaded.blocks[findingKey('a.ts', 'X001')]).toBe(1);
      expect(loaded.totalBlocks).toBe(1);

      fs.writeFileSync(path.join(dir, 'sessions', 'sess-2.json'), '{broken');
      expect(loadSessionState('sess-2')).toEqual(expect.objectContaining({ totalBlocks: 0 }));
    } finally {
      if (prev === undefined) { delete process.env.CLAUDE_PLUGIN_DATA; }
      else { process.env.CLAUDE_PLUGIN_DATA = prev; }
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
