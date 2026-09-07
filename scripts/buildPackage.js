#!/usr/bin/env node
// Both npm and VSIX packages use a fresh build without test fixtures or stale output.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = fs.realpathSync(path.resolve(__dirname, '..'));
const output = path.join(root, 'out');
assert.equal(path.dirname(output), root);
if (fs.existsSync(output)) {
  assert(!fs.lstatSync(output).isSymbolicLink(), 'Refusing to clean a linked output directory');
  assert.equal(fs.realpathSync(output), output, 'Output must resolve to the build directory');
  fs.rmSync(output, { recursive: true, force: true });
}
const result = spawnSync(process.execPath, [require.resolve('typescript/bin/tsc'), '-p', 'tsconfig.package.json'], {
  cwd: root, stdio: 'inherit', timeout: 180000,
});
if (result.error) { throw result.error; }
process.exit(result.status === null ? 1 : result.status);
