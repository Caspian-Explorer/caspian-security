#!/usr/bin/env node
// Exercise the artifact consumers install, without using this checkout's modules.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repo = path.resolve(__dirname, '..');
const manifest = require('../package.json');
const npmCli = process.env.npm_execpath;
assert(npmCli && fs.existsSync(npmCli), 'Run this check with npm run test:package');
const temporaryRoot = fs.realpathSync(os.tmpdir());
const scratch = fs.mkdtempSync(path.join(temporaryRoot, 'caspian-package-'));
const env = { ...process.env };
delete env.NODE_PATH;

function run(args, cwd, expected = 0) {
  const result = spawnSync(process.execPath, args, {
    cwd, env, encoding: 'utf8', timeout: 180000, maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error) { throw result.error; }
  assert.equal(result.status, expected, result.stderr + '\n' + result.stdout);
  return result.stdout;
}

try {
  const packed = JSON.parse(run([npmCli, 'pack', '--json', '--ignore-scripts', '--pack-destination', scratch], repo))[0];
  const files = new Set(packed.files.map(file => file.path));
  for (const file of [...Object.values(manifest.bin), 'out/extension.js', 'docs/CONNECT_PROJECT.md', 'docs/EXAMPLE_PR_REPORT.md']) {
    assert(files.has(file), 'Missing package file: ' + file);
  }
  assert(![...files].some(file => /(^|\/)(__tests__|__mocks__|node_modules|coverage)(\/|$)/.test(file)), 'Package contains development files');
  assert.equal(path.basename(packed.filename), packed.filename);
  const consumer = path.join(scratch, 'consumer');
  fs.mkdirSync(consumer);
  fs.writeFileSync(path.join(consumer, 'package.json'), '{"name":"caspian-package-smoke","private":true}');
  run([npmCli, 'install', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', '--package-lock=false', path.join(scratch, packed.filename)], consumer);
  const installed = path.join(consumer, 'node_modules', 'caspian-security');
  const cli = path.join(installed, manifest.bin.caspian);
  const installedManifest = JSON.parse(fs.readFileSync(path.join(installed, 'package.json'), 'utf8'));
  assert.equal(installedManifest.version, manifest.version);
  assert(run([cli, '--version'], consumer).includes(manifest.version));
  assert(fs.existsSync(path.join(consumer, 'node_modules', '.bin', process.platform === 'win32' ? 'caspian.cmd' : 'caspian')));
  const app = path.join(scratch, 'sample app');
  fs.mkdirSync(app);
  fs.writeFileSync(path.join(app, 'firestore.rules'), 'allow read, write: if true;\n');
  const preview = run([cli, 'init', app, '--github', '--dry-run'], consumer);
  assert(preview.includes('caspian-security.yml'));
  assert.deepEqual(fs.readdirSync(app), ['firestore.rules']);
  run([cli, 'init', app, '--github'], consumer);
  assert(fs.readFileSync(path.join(app, '.github/workflows/caspian-security.yml'), 'utf8').includes('new-only: true'));
  assert(!fs.existsSync(path.join(app, '.caspian/baseline.json')));
  const report = JSON.parse(run([cli, 'scan', app, '--format', 'json', '--strict', '--fail-on', 'error'], consumer, 1));
  assert.equal(report.summary.status, 'findings');
  assert(JSON.stringify(report).includes('DEPLOY001'));
  console.log('Installed package passed: ' + packed.entryCount + ' files, ' + packed.size + ' bytes; version, command shim, setup preview, workflow creation, and strict scan verified.');
} finally {
  // Only remove the unique directory created by this check, within the resolved temp root.
  assert.equal(path.dirname(path.resolve(scratch)), temporaryRoot);
  assert(path.basename(scratch).startsWith('caspian-package-'));
  fs.rmSync(scratch, { recursive: true, force: true });
}
