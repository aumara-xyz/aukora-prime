// SPDX-License-Identifier: AGPL-3.0-or-later
// Materialize just three explicitly pinned contracts into a disposable source-check tree.
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, rm, realpath, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const pins = {
  'runtime.mjs': 'd42ec191f52279b4af33ad23edb1518425817ac89e70a80955d0c0266386be12',
  'shared.mjs': '92dd3cf5aefb2d0fe206c892246620987d62898cdd40e3e7931f53ce590203ff',
  'json.mjs': '068aa14d3be101413cb028dc5f39e442130b4eeb87c40e18209ddce3ffce4639'
};
if (process.argv.length !== 4 || process.argv[2] !== '--contracts-root') throw new TypeError('Usage: node check-source.mjs --contracts-root /explicit/pinned/packages/contracts/src');
const sourceRoot = resolve(process.argv[3]);
if (await realpath(sourceRoot) !== sourceRoot) throw new TypeError('INVALID: physical contracts source path required');
const inputs = [];
for (const [name, pin] of Object.entries(pins)) {
  const path = join(sourceRoot, name), stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new TypeError('INVALID: regular named contracts input required');
  const bytes = await readFile(path);
  if (createHash('sha256').update(bytes).digest('hex') !== pin) throw new TypeError('INVALID: frozen contracts pin mismatch');
  inputs.push([name, bytes]);
}
const stage = await mkdtemp(join(tmpdir(), 'prime-pilot-metadata-'));
try {
  const contracts = join(stage, 'packages/contracts/src'), ops = join(stage, 'packages/ops/owner-save-pilot/v1');
  await mkdir(contracts, { recursive: true }); await mkdir(ops, { recursive: true });
  for (const [name, bytes] of inputs) await writeFile(join(contracts, name), bytes, { mode: 0o600 });
  for (const name of ['scope.mjs', 'profile.json', 'check-metadata.mjs']) {
    await writeFile(join(ops, name), await readFile(fileURLToPath(new URL(name, import.meta.url))), { mode: 0o600 });
  }
  const result = spawnSync(process.execPath, [join(ops, 'check-metadata.mjs')], {
    cwd: stage, env: { PATH: '/usr/bin:/bin', HOME: stage, TMPDIR: stage }, encoding: 'utf8', timeout: 30000, maxBuffer: 64 * 1024
  });
  if (result.error || result.status !== 0) throw new TypeError('SOURCE_CHECK_FAILED: ' + String(result.stderr ?? '').slice(0, 4096));
  process.stdout.write(result.stdout);
} finally { await rm(stage, { recursive: true, force: true }); }
