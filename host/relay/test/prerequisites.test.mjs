// SPDX-License-Identifier: AGPL-3.0-or-later
// Missing host prerequisites report exit 2; unrelated execution errors remain failures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const files = [
  [new URL('../check.mjs', import.meta.url), 'const source ='],
  [new URL('./relay.test.mjs', import.meta.url), 'const tokens ='],
  [new URL('../../aura-interim/verify.mjs', import.meta.url), 'const { verifyCollectorStore }'],
];
const stub = `import {createRequire, syncBuiltinESMExports} from 'node:module';
import {EventEmitter} from 'node:events';
const net = createRequire(import.meta.url)('node:net');
net.createServer = () => Object.assign(new EventEmitter(), {listen() {
  queueMicrotask(() => this.emit('error', Object.assign(new Error('synthetic listen refusal'), {code: process.env.PROBE_ERROR}))); return this;
}});
syncBuiltinESMExports();`;

for (const [url, end] of files) test(`${url.pathname.split('/').slice(-2).join('/')}: named prerequisite and mutation`, () => {
  const source = readFileSync(url, 'utf8').split(end)[0];
  assert.ok(source.includes('process.exit(2)'));
  const directory = mkdtempSync(join(dirname(fileURLToPath(url)), '.prerequisite-'));
  const program = join(dirname(fileURLToPath(url)), `.prerequisite-${directory.split('/').at(-1)}.mjs`);
  try {
    const preload = join(directory, 'listen.mjs'); writeFileSync(preload, stub);
    const run = bytes => {
      writeFileSync(program, bytes);
      return spawnSync(process.execPath, ['--import', preload, program], {encoding: 'utf8', timeout: 10000,
        env: {...process.env, NODE_NO_WARNINGS: '1', AUKORA_RELEASE_DIR: '', PROBE_ERROR: 'EPERM'}});
    };
    const expected = result => {
      assert.equal(result.status, 2, result.stderr);
      assert.match(result.stdout, /^UNPERFORMED: [^\n]+\n$/);
    };
    expected(run(source));
    assert.throws(() => expected(run(source.replace('process.exit(2)', 'process.exit(0)'))), {name: 'AssertionError'});
    if (source.includes("['EPERM', 'EACCES']")) {
      writeFileSync(program, source);
      const result = spawnSync(process.execPath, ['--import', preload, program], {encoding: 'utf8', timeout: 10000,
        env: {...process.env, NODE_NO_WARNINGS: '1', PROBE_ERROR: 'EADDRINUSE'}});
      assert.equal(result.status, 1); assert.doesNotMatch(result.stdout, /UNPERFORMED/);
    }
  } finally {rmSync(program, {force: true}); rmSync(directory, {recursive: true, force: true});}
});
