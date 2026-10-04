// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure source regressions: no provider application, policy INFO, or process launch.
import assert from 'node:assert/strict';
import test from 'node:test';
import { guestBashExecutor, guestSpec } from '../lib/index.mjs';
import { readSettings, validateConfinementInfo } from '../lib/transport.mjs';
import { validateGuestPolicy } from '../lib/subprocess.mjs';

const HOST = '/host/workspace';
const GUEST = '/sandbox';
const unavailable = error => error?.code === 'SANDBOX_UNAVAILABLE';
const policy = (workspaceRoot = HOST, mode = 'workspace-write') => ({
  mode, workspaceRoot, sessionId: 'synthetic-session',
});
const spec = (workdir = HOST, sandboxPolicy = policy()) => ({
  command: 'printf synthetic', workdir, sandboxPolicy, timeoutMs: 1000, stdoutMaxBytes: 128,
});

class FakeExecutor {
  resolve(request) {
    this.baseResolveRequest = request;
    return { ...request };
  }
  async run(resolved) {
    this.baseRunSpec = resolved;
    return resolved;
  }
}

test('applied profile admits the approved terminal devices and refuses other device grants', () => {
  const approved = ['/sandbox', '/tmp', '/dev/null', '/dev/pts', '/dev/ptmx'];
  const info = readWrite => ({
    version: 1, openshell_version: '0.1.2', sandbox: 'auma-ws', state: 'Ready',
    instance_id: 'synthetic-instance', policy_revision: 1, applied_revision: 1,
    workspace_root: GUEST, network_mode: 'none',
    policy: {
      version: 1,
      filesystem_policy: {
        include_workdir: false, read_only: ['/usr', '/proc'], read_write: readWrite,
      },
      landlock: { compatibility: 'hard_requirement' }, network_policies: {},
    },
  });
  for (const roots of [approved, [...approved].reverse()]) {
    const observed = info(roots);
    assert.equal(validateConfinementInfo(observed), observed);
  }
  for (const roots of [
    approved.slice(0, 3),
    approved.filter(path => path !== '/dev/pts'),
    approved.filter(path => path !== '/dev/ptmx'),
    ['/sandbox', '/tmp', '/dev/null', '/dev', '/dev/ptmx'],
    [...approved, '/dev/tty'],
    ['/sandbox', '/tmp', '/dev/null', '/dev/pts', '/dev/pts'],
  ]) {
    assert.throws(() => validateConfinementInfo(info(roots)),
      error => unavailable(error) && error.reason === 'FILE_POLICY');
  }
});

test('host workspace configuration must declare one normalized absolute root', () => {
  const settings = readSettings({ hostWorkspaceRoot: HOST });
  assert.equal(settings.hostWorkspaceRoot, HOST);
  assert.equal(settings.workspaceRoot, GUEST);
  assert.equal(readSettings().hostWorkspaceRoot, undefined);
  for (const root of ['host/workspace', '/', '/host/workspace/', '/host//workspace',
    '/host/./workspace', '/host/../workspace', GUEST]) {
    assert.throws(() => readSettings({ hostWorkspaceRoot: root }), unavailable, root);
  }
});

test('exact declared host identity maps both Bash paths without changing policy mode or input', () => {
  const settings = readSettings({ hostWorkspaceRoot: HOST });
  const original = Object.freeze({ ...spec(), sandboxPolicy: Object.freeze(policy()) });
  const mapped = guestSpec(original, settings);
  assert.equal(mapped.workdir, GUEST);
  assert.deepEqual(mapped.sandboxPolicy, policy(GUEST));
  assert.equal(mapped.command, original.command);
  assert.equal(mapped.timeoutMs, original.timeoutMs);
  assert.equal(mapped.stdoutMaxBytes, original.stdoutMaxBytes);
  assert.equal(original.workdir, HOST);
  assert.equal(original.sandboxPolicy.workspaceRoot, HOST);
  // Mapping a path cannot upgrade the caller's authority into workspace-write.
  const restricted = guestSpec(spec(HOST, policy(HOST, 'read-only')), settings);
  assert.equal(restricted.sandboxPolicy.mode, 'read-only');
  assert.throws(() => validateGuestPolicy(restricted.sandboxPolicy, settings), unavailable);
});

test('declared host root admits no inferred subdirectory or unrelated workspace identity', () => {
  const settings = readSettings({ hostWorkspaceRoot: HOST });
  for (const root of [HOST + '/child', '/other/workspace']) {
    assert.throws(() => guestSpec(spec(root), settings), unavailable, root);
    assert.throws(() => validateGuestPolicy(policy(root), settings), unavailable, root);
  }
  assert.doesNotThrow(() => validateGuestPolicy(policy(HOST), settings));
  assert.doesNotThrow(() => validateGuestPolicy(policy(GUEST), settings));
});

test('without declared host mapping, only the explicit guest workspace is supported', async () => {
  const settings = readSettings();
  const input = spec();
  assert.equal(guestSpec(input, settings), input);
  assert.throws(() => validateGuestPolicy(policy(HOST), settings), unavailable);
  const Executor = guestBashExecutor(FakeExecutor, settings, true);
  const executor = new Executor();
  assert.throws(() => executor.resolve(input), unavailable);
  await assert.rejects(executor.run(input), unavailable);
  const guestInput = spec(GUEST, policy(GUEST));
  assert.equal(executor.resolve(guestInput).workdir, GUEST);
  assert.equal((await executor.run(guestInput)).workdir, GUEST);
});

test('Bash resolve and direct run both use the declared mapping before native execution', async () => {
  const settings = readSettings({ hostWorkspaceRoot: HOST });
  const Executor = guestBashExecutor(FakeExecutor, settings, true);
  const executor = new Executor();
  const input = spec();
  const resolved = executor.resolve(input);
  assert.equal(executor.baseResolveRequest, input);
  assert.equal(resolved.workdir, GUEST);
  assert.deepEqual(resolved.sandboxPolicy, policy(GUEST));
  const fromResolved = await executor.run(resolved);
  assert.equal(executor.baseRunSpec, fromResolved);
  assert.equal(fromResolved.workdir, GUEST);
  assert.deepEqual(fromResolved.sandboxPolicy, policy(GUEST));
  const direct = await executor.run({ ...input, dshEnv: { DSH_SESSION_ID: 'synthetic-session' } });
  assert.equal(direct.workdir, GUEST);
  assert.deepEqual(direct.sandboxPolicy, policy(GUEST));
  assert.equal(direct.dshEnv, undefined);
  assert.equal(input.workdir, HOST);
});

test('already-guest policy cannot bypass the exact workdir guard in resolve or run', async () => {
  const settings = readSettings({ hostWorkspaceRoot: HOST });
  const Executor = guestBashExecutor(FakeExecutor, settings, true);
  const executor = new Executor();
  for (const workdir of [HOST, HOST + '/child', '/other/workspace', GUEST + '/child']) {
    const input = spec(workdir, policy(GUEST));
    assert.throws(() => executor.resolve(input), unavailable, workdir);
    await assert.rejects(executor.run(input), unavailable, workdir);
  }
  assert.equal(executor.baseRunSpec, undefined, 'refused paths must never reach the fake native executor');
});
