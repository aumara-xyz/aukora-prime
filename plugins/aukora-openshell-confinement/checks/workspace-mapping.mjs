// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure source regressions for explicit shell workspace identity mapping.
// The runner below only constructs argv; no provider, readback, sudo or shell
// is invoked. F's v2 readback/isolation checks retain their separate ownership.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readlinkSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  GUEST_WORKSPACE, MAX_COMMAND_BYTES, prepareLabTransport, readSettings, validateRequest,
} from '../lib/transport.mjs';

const HOST = '/host/workspace';
const command = "printf '%s\\n' 'guest-only fixture'";
const argv = Object.freeze(['bash', '-c', command]);
const settings = readSettings({ hostWorkspaceRoot: HOST, timeoutSeconds: 37 });
const layout = Object.freeze({
  users: Object.freeze({ host: 'aukora-host', agent: 'auma', gate: 'aukora-gate' }),
  sandbox: 'auma-ws',
  sbxExec: '/usr/local/lib/aukora-boundary/sbx-exec',
});

// The six-argument fixture matches boundary-gate's sandboxArgv signature.
// It produces data only and never executes the named program.
const checkedArgv = (guestCommand, timeout, selected) => [
  '/usr/bin/sudo',
  ['-n', '-u', selected.users.agent, selected.sbxExec, String(timeout), guestCommand],
];
const policy = (root = HOST) => ({ mode: 'workspace-write', workspaceRoot: root, sessionId: 'fixture-session' });
const prepare = (selectedPolicy, selectedSettings = settings, signal) =>
  prepareLabTransport(argv, selectedPolicy, selectedSettings, checkedArgv, layout, signal);
const refused = (operation, reason, message) => assert.throws(operation,
  error => error?.code === 'SANDBOX_UNAVAILABLE' && error.reason === reason, message);

function guestOnly(transport, forbiddenRoots = [HOST]) {
  assert.deepEqual(transport.argv.slice(0, -1), [
    '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', '/usr/bin/sudo',
    '-n', '-u', 'auma', layout.sbxExec, String(settings.timeoutSeconds),
  ]);
  assert.ok(transport.argv.at(-1).startsWith("cd -- '/sandbox' || "));
  assert.ok(transport.argv.at(-1).endsWith("exec 'bash' '-c' 'printf '\\''%s\\n'\\'' '\\''guest-only fixture'\\'''"));
  for (const root of forbiddenRoots) {
    assert.ok(!transport.argv.some(argument => argument.includes(root)),
      'declared host identity must not become an execution path');
  }
  assert.equal(Object.hasOwn(transport, 'cwd'), false);
  assert.equal(Object.hasOwn(transport, 'enforcement'), false,
    'pure preparation is not full-provider acceptance');
  assert.ok(Object.isFrozen(transport));
}

const cases = [
  ['exact declared host and guest roots yield identical guest-only transport', () => {
    const hostPolicy = Object.freeze(policy());
    const guestPolicy = Object.freeze(policy(GUEST_WORKSPACE));
    validateRequest(argv, hostPolicy, settings);
    const mapped = prepare(hostPolicy);
    assert.deepEqual(mapped, prepare(guestPolicy));
    guestOnly(mapped);
  }],
  ['absent mapping admits only the explicit guest root', () => {
    const unmapped = readSettings({ timeoutSeconds: 37 });
    assert.equal(Object.hasOwn(unmapped, 'hostWorkspaceRoot'), false);
    refused(() => prepare(policy(), unmapped), 'WORKSPACE');
    guestOnly(prepare(policy(GUEST_WORKSPACE), unmapped));
  }],
  ['absent or nontext policy roots never match an absent mapping', () => {
    const unmapped = readSettings({ timeoutSeconds: 37 });
    for (const selectedSettings of [settings, unmapped]) {
      refused(() => prepare({ mode: 'workspace-write', sessionId: 'fixture-session' }, selectedSettings), 'WORKSPACE');
      for (const root of [undefined, null, '', 0, false, {}, []]) {
        refused(() => prepare({ ...policy(), workspaceRoot: root }, selectedSettings), 'WORKSPACE');
      }
    }
  }],
  ['other roots, subroots, prefixes, traversal and lexical aliases refuse', () => {
    for (const root of [
      '/other/workspace', HOST + '/child', HOST + '-other', '/host/workspaces', '/host/work',
      '/', 'host/workspace', HOST + '/', '/host//workspace', '/host/./workspace',
      '/host/child/../workspace', HOST + '/..', HOST + '/.', '/sandbox/', '/sandbox/child',
      '/sandbox/../sandbox', '/sandbox//', HOST + '\0', '/host/\ud800workspace',
    ]) refused(() => prepare(policy(root)), 'WORKSPACE', 'nonexact policy root must refuse');
  }],
  ['noncanonical or unsupported mapping configuration refuses', () => {
    for (const hostWorkspaceRoot of [
      null, '', '/', 'host/workspace', GUEST_WORKSPACE, HOST + '/', '/host//workspace',
      '/host/./workspace', '/host/child/../workspace', HOST + '\0', '/host/\ud800workspace',
      '/' + 'x'.repeat(1024), 1, {}, [],
    ]) refused(() => readSettings({ hostWorkspaceRoot }), 'CONFIG');
    refused(() => readSettings({ hostWorkspaceRoot: HOST, inferredRoot: HOST }), 'CONFIG');
    refused(() => readSettings({ workspaceRoot: HOST }), 'WORKSPACE');
    for (const timeoutSeconds of [0, 301, 1.5, '37']) {
      refused(() => readSettings({ timeoutSeconds }), 'TIMEOUT');
    }
    assert.ok(Object.isFrozen(settings));
  }],
  ['a symlink alias is a distinct declaration and grants no host execution path', () => {
    const fixture = mkdtempSync(join(tmpdir(), 'prime-workspace-mapping-'));
    try {
      const root = join(fixture, 'workspace');
      const alias = join(fixture, 'alias');
      mkdirSync(root);
      symlinkSync(root, alias, 'dir');
      // Inspect the fixture link itself. Production is never asked to realpath
      // or open the host root; the only admission input is the declared string.
      assert.equal(readlinkSync(alias), root);
      const rootSettings = readSettings({ hostWorkspaceRoot: root, timeoutSeconds: 37 });
      refused(() => prepare(policy(alias), rootSettings), 'WORKSPACE');
      const aliasSettings = readSettings({ hostWorkspaceRoot: alias, timeoutSeconds: 37 });
      refused(() => prepare(policy(root), aliasSettings), 'WORKSPACE');
      const aliased = prepare(policy(alias), aliasSettings);
      assert.deepEqual(aliased, prepare(policy(GUEST_WORKSPACE), aliasSettings));
      guestOnly(aliased, [root, alias]);
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  }],
  ['preparation preserves original policy mode, session and command bytes', () => {
    const selected = Object.freeze(policy());
    const before = structuredClone(selected);
    const argvBefore = [...argv];
    prepare(selected);
    assert.deepEqual(selected, before);
    assert.equal(selected.workspaceRoot, HOST);
    assert.equal(selected.mode, 'workspace-write');
    assert.equal(selected.sessionId, 'fixture-session');
    assert.deepEqual(argv, argvBefore);
    validateRequest(argv, { ...policy(), sessionId: 's'.repeat(256) }, settings);
    validateRequest(['bash', '-c', "printf '%s' 'é\nfixture'"], policy(), settings);
  }],
  ['mode and resolved-policy shape guards remain mandatory', () => {
    for (const mode of ['read-only', 'danger-full-access', undefined, null, '']) {
      refused(() => prepare({ ...policy(), mode }), 'POLICY');
    }
    for (const selected of [null, undefined, [], 'workspace-write', { ...policy(), allowHost: true }]) {
      refused(() => prepare(selected), 'POLICY');
    }
  }],
  ['session identity guard remains mandatory after host mapping', () => {
    for (const sessionId of ['', 's'.repeat(257), 'bad\0session', '\ud800', null, 1, {}, []]) {
      refused(() => prepare({ ...policy(), sessionId }), 'POLICY');
    }
    validateRequest(argv, { mode: 'workspace-write', workspaceRoot: HOST }, settings);
  }],
  ['unsupported command forms and invalid text remain refused', () => {
    for (const badArgv of [undefined, null, [], ['echo', 'fixture'], ['python3', '-c', 'pass']]) {
      refused(() => validateRequest(badArgv, policy(), settings), 'ARGV');
    }
    for (const badArgv of [
      ['bash', '-lc', command], ['/bin/bash', '-c', command], ['sh', '-c', command],
      ['bash', '-c', command, 'extra'], ['bash', '-c', 'bad\0command'], ['bash', '-c', '\ud800'],
    ]) refused(() => validateRequest(badArgv, policy(), settings), 'TERMINAL_TRANSPORT');
    for (const executable of ['node', '/usr/bin/node', 'node.exe']) {
      refused(() => validateRequest([executable, '-e', '0'], policy(), settings), 'RUN_CODE_CONTROL_CHANNEL');
    }
  }],
  ['cancellation refuses before preparation and after argv construction', () => {
    const early = new AbortController();
    const earlyReason = new Error('fixture early cancellation');
    early.abort(earlyReason);
    assert.throws(() => prepare(policy(), settings, early.signal), error => error === earlyReason);
    const late = new AbortController();
    const lateReason = new Error('fixture late cancellation');
    let constructions = 0;
    assert.throws(() => prepareLabTransport(argv, policy(), settings, (...args) => {
      constructions++;
      late.abort(lateReason);
      return checkedArgv(...args);
    }, layout, late.signal), error => error === lateReason);
    assert.equal(constructions, 1);
  }],
  ['exact layout guards refuse before a runner can construct argv', () => {
    const wrongLayouts = [
      { ...layout, users: { ...layout.users, host: 'other-host' } },
      { ...layout, users: { ...layout.users, agent: 'other-agent' } },
      { ...layout, users: { ...layout.users, gate: 'other-gate' } },
      { ...layout, sandbox: 'other-sandbox' },
      { ...layout, sbxExec: '/other/sbx-exec' },
    ];
    for (const selected of wrongLayouts) {
      let called = false;
      refused(() => prepareLabTransport(argv, policy(), settings, (...args) => {
        called = true;
        return checkedArgv(...args);
      }, selected), 'BACKEND');
      assert.equal(called, false);
    }
  }],
  ['runner substitution, argument changes and extra flags refuse', () => {
    const brokenRunners = [
      () => ['/bin/bash', []],
      () => ['/usr/bin/sudo', null],
      (...args) => {
        const [program, selected] = checkedArgv(...args);
        return [program, [...selected, '--keep-fd=7']];
      },
      ...[0, 1, 2, 3, 4, 5].map(index => (...args) => {
        const [program, selected] = checkedArgv(...args);
        selected[index] = 'fixture-substitution';
        return [program, selected];
      }),
    ];
    for (const runner of brokenRunners) {
      refused(() => prepareLabTransport(argv, policy(), settings, runner, layout), 'BACKEND');
    }
  }],
  ['encoded command limit refuses before runner construction', () => {
    let called = false;
    refused(() => prepareLabTransport(['bash', '-c', 'x'.repeat(MAX_COMMAND_BYTES)], policy(), settings, (...args) => {
      called = true;
      return checkedArgv(...args);
    }, layout), 'ARGV');
    assert.equal(called, false);
  }],
];

let failures = 0;
for (const [name, check] of cases) {
  try {
    check();
    console.log(`PASS ${name}`);
  } catch (error) {
    failures++;
    console.error(`FAIL ${name}`);
    console.error(error);
  }
}
console.log(`workspace-mapping source checks: ${cases.length - failures}/${cases.length} PASS`);
if (failures) process.exitCode = 1;
