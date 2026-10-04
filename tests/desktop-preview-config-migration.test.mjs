#!/usr/bin/env node
// Synthetic source-only checks. No installed application, backend, live config or key is used.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmod, link, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import {
  inspectLegacyPreviewConfigFile, MAX_PREVIEW_CONFIG_BYTES, MAX_PREVIEW_CONFIG_DEPTH,
  planLegacyPreviewConfigMigration,
} from '../apps/aukora-desktop/migrate-preview-config.mjs'
import { assertDesktopLaunchConfig, loadConfig, resolveTarget } from '../apps/aukora-desktop/resolve.mjs'

const helper = fileURLToPath(new URL('../apps/aukora-desktop/migrate-preview-config.mjs', import.meta.url))
const legacyRefusal = /legacy-preview-setting-refused/u
const migrationRefusal = code => error => error.code === `preview-config-migration:${code}`
const token = 'synthetic-token-never-a-live-credential'
// Reading can update atime; mutation metadata and file bytes must remain unchanged.
const mutationMetadata = info => Object.fromEntries(['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
  .map(field => [field, info[field]]))

async function scratch(t) {
  const path = await realpath(await mkdtemp(join(tmpdir(), 'aukora-config-migration-')))
  await chmod(path, 0o700)
  t.after(() => rm(path, { recursive: true, force: true }))
  return path
}

async function privateConfig(path, bytes) {
  await writeFile(path, bytes, { mode: 0o600 })
  await chmod(path, 0o600)
}

function cli(argv) {
  const result = spawnSync(process.execPath, [helper, ...argv], { encoding: 'utf8', timeout: 10_000 })
  assert.equal(result.error, undefined)
  assert.ok(!result.stdout.includes(token) && !result.stderr.includes(token), 'CLI must not disclose config values')
  return result
}

test('the exact legacy false shape refuses before attach and needs an explicit operator edit', async t => {
  const userData = await scratch(t)
  const path = join(userData, 'config.json')
  const bytes = '{\r\n  "attachUrl": "http://127.0.0.1:3187/?token=' + token + '",\r\n'
    + '  "allowUnapproved": false,\r\n  "approvedRecordSha": [],\r\n'
    + '  "note": "synthetic fixture only"\r\n}\r\n'
  await privateConfig(path, bytes)
  const args = { env: {}, userData, checkoutsDir: join(userData, 'checkouts') }
  await assert.rejects(loadConfig(userData), error => legacyRefusal.test(error.message)
    && error.message.includes(path) && error.message.includes('literal false')
    && error.message.includes('explicit operator review') && error.message.includes('never rename or convert')
    && !error.message.includes(token))
  await assert.rejects(resolveTarget(args), legacyRefusal)
  assert.equal(await readFile(path, 'utf8'), bytes)
  for (const name of ['checkouts', 'state', 'aumlok-directory.patch.yml']) {
    await assert.rejects(lstat(join(userData, name)), { code: 'ENOENT' })
  }
  const before = await lstat(path, { bigint: true })
  const plan = inspectLegacyPreviewConfigFile(path)
  assert.equal(plan.changed, true)
  assert.equal(plan.text, bytes.replace(',\r\n  "allowUnapproved": false', ''))
  assert.equal(await readFile(path, 'utf8'), bytes, 'read-only inspector never applies the plan')
  assert.deepEqual(mutationMetadata(await lstat(path, { bigint: true })), mutationMetadata(before))
  const check = cli(['--config', path])
  assert.equal(check.status, 0)
  assert.match(check.stdout, /^preview-config-migration:eligible:/u)
  assert.equal(check.stderr, '')
  assert.equal(await readFile(path, 'utf8'), bytes)

  // This synthetic write stands for the operator's explicit edit, not a helper writer.
  await privateConfig(path, plan.text)
  const migrated = JSON.parse(plan.text)
  assert.deepEqual(migrated, { attachUrl: 'http://127.0.0.1:3187/?token=' + token,
    approvedRecordSha: [], note: 'synthetic fixture only' })
  assertDesktopLaunchConfig(migrated)
  const target = await resolveTarget(args)
  assert.equal(target.mode, 'attach')
  assert.equal(target.origin, 'http://127.0.0.1:3187')
  assert.equal(target.bootstrapUrl, migrated.attachUrl)
  assert.equal(Object.hasOwn(target, 'unsafePreviewAllowUnapproved'), false)
  assert.equal(await readFile(path, 'utf8'), plan.text)
  for (const name of ['checkouts', 'state', 'aumlok-directory.patch.yml']) {
    await assert.rejects(lstat(join(userData, name)), { code: 'ENOENT' })
  }
})

test('only one top-level false member is removed, preserving all other raw value bytes', () => {
  for (const [before, after] of [
    ['{"allowUnapproved":false}', '{}'],
    ['{ "allowUnapproved" : false , "x": 1e3 }', '{ "x": 1e3 }'],
    ['{"x":1, "allowUnapproved":false, "y":-0}', '{"x":1, "y":-0}'],
    ['{"x":1, "allowUnapproved":false }', '{"x":1 }'],
    ['{\r\n "emoji":"🌲 café",\r\n "allowUnapproved":false\r\n}', '{\r\n "emoji":"🌲 café"\r\n}'],
    ['{"allow\\u0055napproved":false,"x":"\\u0061"}', '{"x":"\\u0061"}'],
    ['{"nested":{"allowUnapproved":false},"text":"allowUnapproved:false","allowUnapproved":false}',
      '{"nested":{"allowUnapproved":false},"text":"allowUnapproved:false"}'],
  ]) {
    const plan = planLegacyPreviewConfigMigration(before)
    assert.equal(plan.changed, true)
    assert.equal(plan.text, after)
    const expected = JSON.parse(before)
    delete expected.allowUnapproved
    assert.deepEqual(JSON.parse(plan.text), expected)
    assert.equal(Object.hasOwn(JSON.parse(plan.text), 'unsafePreviewAllowUnapproved'), false)
  }
  const absent = '{ "nested": {"allowUnapproved":false}, "number": 1e309 }\r\n'
  assert.deepEqual(planLegacyPreviewConfigMigration(absent), { changed: false, text: absent })
})

test('true and nonboolean legacy values, and any own preview waiver, cannot be migrated', () => {
  for (const value of [true, null, 0, 'false', [], {}]) {
    const text = JSON.stringify({ allowUnapproved: value })
    assert.throws(() => planLegacyPreviewConfigMigration(text), migrationRefusal('legacy-value-refused'))
    assert.throws(() => assertDesktopLaunchConfig(JSON.parse(text)), legacyRefusal)
  }
  for (const value of [false, true, null, 0, 'false']) {
    for (const legacy of [{}, { allowUnapproved: false }]) {
      assert.throws(() => planLegacyPreviewConfigMigration(JSON.stringify({ ...legacy, unsafePreviewAllowUnapproved: value })),
        migrationRefusal('unsafe-preview-setting-refused'))
    }
    assert.throws(() => assertDesktopLaunchConfig({ unsafePreviewAllowUnapproved: value }),
      /unsafe-preview-configuration-refused/u)
  }
  for (const profile of ['production', 'disposable-preview']) {
    assert.throws(() => assertDesktopLaunchConfig({ allowUnapproved: false }, profile), legacyRefusal)
  }
})

test('ambiguous, malformed, nonobject, oversized and deep JSON refuses with fixed codes', () => {
  for (const text of [
    '{"allowUnapproved":true,"allowUnapproved":false}',
    '{"allow\\u0055napproved":false,"allowUnapproved":false}',
    '{"allowUnapproved":false,"nested":{"x":1,"x":2}}',
  ]) assert.throws(() => planLegacyPreviewConfigMigration(text), migrationRefusal('json-duplicate-key-refused'))
  for (const text of ['{', '{"secret":"' + token + '",}', '\ufeff{"allowUnapproved":false}']) {
    assert.throws(() => planLegacyPreviewConfigMigration(text), migrationRefusal('json-malformed'))
  }
  for (const text of ['null', '[]', 'true', '1', '"object"']) {
    assert.throws(() => planLegacyPreviewConfigMigration(text), migrationRefusal('json-object-required'))
  }
  assert.throws(() => planLegacyPreviewConfigMigration({ allowUnapproved: false }), migrationRefusal('json-malformed'))
  assert.throws(() => planLegacyPreviewConfigMigration('{"padding":"' + 'x'.repeat(MAX_PREVIEW_CONFIG_BYTES) + '"}'),
    migrationRefusal('json-size-refused'))
  const deep = '{"allowUnapproved":false,"nested":' + '['.repeat(MAX_PREVIEW_CONFIG_DEPTH) + '0'
    + ']'.repeat(MAX_PREVIEW_CONFIG_DEPTH) + '}'
  assert.throws(() => planLegacyPreviewConfigMigration(deep), migrationRefusal('json-depth-refused'))
})

test('explicit reader refuses symlinks, hardlinks, directory targets, wider modes and invalid UTF-8', async t => {
  const root = await scratch(t)
  const path = join(root, 'config.json')
  const bytes = '{"attachUrl":"http://127.0.0.1/?token=' + token + '","allowUnapproved":false}'
  await privateConfig(path, bytes)
  const named = join(root, 'named.json')
  await symlink(path, named)
  assert.throws(() => inspectLegacyPreviewConfigFile(named), migrationRefusal('canonical-config-path-required'))
  await rm(named)
  await link(path, named)
  assert.throws(() => inspectLegacyPreviewConfigFile(path), migrationRefusal('private-file-required'))
  await rm(named)
  assert.throws(() => inspectLegacyPreviewConfigFile(root), migrationRefusal('private-file-required'))
  await chmod(path, 0o644)
  assert.throws(() => inspectLegacyPreviewConfigFile(path), migrationRefusal('private-file-required'))
  await chmod(path, 0o600)
  await chmod(root, 0o755)
  assert.throws(() => inspectLegacyPreviewConfigFile(path), migrationRefusal('private-file-required'))
  await chmod(root, 0o700)
  const alias = join(root, 'alias')
  const folder = join(root, 'folder')
  await mkdir(folder, { mode: 0o700 })
  await privateConfig(join(folder, 'config.json'), bytes)
  await symlink(folder, alias)
  assert.throws(() => inspectLegacyPreviewConfigFile(join(alias, 'config.json')), migrationRefusal('canonical-config-path-required'))
  const fifo = join(root, 'fifo')
  const made = spawnSync('/usr/bin/mkfifo', [fifo], { encoding: 'utf8', timeout: 10_000 })
  assert.equal(made.status, 0)
  assert.throws(() => inspectLegacyPreviewConfigFile(fifo), migrationRefusal('private-file-required'))
  assert.equal(await readFile(path, 'utf8'), bytes)
  await privateConfig(path, Buffer.from([0xff, 0xfe]))
  assert.throws(() => inspectLegacyPreviewConfigFile(path), migrationRefusal('json-malformed'))
  await privateConfig(path, ' '.repeat(MAX_PREVIEW_CONFIG_BYTES + 1))
  assert.throws(() => inspectLegacyPreviewConfigFile(path), migrationRefusal('json-size-refused'))
})

test('CLI has no default/discovery/write option and never prints malformed data or duplicate keys', async t => {
  const root = await scratch(t)
  const path = join(root, 'config.json')
  for (const argv of [[], ['--config'], ['--config', 'config.json'], ['--config', path, '--config', path],
    ['--apply', '--config', path], [path]]) {
    const result = cli(argv)
    assert.equal(result.status, 1)
    assert.equal(result.stdout, '')
    assert.match(result.stderr, /^preview-config-migration:/u)
  }
  for (const bytes of ['{"' + token + '":1,"' + token + '":2,"allowUnapproved":false}',
    '{"secret":"' + token + '",}', '{"allowUnapproved":true,"secret":"' + token + '"}']) {
    await privateConfig(path, bytes)
    const before = await lstat(path, { bigint: true })
    const result = cli(['--config', path])
    assert.equal(result.status, 1)
    assert.equal(result.stdout, '')
    assert.equal(await readFile(path, 'utf8'), bytes)
    assert.deepEqual(mutationMetadata(await lstat(path, { bigint: true })), mutationMetadata(before))
  }
  await privateConfig(path, '{"attachUrl":"http://127.0.0.1/?token=' + token + '"}')
  const result = cli(['--config', path])
  assert.equal(result.status, 0)
  assert.match(result.stdout, /^preview-config-migration:unchanged:/u)
})
