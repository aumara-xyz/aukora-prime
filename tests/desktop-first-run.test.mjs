#!/usr/bin/env node
// Resolver-only check: synthetic installation evidence in a scratch root, never an app or launcher.
// Shape-only receipts do not establish owner enrollment, key custody or signature verification.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { copyFile, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { CONFIG_TEMPLATE, resolveTarget } from '../apps/aukora-desktop/resolve.mjs'
import { artifactDigest } from '../plugins/aukora-composition-gate/src/artifact.mjs'
import { pluginSetDigest } from '../plugins/aukora-composition-gate/src/admission-grant.mjs'
import { operationDigestOf, setOperationContent } from '../plugins/aukora-composition-gate/src/plugin-set.mjs'

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
const scratch = await mkdtemp(join(tmpdir(), 'aukora-desktop-first-run-'))
const shell = fileURLToPath(new URL('../apps/aukora-desktop/', import.meta.url))
const templateBefore = structuredClone(CONFIG_TEMPLATE)

function pluginRecord(revision = 'original') {
  const shared = { 'plugins/shared/value.mjs': sha256('shared') }
  const artifacts = Object.fromEntries([
    ['zeta-long', 'plugins/zeta/index.mjs', revision],
    ['a', 'plugins/a/index.mjs', 'unchanged'],
  ].map(([id, entry, bytes]) => {
    const files = { ...shared, [entry]: sha256(bytes) }
    return [id, { id, entry, files, digest: artifactDigest(files) }]
  }))
  return { formatVersion: 1, kind: 'aukora-plugin-set/v1', count: 2, fileCount: 3,
    setDigest: pluginSetDigest(artifacts), artifacts }
}

const originalSet = pluginRecord()
const changedSet = pluginRecord('changed')
const receipt = {
  domain: 'aukora:approval-receipt:v1', verdict: 'OWNER_KEY_SIGNED',
  operationDigest: operationDigestOf(setOperationContent(originalSet)),
  approvalKeyDid: 'fixture-not-a-key', subject: 'fixture-subject', activeControlDigest: 'a'.repeat(64),
  challenge: 'b'.repeat(64), issuedAt: 1, expiresAt: 2, signature: '0'.repeat(128),
  signedBytesDigest: 'c'.repeat(64), approvalClass: 'fixture', keyClass: 'fixture',
}
const artifactBytes = Buffer.from('{\r\n  "producer": { "genesisCommit": "' + '1'.repeat(40) + '" }\r\n}\r\n')
const recordSha = sha256(artifactBytes)
assert.notEqual(recordSha, sha256(JSON.stringify(JSON.parse(artifactBytes))))

async function write(path, bytes) {
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, bytes)
}

async function fixture(name, { config = {}, env = {}, approval, record = originalSet, launchProfile } = {}) {
  const userData = join(scratch, name)
  const release = join(userData, 'release')
  const configPath = join(userData, 'config.json')
  const artifactPath = join(release, '.dsh-build/genesis-artifacts.json')
  const setPath = join(release, '.dsh-build/plugin-set.json')
  const stateRoot = env.AUKORA_DESKTOP_STATE ?? config.stateRoot ?? join(userData, 'state')
  const approvalPath = join(stateRoot, 'gate-state/plugin-set-approval.json')
  await write(configPath, JSON.stringify({ release, checkout: join(userData, 'checkout'), ...config }, null, 2) + '\n')
  await write(artifactPath, artifactBytes)
  await write(setPath, JSON.stringify(record, null, 2) + '\n')
  if (approval !== undefined) await write(approvalPath, typeof approval === 'string' ? approval : JSON.stringify(approval) + '\n')
  const tracked = [configPath, artifactPath, setPath, ...(approval === undefined ? [] : [approvalPath])]
  return { userData, release, stateRoot, approvalPath, setPath, configPath, artifactPath, tracked,
    args: { env, userData, checkoutsDir: join(userData, 'checkouts'), ...(launchProfile === undefined ? {} : { launchProfile }) } }
}

async function resolveUnchanged(sample, resolver = resolveTarget) {
  const before = await Promise.all(sample.tracked.map(path => readFile(path)))
  const target = await resolver(sample.args)
  assert.deepEqual(await Promise.all(sample.tracked.map(path => readFile(path))), before)
  return target
}

async function refuseUnchanged(sample, resolver = resolveTarget) {
  const before = await Promise.all(sample.tracked.map(path => readFile(path)))
  await assert.rejects(resolver(sample.args), error => error.message.startsWith('unapproved-release:')
    && error.message.includes(sample.configPath) && error.message.includes(sample.approvalPath))
  assert.deepEqual(await Promise.all(sample.tracked.map(path => readFile(path))), before)
  await assert.rejects(lstat(sample.args.checkoutsDir), { code: 'ENOENT' })
  await assert.rejects(lstat(join(sample.userData, 'aumlok-directory.patch.yml')), { code: 'ENOENT' })
}

function production(target) {
  assert.equal(target.launchProfile, 'production')
  assert.equal(Object.hasOwn(target, 'unsafePreviewAllowUnapproved'), false)
  assert.ok(target.why.every(line => !line.includes('UNSAFE DISPOSABLE PREVIEW')))
}

try {
  const first = await fixture('first-run')
  // A composition would otherwise cause the first-link overlay to be written.
  await write(join(first.release, 'aukora-composition.patch.yml'), 'synthetic composition\n')
  first.tracked.push(join(first.release, 'aukora-composition.patch.yml'))
  await refuseUnchanged(first)
  await assert.rejects(lstat(join(first.stateRoot, 'gate-state')), { code: 'ENOENT' })

  const bound = await fixture('bound-never-approved')
  for (const marker of [join(bound.userData, 'kira-deployment-overlay.patch.yml'), join(bound.stateRoot, 'aumlok/local-control.json')]) {
    await write(marker, 'synthetic marker, not key material\n')
    bound.tracked.push(marker)
  }
  await refuseUnchanged(bound)
  for (const [name, options] of [
    ['lost-approval', {}],
    ['lost-config-root', { config: { stateRoot: join(scratch, 'lost-config-state') } }],
    ['lost-env-root', { env: { AUKORA_DESKTOP_STATE: join(scratch, 'lost-env-state') } }],
  ]) {
    const sample = await fixture(name, options)
    const pin = join(sample.stateRoot, 'gate-state/plugin-set-approver.json')
    await write(pin, 'synthetic pin\n')
    sample.tracked.push(pin)
    await refuseUnchanged(sample)
  }
  const danglingPin = await fixture('dangling-pin')
  await mkdir(join(danglingPin.stateRoot, 'gate-state'), { recursive: true })
  await symlink(join(scratch, 'missing-pin'), join(danglingPin.stateRoot, 'gate-state/plugin-set-approver.json'))
  await refuseUnchanged(danglingPin)
  console.log('PASS first run, bound install and lost approval: refused without rewriting evidence')

  const approved = await fixture('approved-install', { approval: receipt })
  const approvedTarget = await resolveUnchanged(approved)
  production(approvedTarget)
  assert.deepEqual(approvedTarget.approvedRecordSha, [recordSha])
  assert.ok(approvedTarget.why.some(line => line.startsWith('APPROVED BY THE OWNER:')
    && line.includes(approved.approvalPath) && line.includes(originalSet.setDigest)))
  const copied = await fixture('approved-copy')
  await copyFile(approved.artifactPath, copied.artifactPath)
  await copyFile(approved.setPath, copied.setPath)
  await mkdir(dirname(copied.approvalPath), { recursive: true })
  await copyFile(approved.approvalPath, copied.approvalPath)
  copied.tracked.push(copied.approvalPath)
  const copiedTarget = await resolveUnchanged(copied)
  production(copiedTarget)
  assert.deepEqual(copiedTarget.approvedRecordSha, [recordSha])

  const changed = await fixture('changed-set', { approval: receipt, record: changedSet })
  await refuseUnchanged(changed)
  const configuredRoot = join(scratch, 'configured-state')
  const configured = await fixture('configured-root', { config: { stateRoot: configuredRoot }, approval: receipt })
  const configuredTarget = await resolveUnchanged(configured)
  production(configuredTarget)
  assert.equal(configuredTarget.stateRoot, configuredRoot)
  assert.deepEqual(configuredTarget.approvedRecordSha, [recordSha])
  const envRoot = join(scratch, 'environment-state')
  const environment = await fixture('environment-root', { config: { stateRoot: configuredRoot },
    env: { AUKORA_DESKTOP_STATE: envRoot }, approval: receipt })
  assert.equal((await resolveUnchanged(environment)).stateRoot, envRoot)
  console.log('PASS matching approval: raw-byte SHA, state-root precedence and synthetic copy preserved')

  const configuredSha = 'f'.repeat(64)
  const explicit = await fixture('explicit-record', { config: { approvedRecordSha: [configuredSha] } })
  const explicitTarget = await resolveUnchanged(explicit)
  production(explicitTarget)
  assert.deepEqual(explicitTarget.approvedRecordSha, [configuredSha])
  const append = await fixture('append-record', { config: { approvedRecordSha: [configuredSha] }, approval: receipt })
  assert.deepEqual((await resolveUnchanged(append)).approvedRecordSha, [configuredSha, recordSha])
  const duplicate = await fixture('duplicate-record', { config: { approvedRecordSha: [recordSha] }, approval: receipt })
  assert.deepEqual((await resolveUnchanged(duplicate)).approvedRecordSha, [recordSha])
  const preview = await fixture('explicit-preview', {
    launchProfile: 'disposable-preview', config: { unsafePreviewAllowUnapproved: true, approvedRecordSha: [configuredSha] },
    approval: receipt, record: changedSet,
  })
  const previewTarget = await resolveUnchanged(preview)
  assert.equal(previewTarget.unsafePreviewAllowUnapproved, true)
  assert.equal(previewTarget.launchProfile, 'disposable-preview')
  assert.deepEqual(previewTarget.approvedRecordSha, [configuredSha])
  for (const config of [{}, { unsafePreviewAllowUnapproved: false }]) {
    await refuseUnchanged(await fixture('preview-strict-' + Object.keys(config).length,
      { launchProfile: 'disposable-preview', config }))
  }
  assert.deepEqual(CONFIG_TEMPLATE, templateBefore)
  console.log('PASS configured approvals retained; explicit preview alone permits an explicit waiver')

  for (const [name, options] of [
    ['malformed-json', { approval: '{' }], ['malformed-receipt', { approval: {} }],
    ['truncated-receipt', { approval: { domain: receipt.domain, verdict: receipt.verdict, operationDigest: receipt.operationDigest } }],
    ['malformed-record', { approval: receipt, record: {} }],
  ]) await refuseUnchanged(await fixture(name, options))
  const dangling = await fixture('dangling-approval')
  await mkdir(dirname(dangling.approvalPath), { recursive: true })
  await symlink(join(scratch, 'missing-receipt'), dangling.approvalPath)
  await refuseUnchanged(dangling)
  assert.equal((await lstat(dangling.approvalPath)).isSymbolicLink(), true)

  // Exercise the packaged resolver and the receipt-to-set comparison through its actual implementation.
  const packagedRoot = join(scratch, 'packaged-shell')
  const isolatedShell = join(packagedRoot, 'Resources', 'app')
  await mkdir(isolatedShell, { recursive: true })
  for (const name of ['url-policy.mjs', 'install-settings.mjs']) await copyFile(join(shell, name), join(isolatedShell, name))
  const desktopPackage = JSON.parse(await readFile(join(shell, 'package.json'), 'utf8'))
  const helper = desktopPackage.build.extraFiles.find(entry =>
    entry.from === '../../plugins/aukora-aumlok/lib' && entry.to === 'plugins/aukora-aumlok/lib')
  assert.ok(helper?.filter.includes('plugin-set-content.mjs'))
  const helperDirectory = join(packagedRoot, helper.to)
  await mkdir(helperDirectory, { recursive: true })
  await copyFile(join(shell, helper.from, 'plugin-set-content.mjs'), join(helperDirectory, 'plugin-set-content.mjs'))
  const source = await readFile(join(shell, 'resolve.mjs'), 'utf8')
  for (const [name, anchor, replacement, sample] of [
    ['receipt-comparison', 'receipt.operationDigest === pluginSetOperationDigest(record)', 'true', changed],
    ['approval-required', 'if (approvedRecordSha.length === 0) {', 'if (false) {', first],
  ]) {
    assert.equal(source.split(anchor).length, 2)
    const mutantPath = join(isolatedShell, 'resolve-' + name + '.mjs')
    await writeFile(mutantPath, source.replace(anchor, replacement))
    const mutant = await import(pathToFileURL(mutantPath).href)
    await assert.rejects(refuseUnchanged(sample, mutant.resolveTarget), error => error.code === 'ERR_ASSERTION')
    console.log('RED caught: ' + name + ' removal violates the approval refusal oracle')
  }
  console.log('PASS desktop-first-run: resolver evidence only; signature verification and app launch excluded')
} finally {
  await rm(scratch, { recursive: true, force: true })
}
