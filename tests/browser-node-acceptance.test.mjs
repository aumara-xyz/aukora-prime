// Verify container transport readback before privileged acceptance dispatch.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
// Registered with this existing acceptance check to keep the shared runner unchanged.
import { evidenceFixture } from './browser-node-evidence.test.mjs'
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const script = path.join(root, 'ops/node-spawn/browser/acceptance.sh')
const source = fs.readFileSync(script, 'utf8')
const base = { config: { 'security.privileged': 'false', 'security.nesting': 'false',
  'security.idmap.isolated': 'true', 'security.devlxd': 'false' }, devices: {
  root: { type: 'disk' },
  'browser-app': { type: 'proxy', bind: 'host', nat: 'false', 'security.uid': '65534',
    'security.gid': '65534', connect: 'tcp:127.0.0.1:18735', listen: 'tcp:127.0.0.1:28735' },
  'browser-owner': { type: 'proxy', bind: 'host', nat: 'false', 'security.uid': '65534',
    'security.gid': '65534', connect: 'tcp:127.0.0.1:17792', listen: 'tcp:127.0.0.1:27792' },
  'browser-claim': { type: 'proxy', bind: 'host', nat: 'false', 'security.uid': '65534',
    'security.gid': '65534', connect: 'tcp:127.0.0.1:18736', listen: 'tcp:127.0.0.1:28736' },
} }

function fixture(t) {
  const runtime = path.join(root, '.runtime')
  fs.mkdirSync(runtime, { recursive: true, mode: 0o700 })
  const dir = fs.mkdtempSync(path.join(runtime, 'browser-accept-'))
  const config = path.join(dir, 'config.json'), log = path.join(dir, 'calls')
  fs.writeFileSync(path.join(dir, 'lxc'), '#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\n'
    + 'case "$*" in *" query "*) if [[ ${REFUSE_CONFIG:-0} == 1 ]]; then exit 1; fi; cat "$CONFIG" ;; *"--evidence"*) if [[ -n ${EVIDENCE_FILE:-} ]]; then cat "$EVIDENCE_FILE"; else printf "%s\\n" "$EVIDENCE_RECORD"; fi; exit "${ACCEPTANCE_EXIT:-0}" ;; *" exec "*) printf "PASS synthetic container acceptance\\n" ;; *) exit 66 ;; esac\n', { mode: 0o700 })
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const call = (value = base, args = ['--name', 'C1', '--phase', 'after'], modified = source, extra = {}) => {
    fs.writeFileSync(config, typeof value === 'string' ? value : JSON.stringify({ expanded_config: value.config, expanded_devices: value.devices }))
    fs.writeFileSync(log, '')
    const file = path.join(dir, 'acceptance.sh')
    fs.writeFileSync(file, modified)
    const result = spawnSync('bash', [file, ...args], { cwd: root, encoding: 'utf8', timeout: 10000,
      env: { PATH: dir + ':' + process.env.PATH, CONFIG: config, CALLS: log, ...extra } })
    return { ...result, calls: fs.readFileSync(log, 'utf8') }
  }
  return Object.assign(call, { directory: dir })
}
const clone = () => structuredClone(base)
const attacks = [
  ['privileged', 'assert config.get("security.privileged")=="false" and config.get("security.nesting")=="false"', v => v.config['security.privileged'] = 'true'],
  ['nested', 'assert config.get("security.privileged")=="false" and config.get("security.nesting")=="false"', v => v.config['security.nesting'] = 'true'],
  ['idmap', 'assert config.get("security.idmap.isolated")=="true" and config.get("security.devlxd")=="false"', v => v.config['security.idmap.isolated'] = 'false'],
  ['devlxd', 'assert config.get("security.idmap.isolated")=="true" and config.get("security.devlxd")=="false"', v => v.config['security.devlxd'] = 'true'],
  ['NIC', 'assert set(devices)=={"root","browser-app","browser-owner","browser-claim"} and devices["root"]["type"]=="disk"', v => v.devices.net = { type: 'nic' }],
  ['proxy type', 'assert device["type"]=="proxy" and device.get("bind")=="host" and device.get("nat")=="false"', v => v.devices['browser-app'].type = 'disk'],
  ['proxy namespace', 'assert device["type"]=="proxy" and device.get("bind")=="host" and device.get("nat")=="false"', v => v.devices['browser-app'].bind = 'container'],
  ['NAT', 'assert device["type"]=="proxy" and device.get("bind")=="host" and device.get("nat")=="false"', v => v.devices['browser-app'].nat = 'true'],
  ['proxy uid', 'assert device.get("security.uid")=="65534" and device.get("security.gid")=="65534"', v => v.devices['browser-app']['security.uid'] = '0'],
  ['proxy gid', 'assert device.get("security.uid")=="65534" and device.get("security.gid")=="65534"', v => v.devices['browser-app']['security.gid'] = '0'],
  ['target', 'assert device["connect"]=="tcp:127.0.0.1:"+target', v => v.devices['browser-owner'].connect = 'tcp:0.0.0.0:17792'],
  ['low port', 'assert match and 1024<=int(match[1])<=65535', v => v.devices['browser-app'].listen = 'tcp:127.0.0.1:1000'],
  ['high port', 'assert match and 1024<=int(match[1])<=65535', v => v.devices['browser-app'].listen = 'tcp:127.0.0.1:65536'],
  ['same port', 'assert len(set(ports))==3', v => v.devices['browser-owner'].listen = v.devices['browser-app'].listen],
  ['claim port collision', 'assert len(set(ports))==3', v => v.devices['browser-claim'].listen = v.devices['browser-app'].listen],
]
test('acceptance validates arguments, local proxy readback and embedded Python syntax', t => {
  const call = fixture(t)
  const ok = call()
  assert.equal(ok.status, 0, ok.stderr)
  assert.match(ok.calls, /^--force-local query \/1\.0\/instances\/C1\n--force-local exec C1 /)
  assert.match(ok.calls, /accept --phase after/)
  for (const args of [[], ['--name', '-C1', '--phase', 'after'], ['--name', 'C 1', '--phase', 'after'],
    ['--name', 'C1', '--phase', 'unknown'], ['--name', 'C1', '--phase', 'after', '--extra']]) {
    const bad = call(base, args)
    assert.equal(bad.status, 1); assert.match(bad.stderr, /BROWSER_ACCEPTANCE_USAGE/); assert.equal(bad.calls, '')
  }
  const config = call(base, undefined, undefined, { REFUSE_CONFIG: '1' })
  assert.equal(config.status, 1); assert.match(config.stderr, /BROWSER_ACCEPTANCE_CONFIG/)
  const missingClaim = clone(); delete missingClaim.devices['browser-claim']
  assert.equal(call(missingClaim).status, 1)
  for (const value of ['not json PRIVATE_SENTINEL', {}, { ...base, config: {} }]) {
    const bad = call(value)
    assert.equal(bad.status, 1); assert.match(bad.stderr, /BROWSER_ACCEPTANCE_TRANSPORT/)
    assert.doesNotMatch(bad.stdout + bad.stderr, /PRIVATE_SENTINEL/)
    assert.doesNotMatch(bad.calls, / exec /)
  }
  const code = source.match(/python3 -I -S -c '([\s\S]*?)'\n/)[1]
  assert.equal(spawnSync('python3', ['-I', '-S', '-B', '-c', 'import sys;compile(sys.stdin.read(),"acceptance-inline","exec")'], { input: code }).status, 0)
})
test('acceptance transport guard removals fail real negative readback fixtures', t => {
  const call = fixture(t)
  for (const [label, anchor, attack] of attacks) {
    const value = clone(); attack(value)
    const bad = call(value)
    assert.equal(bad.status, 1, label); assert.doesNotMatch(bad.calls, / exec /)
    assert.equal(source.split(anchor).length, 2, label)
    const removed = call(value, undefined, source.replace(anchor, 'pass'))
    assert.equal(removed.status, 0, 'removed guard should accept the unsafe fixture: ' + label)
  }
  const publicListener = clone()
  publicListener.devices['browser-app'].listen = 'tcp:0.0.0.0:28735'
  assert.equal(call(publicListener).status, 1)
  const anchor = 'tcp:127\\.0\\.0\\.1:([1-9][0-9]{3,4})'
  assert.equal(source.split(anchor).length, 2)
  assert.equal(call(publicListener, undefined, source.replace(anchor, 'tcp:[^:]+:([1-9][0-9]{3,4})')).status, 0)
  console.log(`SOURCE-ONLY browser acceptance transport mutations: ${attacks.length + 1}/${attacks.length + 1} killed; mocked LXD only`)
})

test('acceptance exports only after to a fresh file and preserves failed observations', t => {
  const call = fixture(t), out = path.join(call.directory, 'evidence.json')
  const args = ['--name', 'C1', '--phase', 'after', '--evidence', out]
  const record = JSON.stringify({ kind: 'aukora-browser-node-evidence/v1', checks: [{ name: 'root_platform', status: 'FAIL' }] })
  const exported = JSON.stringify({ kind: 'aukora-browser-node-evidence/v1', checks: [
    { name: 'host_transport', status: 'PASS' }, { name: 'root_platform', status: 'FAIL' }] }) + '\n'
  const extra = { EVIDENCE_RECORD: record, ACCEPTANCE_EXIT: '1' }
  const fail = call(base, args, source, extra)
  assert.equal(fail.status, 1)
  assert.equal(fs.readFileSync(out, 'utf8'), exported)
  assert.equal(fs.statSync(out).mode & 0o777, 0o600)
  assert.match(fail.calls, /accept --phase after --evidence/)
  const overwrite = call(base, args, source, { EVIDENCE_RECORD: record })
  assert.equal(overwrite.status, 1); assert.match(overwrite.stderr, /BROWSER_ACCEPTANCE_EVIDENCE_OUTPUT/)
  assert.equal(fs.readFileSync(out, 'utf8'), exported)
  fs.unlinkSync(out)
  fs.symlinkSync(path.join(call.directory, 'missing-target'), out)
  assert.equal(call(base, args, source, extra).status, 1)
  assert.equal(fs.existsSync(path.join(call.directory, 'missing-target')), false)
  fs.unlinkSync(out)
  for (const raw of ['PRIVATE_SENTINEL', '{"kind":"private","secret":"PRIVATE_SENTINEL"}']) {
    const bad = call(base, args, source, { EVIDENCE_RECORD: raw })
    assert.equal(bad.status, 1); assert.equal(fs.existsSync(out), false)
    assert.doesNotMatch(bad.stdout + bad.stderr, /PRIVATE_SENTINEL/)
  }
  const beforeArgs = ['--name', 'C1', '--phase', 'before', '--evidence', out]
  assert.equal(call(base, beforeArgs, source, extra).calls, '')
  assert.equal(call(base, args, source, { EVIDENCE_RECORD: record }).status, 0)
  const huge = path.join(call.directory, 'huge-input.json')
  fs.writeFileSync(huge, record + ' '.repeat(4 * 1024 * 1024))
  const controls = [
    ['after-only export', ' && $4 == after', '', beforeArgs, extra],
    ['exclusive output', 'os.O_EXCL', '0', args, { EVIDENCE_RECORD: record }],
    ['public record kind', 'assert isinstance(value,dict) and value.get("kind")=="aukora-browser-node-evidence/v1"', 'pass',
      ['--name', 'C1', '--phase', 'after', '--evidence', path.join(call.directory, 'private.json')], { EVIDENCE_RECORD: '{"secret":"PRIVATE_SENTINEL","checks":[]}' }],
    ['output bound', 'assert 0<len(raw)<=4*1024*1024', 'pass',
      ['--name', 'C1', '--phase', 'after', '--evidence', path.join(call.directory, 'huge.json')],
      { EVIDENCE_FILE: huge }],
  ]
  for (const [name, anchor, replacement, argv, environment] of controls) {
    if (name === 'output bound') assert.equal(call(base, argv, source, environment).status, 1)
    assert.equal(source.split(anchor).length, 2, name)
    const result = call(base, argv, source.replace(anchor, replacement), environment)
    assert.equal(result.status, environment.ACCEPTANCE_EXIT === '1' ? 1 : 0, name)
    if (name === 'after-only export') assert.match(result.calls, / exec /)
    else assert.equal(result.status, 0)
  }
  console.log(`SOURCE-ONLY browser evidence output mutations: ${controls.length}/${controls.length} killed; mocked LXD only`)
  const anchor = '    value["checks"].insert(0,{"name":"host_transport","status":"PASS"})\n'
  assert.equal(source.split(anchor).length, 2)
  fs.unlinkSync(out)
  const removed = call(base, args, source.replace(anchor, ''), { EVIDENCE_RECORD: record })
  assert.equal(removed.status, 0)
  assert.throws(() => assert.equal(fs.readFileSync(out, 'utf8'), exported), { code: 'ERR_ASSERTION' })
  console.log('SOURCE-ONLY browser evidence host transport removal: 1/1 killed; mocked LXD only')
})

test('Python export and host projection preserve signed receipt bytes for the offline CLI', t => {
  const f = evidenceFixture(), record = f.record, artifacts = '{"artifacts":[]}\n'
  const hash = value => createHash('sha256').update(value).digest('hex')
  const content = JSON.parse(record.approval.content)
  record.release.record_sha256 = record.floor.record = content.record = hash(artifacts)
  record.approval.content = JSON.stringify(content)
  record.approval.receipt.new_sha = hash(record.approval.content)
  f.signReceipt()
  const python = `import json,sys,types
from pathlib import Path
from datetime import datetime
root,node=sys.argv[1:]
record=json.load(sys.stdin)
m=types.ModuleType('export_fixture')
exec(compile((Path(root)/'ops/node-spawn/browser/node.py').read_text(),'node.py','exec'),m.__dict__)
m.installed=lambda: {'revision':record['release']['revision'],'inputs':dict(record['installer_inputs'],app_host='PRIVATE_HOST',owner_host='PRIVATE_HOST')}
sources={'plugin-set-approver.json':{'gatePubkeyPem':record['signer']['public_key_pem']},'plugin-set-approval.json':record['approval'],'release-floor.json':record['floor'],'signer-epochs.json':{'epochs':[{'gate_pubkey_sha256':record['signer']['sha256']}]},'plugin-set.json':{'setDigest':record['release']['plugin_set_sha256']},'aukora-release.json':{'tipSha':record['release']['revision']},'genesis-artifacts.json':{'artifacts':[]}}
m.evidence_json=lambda file: (sources[file.name],b'${artifacts.replaceAll('\n', '\\n')}')
m.protected=lambda *args,**kwargs: None
m.gate_signer=lambda: record['signer']['public_key_pem']
m.NODE=node
m.CHECKOUT=Path(root)
m.datetime=types.SimpleNamespace(now=lambda zone: datetime.fromisoformat(record['observed_at'].replace('Z','+00:00')))
print(m.evidence_record(record['checks'][1:]))
`
  const exported = spawnSync('python3', ['-I', '-S', '-B', '-c', python, root, process.execPath], {
    input: JSON.stringify(record), encoding: 'utf8', timeout: 10000,
  })
  assert.equal(exported.status, 0, exported.stderr)
  assert.doesNotMatch(exported.stdout, /PRIVATE_HOST/)
  assert.equal(JSON.stringify(JSON.parse(exported.stdout).approval.receipt), JSON.stringify(record.approval.receipt))
  assert.equal(JSON.parse(exported.stdout).approval.ledger_entry.detail, record.approval.ledger_entry.detail)
  const call = fixture(t), out = path.join(call.directory, 'roundtrip.json')
  assert.equal(call(base, ['--name', 'C1', '--phase', 'after', '--evidence', out], source,
    { EVIDENCE_RECORD: exported.stdout }).status, 0)
  const checked = spawnSync(process.execPath, [path.join(root, 'scripts/audit/browser-node-evidence.mjs'), out], {
    encoding: 'utf8', timeout: 10000,
  })
  assert.equal(checked.status, 0, checked.stdout + checked.stderr)
  assert.match(checked.stdout, /OBSERVATIONS PASS checks=22/)
  console.log('SOURCE-ONLY browser evidence Python/host/offline roundtrip: PASS; synthetic signer and mocked installation only')
})

test('registered browser evidence verification removals fail their regressions', () => {
  const env = { ...process.env }
  delete env.NODE_TEST_CONTEXT
  const result = spawnSync(process.execPath, [path.join(root, 'tests/browser-node-evidence.test.mjs'), '--mutations'], {
    cwd: root, env, encoding: 'utf8', timeout: 45000, maxBuffer: 2 * 1024 * 1024,
  })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.stdout, /browser node evidence mutations: [1-9][0-9]*\/[1-9][0-9]* killed/)
  process.stdout.write(result.stdout)
})
