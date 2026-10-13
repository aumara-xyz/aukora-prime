// Verify container transport readback before privileged acceptance dispatch.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
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
  const dir = fs.mkdtempSync(path.join(root, '.runtime/browser-accept-'))
  const config = path.join(dir, 'config.json'), log = path.join(dir, 'calls')
  fs.writeFileSync(path.join(dir, 'lxc'), '#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\n'
    + 'case "$*" in *" query "*) if [[ ${REFUSE_CONFIG:-0} == 1 ]]; then exit 1; fi; cat "$CONFIG" ;; *" exec "*) printf "PASS synthetic container acceptance\\n" ;; *) exit 66 ;; esac\n', { mode: 0o700 })
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return (value = base, args = ['--name', 'C1', '--phase', 'after'], modified = source, extra = {}) => {
    fs.writeFileSync(config, typeof value === 'string' ? value : JSON.stringify({ expanded_config: value.config, expanded_devices: value.devices }))
    fs.writeFileSync(log, '')
    const file = path.join(dir, 'acceptance.sh')
    fs.writeFileSync(file, modified)
    const result = spawnSync('bash', [file, ...args], { cwd: root, encoding: 'utf8', timeout: 10000,
      env: { PATH: dir + ':' + process.env.PATH, CONFIG: config, CALLS: log, ...extra } })
    return { ...result, calls: fs.readFileSync(log, 'utf8') }
  }
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
