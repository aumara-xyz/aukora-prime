// Installed launches recheck the protected floor and cannot turn plugin-set enforcement into a waiver.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

import { releaseRootIsProtected, requirePluginSetMode }
  from '../plugins/aukora-composition-gate/src/policy.js'

const launcherPath = new URL('../scripts/launch-dsh.py', import.meta.url)
const policyPath = new URL('../plugins/aukora-composition-gate/src/policy.js', import.meta.url)
const launcherSource = readFileSync(launcherPath, 'utf8')
const policySource = readFileSync(policyPath, 'utf8')

const pythonWorker = String.raw`
import ast, json, subprocess, sys
from pathlib import Path

payload=json.load(sys.stdin)
tree=ast.parse(payload['source'],filename='launch-dsh.py')
function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='check_release_floor')
class Refused(Exception): pass
class Parser:
    def error(self,message): raise Refused(message)
class Result:
    returncode=payload['returncode']; stdout=payload.get('stdout',''); stderr=payload.get('stderr','')
calls=[]
def runner(command,**options): calls.append([command,options]); return Result()
scope={'Path':Path,'subprocess':subprocess,'parser':Parser(),
       'FLOOR_BOOTSTRAP':Path('/usr/local/lib/aukora-boundary/gate-bootstrap')}
exec(compile(ast.Module(body=[function],type_ignores=[]),'launch-dsh.py:check_release_floor','exec'),scope)
refusal=None
try: scope['check_release_floor'](Path('/opt/aukora-genesis/release-1111111'),Path('/etc/aukora-approvals/one/state'),runner)
except Refused as error: refusal=str(error)
print(json.dumps({'calls':calls,'refusal':refusal}))
`

function runFloor(source, returncode, stderr = '') {
  const result = spawnSync('/usr/bin/python3', ['-I', '-S', '-c', pythonWorker], {
    input: JSON.stringify({ source, returncode, stderr }), encoding: 'utf8', timeout: 10_000,
  })
  assert.equal(result.error, undefined)
  assert.equal(result.status, 0, result.stderr)
  return JSON.parse(result.stdout)
}

function floorRefusalOracle(source) {
  const result = runFloor(source, 2, 'release-floor-absent: no release floor')
  assert.match(result.refusal ?? '', /^release-floor-refused: release-floor-absent/u)
  assert.deepEqual(result.calls[0], [[
    '/usr/bin/python3', '-I', '-S', '/usr/local/lib/aukora-boundary/gate-bootstrap', 'floor', 'check',
    '--release-dir', '/opt/aukora-genesis/release-1111111',
    '--approval-state-root', '/etc/aukora-approvals/one/state',
  ], { capture_output: true, text: true }])
}

function floorWiringOracle(source) {
  const call = "    check_release_floor(release,a.approval_state_root)"
  assert.equal(source.split(call).length, 2)
  assert.ok(source.indexOf(call) < source.indexOf('patches=[p.resolve()'))
  assert.match(source, /if a\.launch_profile != 'disposable-preview' and \(a\.foreground or FLOOR_BOOTSTRAP\.exists\(\)\):/u)
}

function virtualProtection({ releaseUid = 0, releaseMode = 0o755 } = {}) {
  const rows = new Map([
    ['/', { uid: 0, mode: 0o755 }], ['/opt', { uid: 0, mode: 0o755 }],
    ['/opt/aukora-genesis', { uid: 0, mode: 0o755 }],
    ['/opt/aukora-genesis/release-1111111', { uid: releaseUid, mode: releaseMode }],
  ])
  return path => {
    const row = rows.get(path)
    if (row === undefined) throw Object.assign(new Error('missing'), { code: 'ENOENT' })
    return { ...row, isDirectory: () => true }
  }
}

function waiverOracle(requireMode) {
  const inspect = virtualProtection()
  assert.equal(releaseRootIsProtected('/opt/aukora-genesis/release-1111111', inspect, value => value), true)
  assert.throws(() => requireMode('waived', '/opt/aukora-genesis/release-1111111', inspect, value => value),
    error => error.code === 'plugin-set-waiver-refused')
  assert.doesNotThrow(() => requireMode('enforce', '/opt/aukora-genesis/release-1111111', inspect, value => value))
  const preview = virtualProtection({ releaseUid: 1000 })
  assert.equal(releaseRootIsProtected('/opt/aukora-genesis/release-1111111', preview, value => value), false)
  assert.doesNotThrow(() => requireMode('waived', '/opt/aukora-genesis/release-1111111', preview, value => value))
  assert.throws(() => requireMode('waived', '/missing', () => { throw new Error('unreadable') }, value => value),
    error => error.code === 'plugin-set-waiver-refused')
}

test('production launcher runs the installed floor check and names an absent-floor refusal', () => {
  floorWiringOracle(launcherSource)
  floorRefusalOracle(launcherSource)
  assert.equal(runFloor(launcherSource, 0).refusal, null)
})

test('floor refusal and launcher wiring mutations are killed', () => {
  const guard = '    if result.returncode != 0:'
  assert.equal(launcherSource.split(guard).length, 2)
  assert.throws(() => floorRefusalOracle(launcherSource.replace(guard, '    if False:')), { code: 'ERR_ASSERTION' })
  const call = "    check_release_floor(release,a.approval_state_root)"
  assert.throws(() => floorWiringOracle(launcherSource.replace(call, '    pass')), { code: 'ERR_ASSERTION' })
  console.log('SOURCE-ONLY floor mutations: 2/2 killed; refusal and production wiring are both required')
})

test('root-protected releases refuse a mutable config waiver while disposable previews retain it', () => {
  waiverOracle(requirePluginSetMode)
  assert.match(policySource, /requirePluginSetMode\(mode, mode === 'waived'[\s\S]{0,120}fileURLToPath\(import\.meta\.url\)/u)
})

test('installed-release waiver mutation is killed', async () => {
  const guard = "  if (mode === 'waived' && releaseRootIsProtected(releaseRoot, inspect, canonical)) {"
  assert.equal(policySource.split(guard).length, 2)
  const mutant = policySource.replace(guard, '  if (false) {')
    .replace(/from (['"])(\.[^'"]+)\1/gu,
      (_match, _quote, specifier) => 'from ' + JSON.stringify(new URL(specifier, policyPath).href))
  const module = await import(`data:text/javascript;base64,${Buffer.from(mutant).toString('base64')}`)
  assert.throws(() => waiverOracle(module.requirePluginSetMode), { code: 'ERR_ASSERTION' })
  console.log('SOURCE-ONLY plugin waiver mutation: 1/1 killed; protected installed release no longer accepts waived')
})

// A rehearsal node failed to boot when the default filesystem readers were not imported; call them for real.
test('mode check runs with its own filesystem readers, as the import hook calls it', () => {
  assert.equal(requirePluginSetMode('enforce', null), undefined)
  assert.throws(() => requirePluginSetMode('waived', '/'), { code: 'plugin-set-waiver-refused' })
})
