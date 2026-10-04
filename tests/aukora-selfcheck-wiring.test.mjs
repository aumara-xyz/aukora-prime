// SPDX-License-Identifier: AGPL-3.0-or-later
// SOURCE_ONLY: parses unit source and models the documented dependency/timer rules.
// It never invokes systemd, the bootstrap, Node selfcheck, a gate, or a runtime.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const UNIT_ROOT = new URL('../packages/boundary-gate/host/systemd/', import.meta.url)
const LATCH = 'aukora-selfcheck.service'
const PERIODIC = 'aukora-selfcheck-periodic.service'
const GENESIS = 'aukora-genesis.service'
const TIMER = 'aukora-selfcheck.timer'
const FAIL_CLOSED = 'aukora-genesis-failclosed.service'
const BOOTSTRAP = '/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package'
const RUNTIME_BOOTSTRAP = '/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-runtime'
const SELF_CHECK = '/opt/aukora-node/bin/node /opt/aukora-boundary-gate/bin/selfcheck.mjs --run /run/aukora-gate --gate-home /home/aukora-gate --target-root /var/lib/aukora-boundary/targets --release-parent /opt/aukora-genesis --forbid-write /opt/aukora-boundary-gate/bin/gate.mjs --forbid-write /usr/local/lib/aukora-boundary/sbx-exec'
const GENESIS_SELF_CHECK = SELF_CHECK + ' --forbid-write /opt/aukora-boundary-gate/bin/plugin-set-approval.mjs --forbid-write /opt/aukora-boundary-gate/bin/release-floor.mjs --forbid-write /opt/aukora-boundary-gate/src/plugin-set-canon.mjs --forbid-write /opt/aukora-boundary-gate/src/release-floor.mjs --forbid-write /opt/aukora-boundary-gate/src/vendor/operator-data.mjs --forbid-write /opt/aukora-boundary-gate/src/vendor/plugin-set-content.mjs --forbid-write /opt/aukora-boundary-gate/src/vendor/trusted-verifier-pins.json --forbid-write /opt/aukora-boundary-gate/src/vendor/signer-epochs.mjs --forbid-write /etc/aukora-boundary-gate/signer-epochs.json --forbid-write /etc/aukora-boundary-gate/gate-package-manifest.json --forbid-write /usr/local/lib/aukora-boundary/gate-bootstrap'
const GENESIS_FLOOR = '/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap floor check --release-dir ${AUKORA_RELEASE_DIR} --approval-state-root ${AUKORA_APPROVAL_ROOT}'
const GENESIS_LAUNCH = '/usr/bin/python3 scripts/launch-dsh.py --release ${AUKORA_RELEASE_DIR} --state-root /home/aukora-host/genesis/state --port 18735 --foreground --node /opt/aukora-node/bin/node --approval-state-root ${AUKORA_APPROVAL_ROOT} --approved-record-sha ${AUKORA_RECORD_SHA} --patch ${AUKORA_RELEASE_DIR}/aukora-composition.patch.yml --patch ${AUKORA_RELEASE_DIR}/linux-openshell.patch.yml'
const LOADERS = ['NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONHOME', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT']

function parseUnit(text) {
  const values = new Map()
  let section
  for (const original of text.split('\n')) {
    const line = original.trim()
    if (!line || line.startsWith('#') || line.startsWith(';')) continue
    if (/^\[[A-Za-z]+\]$/.test(line)) { section = line.slice(1, -1); continue }
    const match = /^([A-Za-z][A-Za-z0-9]*)=(.*)$/.exec(line)
    assert.ok(section && match, 'fixture unit parser refuses unsupported syntax: ' + line)
    const key = section + '.' + match[1]
    const prior = values.get(key) ?? []
    prior.push(match[2]); values.set(key, prior)
  }
  return {
    all: (section, key) => [...(values.get(section + '.' + key) ?? [])],
    one: (section, key) => {
      const found = values.get(section + '.' + key) ?? []
      assert.ok(found.length <= 1, 'source must not ambiguously repeat ' + section + '.' + key)
      return found[0]
    },
    words: (section, key) => (values.get(section + '.' + key) ?? []).flatMap(value => value.split(/\s+/).filter(Boolean)),
  }
}

function sources() {
  return Object.fromEntries([LATCH, PERIODIC, GENESIS, TIMER, FAIL_CLOSED]
    .map(name => [name, readFileSync(new URL(name, UNIT_ROOT), 'utf8')]))
}

function units(source) {
  return Object.fromEntries(Object.entries(source).map(([name, text]) => [name, parseUnit(text)]))
}

function assertWiring(source) {
  const u = units(source)
  assert.deepEqual(u[GENESIS].all('Unit', 'BindsTo'), [LATCH], 'Genesis must bind to the startup check without reset assignments')
  assert.deepEqual(u[GENESIS].all('Unit', 'After'), ['network-online.target aukora-boundary-gate.service aukora-auma-sandbox.service ' + LATCH],
    'Genesis must wait for its original providers and startup check without reset assignments')
  assert.equal(u[LATCH].one('Service', 'RemainAfterExit'), 'yes', 'startup check must remain active')
  assert.equal(u[PERIODIC].one('Service', 'RemainAfterExit'), undefined, 'periodic check must return to inactive')
  assert.equal(u[TIMER].one('Timer', 'Unit'), PERIODIC, 'timer must not point to the active startup check')
  assert.deepEqual(u[GENESIS].all('Service', 'ExecStartPre'), [BOOTSTRAP, RUNTIME_BOOTSTRAP, GENESIS_SELF_CHECK, GENESIS_FLOOR])
  assert.deepEqual(u[GENESIS].all('Service', 'UnsetEnvironment'), [LOADERS.join(' ')])
  for (const name of [LATCH, PERIODIC]) {
    assert.equal(u[name].one('Service', 'Type'), 'oneshot')
    assert.deepEqual(u[name].all('Unit', 'After'), ['aukora-boundary-gate.service aukora-auma-sandbox.service'])
    assert.deepEqual(u[name].all('Unit', 'OnFailure'), [FAIL_CLOSED])
    assert.deepEqual(u[name].all('Service', 'ExecStartPre'), [RUNTIME_BOOTSTRAP])
    assert.equal(u[name].one('Service', 'ExecStart'), SELF_CHECK)
    assert.deepEqual(u[name].all('Service', 'UnsetEnvironment'), [LOADERS.join(' ')])
    assert.equal(u[name].one('Service', 'User'), 'aukora-host')
    assert.equal(u[name].one('Service', 'Group'), 'aukora-host')
    assert.equal(u[name].one('Service', 'UMask'), '0077')
    assert.equal(u[name].one('Service', 'TimeoutStartSec'), '300')
    assert.equal(u[name].one('Service', 'WorkingDirectory'), '/tmp')
    assert.equal(u[name].one('Service', 'Environment'), 'PATH=/usr/bin:/bin')
  }
  assert.equal(u[TIMER].one('Timer', 'OnBootSec'), '5min')
  assert.equal(u[TIMER].one('Timer', 'OnUnitActiveSec'), '15min')
  assert.equal(u[FAIL_CLOSED].one('Service', 'ExecStart'), '/usr/bin/systemctl stop aukora-genesis.service')
}

// This limited model tests source graph mechanisms, not systemd implementation or installed bytes.
// Documented rules: BindsTo pulls its unit into startup; After orders those jobs; BindsTo+After
// requires the bound unit to remain active. Timers do not restart an already active service.
// Primary sources: https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml (BindsTo),
// https://github.com/systemd/systemd/blob/main/man/systemd.service.xml (RemainAfterExit),
// https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml (active target service).
function model(source) {
  const u = units(source)
  const state = { active: new Set(), launches: 0, checks: 0, nodeChecks: 0, genesisNodeChecks: 0, failures: 0, stops: 0 }
  const bound = u[GENESIS].words('Unit', 'BindsTo').includes(LATCH)
  const pulled = bound || ['Wants', 'Requires'].some(key => u[GENESIS].words('Unit', key).includes(LATCH))
  const ordered = u[GENESIS].words('Unit', 'After').includes(LATCH)
  function stopGenesis() {
    if (state.active.delete(GENESIS)) state.stops++
  }
  function deactivateLatch() {
    state.active.delete(LATCH)
    if (bound) stopGenesis()
  }
  // check-package permits legacy custody v1; check-runtime requires the complete v2 runtime profile.
  // Profile-content/custody verification remains the bootstrap's separate tests, not this unit model.
  function bootstrapAllows(commands, bootstrapPass, manifestVersion) {
    const guarded = commands.includes(BOOTSTRAP) || commands.includes(RUNTIME_BOOTSTRAP)
    return !guarded || (bootstrapPass && (!commands.includes(RUNTIME_BOOTSTRAP) || manifestVersion === 2))
  }
  function check(name, { pass = true, bootstrapPass = true, manifestVersion = 2 } = {}) {
    if (state.active.has(name)) return
    state.checks++
    const allowed = bootstrapAllows(u[name].all('Service', 'ExecStartPre'), bootstrapPass, manifestVersion)
    if (allowed) state.nodeChecks++
    if (!allowed || !pass) {
      state.failures++
      state.active.delete(name)
      if (u[name].words('Unit', 'OnFailure').includes(FAIL_CLOSED)) stopGenesis()
      if (name === LATCH && bound) stopGenesis()
      return
    }
    if (u[name].one('Service', 'RemainAfterExit') === 'yes') state.active.add(name)
  }
  function launchGenesis(prechecksPass, { bootstrapPass = true, manifestVersion = 2 } = {}) {
    const prechecks = u[GENESIS].all('Service', 'ExecStartPre')
    const firstNode = prechecks.findIndex(command => command.startsWith('/opt/aukora-node/bin/node '))
    const beforeNode = firstNode === -1 ? prechecks : prechecks.slice(0, firstNode)
    if (!bootstrapAllows(beforeNode, bootstrapPass, manifestVersion)) return
    state.genesisNodeChecks++
    if (prechecksPass) { state.active.add(GENESIS); state.launches++ }
  }
  return {
    state,
    start({ pass = true, bootstrapPass = true, manifestVersion = 2,
      genesisPrechecksPass = true, genesisManifestVersion = manifestVersion } = {}) {
      if (pulled && ordered) {
        check(LATCH, { pass, bootstrapPass, manifestVersion })
        if (!bound || state.active.has(LATCH)) launchGenesis(genesisPrechecksPass, { bootstrapPass, manifestVersion: genesisManifestVersion })
      } else {
        // Without ordering a permitted schedule can launch Genesis before a bound check fails.
        launchGenesis(genesisPrechecksPass, { bootstrapPass, manifestVersion: genesisManifestVersion })
        if (pulled) check(LATCH, { pass, bootstrapPass, manifestVersion })
      }
    },
    tick(options) { check(u[TIMER].one('Timer', 'Unit'), options) },
    deactivateLatch,
  }
}

test('SOURCE_ONLY unit graph preserves check command, roles, fail-closed action and timer cadence', () => {
  assertWiring(sources())
})

test('SOURCE_ONLY Genesis retains every existing precheck, launch argument and restart bound', () => {
  const u = units(sources())[GENESIS]
  assert.deepEqual(u.all('Service', 'ExecStartPre'), [BOOTSTRAP, RUNTIME_BOOTSTRAP, GENESIS_SELF_CHECK, GENESIS_FLOOR])
  assert.deepEqual(u.all('Service', 'ExecStartPre').filter(command => command !== RUNTIME_BOOTSTRAP),
    [BOOTSTRAP, GENESIS_SELF_CHECK, GENESIS_FLOOR], 'all three original prechecks stay verbatim and ordered')
  assert.equal(u.one('Service', 'ExecStart'), GENESIS_LAUNCH)
  assert.deepEqual(u.words('Unit', 'Wants'), ['aukora-boundary-gate.service', 'aukora-auma-sandbox.service'])
  assert.deepEqual(u.words('Unit', 'After'), ['network-online.target', 'aukora-boundary-gate.service', 'aukora-auma-sandbox.service', LATCH])
  assert.equal(u.one('Unit', 'StartLimitIntervalSec'), '300')
  assert.equal(u.one('Unit', 'StartLimitBurst'), '3')
  assert.equal(u.one('Service', 'Restart'), 'on-failure')
  assert.equal(u.one('Service', 'RestartSec'), '5')
  assert.equal(u.one('Service', 'KillMode'), 'control-group')
  assert.equal(u.one('Service', 'TimeoutStartSec'), '120')
  assert.equal(u.one('Service', 'EnvironmentFile'), '/etc/aukora-genesis/release.env')
  assert.deepEqual(u.all('Service', 'UnsetEnvironment'), [LOADERS.join(' ')])
})

test('SOURCE_ONLY startup ordering graph waits for both existing providers without a cycle', () => {
  const u = units(sources())
  const graph = new Map([GENESIS, LATCH, PERIODIC].map(name => [name, u[name].words('Unit', 'After')]))
  const visiting = new Set(), visited = new Set()
  function visit(name) {
    assert.equal(visiting.has(name), false, 'ordering graph must not cycle at ' + name)
    if (visited.has(name)) return
    visiting.add(name)
    for (const dependency of graph.get(name) ?? []) visit(dependency)
    visiting.delete(name); visited.add(name)
  }
  visit(GENESIS); visit(PERIODIC)
  for (const provider of u[GENESIS].words('Unit', 'Wants')) {
    assert.ok(u[LATCH].words('Unit', 'After').includes(provider), 'startup check must wait for ' + provider)
  }
})

test('SOURCE_ONLY modeled success keeps startup check active and stops Genesis on its loss', () => {
  const m = model(sources()); m.start()
  assert.equal(m.state.launches, 1)
  assert.equal(m.state.active.has(LATCH), true)
  m.deactivateLatch()
  assert.equal(m.state.active.has(GENESIS), false)
  assert.equal(m.state.stops, 1)
})

test('SOURCE_ONLY modeled startup failure prevents any runtime launch', () => {
  const m = model(sources()); m.start({ pass: false })
  assert.equal(m.state.launches, 0)
  assert.equal(m.state.active.has(GENESIS), false)
})

test('SOURCE_ONLY modeled bootstrap refusal prevents Node and runtime launch', () => {
  const m = model(sources()); m.start({ bootstrapPass: false })
  assert.equal(m.state.nodeChecks, 0)
  assert.equal(m.state.launches, 0)
})

test('SOURCE_ONLY modeled legacy v1 custody cannot launch selfcheck or Genesis Node', () => {
  const latch = model(sources()); latch.start({ manifestVersion: 1 })
  assert.equal(latch.state.nodeChecks, 0)
  assert.equal(latch.state.genesisNodeChecks, 0)
  assert.equal(latch.state.launches, 0)
  const genesis = model(sources()); genesis.start({ genesisManifestVersion: 1 })
  assert.equal(genesis.state.nodeChecks, 1, 'valid startup check can already have passed')
  assert.equal(genesis.state.genesisNodeChecks, 0)
  assert.equal(genesis.state.launches, 0)
  const periodic = model(sources()); periodic.start(); periodic.tick({ manifestVersion: 1 })
  assert.equal(periodic.state.nodeChecks, 1, 'periodic v1 attempt must not start another Node')
  assert.equal(periodic.state.active.has(GENESIS), false)
})

test('SOURCE_ONLY modeled periodic checks keep running without deactivating the startup latch', () => {
  const m = model(sources()); m.start(); m.tick(); m.tick(); m.tick()
  assert.equal(m.state.checks, 4)
  assert.equal(m.state.active.has(LATCH), true)
  assert.equal(m.state.active.has(PERIODIC), false)
  assert.equal(m.state.active.has(GENESIS), true)
  assert.equal(m.state.launches, 1)
})

test('SOURCE_ONLY modeled periodic command and bootstrap failures stop Genesis without restarting it', () => {
  for (const options of [{ pass: false }, { bootstrapPass: false }]) {
    const m = model(sources()); m.start(); m.tick(options)
    assert.equal(m.state.active.has(GENESIS), false)
    assert.equal(m.state.stops, 1)
    assert.equal(m.state.launches, 1)
    assert.equal(m.state.active.has(LATCH), true)
  }
})

test('SOURCE_ONLY targeted guards reject mutants; lifecycle/profile mutants also expose modeled failures', async t => {
  const original = sources()
  const cases = [
    ['remove BindsTo', GENESIS, 'BindsTo=' + LATCH + '\n', '', changed => {
      const m = model(changed); m.start(); m.deactivateLatch()
      assert.equal(m.state.active.has(GENESIS), true, 'bound-unit loss must now leave an unsafe running runtime')
    }],
    ['remove After ordering', GENESIS, ' aukora-selfcheck.service\nWants=', '\nWants=', changed => {
      const m = model(changed); m.start({ pass: false })
      assert.equal(m.state.launches, 1, 'failed check must now permit a runtime launch before failure')
    }],
    ['remove startup RemainAfterExit', LATCH, 'RemainAfterExit=yes\n', '', changed => {
      const m = model(changed); m.start()
      assert.equal(m.state.launches, 0, 'a successful inactive check must now break bound startup')
    }],
    ['remove periodic OnFailure', PERIODIC, 'OnFailure=' + FAIL_CLOSED + '\n', '', changed => {
      const m = model(changed); m.start(); m.tick({ pass: false })
      assert.equal(m.state.active.has(GENESIS), true, 'periodic failure must now leave runtime running')
    }],
    ['point timer at active startup latch', TIMER, 'Unit=' + PERIODIC, 'Unit=' + LATCH, changed => {
      const m = model(changed); m.start(); m.tick(); m.tick()
      assert.equal(m.state.checks, 1, 'timer must now silently skip subsequent selfchecks')
    }],
    ['remove periodic runtime bootstrap', PERIODIC, 'ExecStartPre=' + RUNTIME_BOOTSTRAP + '\n', '', changed => {
      const m = model(changed); m.start(); m.tick({ bootstrapPass: false })
      assert.equal(m.state.nodeChecks, 2, 'Node must now execute despite rejected bootstrap bytes')
    }],
    ['remove periodic preload scrub', PERIODIC, 'UnsetEnvironment=' + LOADERS.join(' ') + '\n', '', () => {}],
    ['remove startup sandbox ordering', LATCH, 'After=aukora-boundary-gate.service aukora-auma-sandbox.service', 'After=aukora-boundary-gate.service', () => {}],
    ['reset periodic preload scrub', PERIODIC, 'UnsetEnvironment=' + LOADERS.join(' ') + '\n', 'UnsetEnvironment=' + LOADERS.join(' ') + '\nUnsetEnvironment=\n', () => {}],
    ['reset Genesis preload scrub', GENESIS, 'UnsetEnvironment=' + LOADERS.join(' ') + '\n', 'UnsetEnvironment=' + LOADERS.join(' ') + '\nUnsetEnvironment=\n', () => {}],
    ['replace periodic runtime guard with legacy custody guard', PERIODIC, 'ExecStartPre=' + RUNTIME_BOOTSTRAP, 'ExecStartPre=' + BOOTSTRAP, changed => {
      const m = model(changed); m.start(); m.tick({ manifestVersion: 1 })
      assert.equal(m.state.nodeChecks, 2, 'legacy custody must now incorrectly admit another Node check')
      assert.equal(m.state.active.has(GENESIS), true)
    }],
    ['remove Genesis runtime guard', GENESIS, 'ExecStartPre=' + RUNTIME_BOOTSTRAP + '\n', '', changed => {
      const m = model(changed); m.start({ genesisManifestVersion: 1 })
      assert.equal(m.state.genesisNodeChecks, 1, 'legacy custody must now admit Genesis Node precheck')
      assert.equal(m.state.launches, 1, 'legacy custody must now admit the Genesis launcher')
    }],
  ]
  for (const [name, file, before, after, witness] of cases) {
    await t.test(name, () => {
      assert.equal(original[file].split(before).length - 1, 1, 'named mutation must match exactly one current guard')
      const changed = { ...original, [file]: original[file].replace(before, after) }
      assert.throws(() => assertWiring(changed), undefined, 'required source guard must reject the mutant')
      witness(changed)
    })
  }
})
