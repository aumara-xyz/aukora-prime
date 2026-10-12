// Check unit syntax and preserve the reviewed Buzz restrictions without disabling Podman helpers.
import assert from 'node:assert/strict'
import test from 'node:test'
import { readdirSync, readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { dirname, basename, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../../..')
const proposal = readFileSync(join(here, 'HARDENING.proposed.conf'), 'utf8')
const trees = ['packages/boundary-gate/host/systemd', 'host', 'ops/systemd', 'ops/buzz-relay']
const sections = {
  Unit: 'Description After Before Requires Wants BindsTo PartOf OnFailure StartLimitIntervalSec StartLimitBurst DefaultDependencies',
  Service: 'Type User Group UMask RuntimeDirectory RuntimeDirectoryMode UnsetEnvironment ExecStart ExecStartPre ExecStop ExecStopPost ExecReload Restart RestartSec NoNewPrivileges RemainAfterExit TimeoutStartSec TimeoutStopSec WorkingDirectory Environment EnvironmentFile KillMode ProtectSystem ProtectHome ReadOnlyPaths ReadWritePaths BindPaths PrivateTmp PrivateNetwork PrivateDevices ProtectKernelTunables ProtectKernelModules ProtectKernelLogs ProtectControlGroups RestrictAddressFamilies RestrictNamespaces RestrictSUIDSGID LockPersonality MemoryDenyWriteExecute SystemCallFilter SystemCallErrorNumber CapabilityBoundingSet AmbientCapabilities TasksMax MemoryHigh MemoryMax CPUQuota StandardOutput StandardError LimitNOFILE LimitCORE',
  Timer: 'OnBootSec OnActiveSec OnUnitActiveSec AccuracySec Persistent Unit',
  Install: 'WantedBy RequiredBy Also Alias',
}
const booleans = new Set('NoNewPrivileges RemainAfterExit PrivateTmp PrivateNetwork PrivateDevices ProtectKernelTunables ProtectKernelModules ProtectKernelLogs ProtectControlGroups RestrictNamespaces RestrictSUIDSGID LockPersonality MemoryDenyWriteExecute Persistent DefaultDependencies'.split(' '))
const deniedCaps = 'CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_TIME CAP_SYSLOG CAP_WAKE_ALARM'.split(' ')
const buzz = ['ops/buzz-relay/aukora-buzz.service', 'ops/buzz-relay/aukora-buzz-watch.service']

function unitsBelow(dir) {
  return readdirSync(join(root, dir), { withFileTypes: true }).flatMap((entry) => {
    const path = `${dir}/${entry.name}`
    return entry.isDirectory() ? unitsBelow(path) : /\.(service|timer|socket|target)(\.in)?$/.test(path) ? [path] : []
  })
}
const units = trees.flatMap(unitsBelow).sort()

function render(text) {
  const values = { UID: '12345', MEMORY_LIMITS: '0', NODE_PATH: '/usr/bin/node', SOURCE_ROOT: '/opt/source', EXISTING_PRIVATE_DOOR_KEY_FILE: '/var/lib/aukora-host/door.key' }
  return text.replace(/@([A-Z_]+)@/g, (_, name) => {
    assert.ok(Object.hasOwn(values, name), `UNKNOWN_TEMPLATE: ${name}`)
    return values[name]
  })
}

function parse(text, label, dropIn = false) {
  const rows = []
  let section = '', previous = ''
  for (const [index, raw] of render(text).split('\n').entries()) {
    const line = raw.trim(), where = `${label}:${index + 1}`
    if (!line || /^[#;]/.test(line)) { previous = line; continue }
    if (/^\[[A-Za-z]+\]$/.test(line)) {
      section = line.slice(1, -1)
      assert.ok(Object.hasOwn(sections, section), `UNIT_SECTION: ${where}`)
    } else {
      const match = /^([A-Za-z][A-Za-z0-9]*)=(.*)$/.exec(line)
      assert.ok(match && section, `UNIT_ASSIGNMENT: ${where}`)
      const [, key, value] = match
      assert.ok(sections[section].split(' ').includes(key), `UNIT_KEY: ${where}: ${key}`)
      if (booleans.has(key)) assert.match(value, /^(yes|no|true|false|0|1)$/, `UNIT_BOOLEAN: ${where}`)
      if (key === 'UMask') assert.match(value, /^0?[0-7]{3}$/, `UNIT_UMASK: ${where}`)
      if (key === 'ProtectSystem') assert.match(value, /^(yes|no|true|false|full|strict)$/, `UNIT_PROTECT: ${where}`)
      if (key === 'ProtectHome') assert.match(value, /^(yes|no|true|false|read-only|tmpfs)$/, `UNIT_HOME: ${where}`)
      if (key === 'RestrictAddressFamilies') assert.match(value, /^~?AF_[A-Z0-9_]+(?: AF_[A-Z0-9_]+)*$/, `UNIT_FAMILY: ${where}`)
      if (/^(ReadWritePaths|ReadOnlyPaths|BindPaths)$/.test(key)) {
        assert.ok(value.split(/\s+/).every((path) => /^-?\//.test(path) && !path.split('/').includes('..')), `UNIT_PATH: ${where}`)
      }
      if (/^Exec/.test(key)) assert.match(value, /^[+!:@-]*\/\S+/, `UNIT_EXEC: ${where}`)
      if (dropIn) assert.match(previous, /^# .+/, `DIRECTIVE_REASON: ${where}`)
      rows.push({ section, key, value })
    }
    previous = line
  }
  assert.ok(section, `UNIT_EMPTY: ${label}`)
  if (/\.timer(?:\.in)?$/.test(label)) assert.ok(rows.every((r) => r.section !== 'Service'), `TIMER_EXECUTION: ${label}`)
  return rows
}

function proposals(text) {
  const blocks = new Map()
  let path, lines = []
  for (const line of text.split('\n')) {
    if (line.startsWith('# BEGIN ')) {
      assert.equal(path, undefined, 'PROPOSAL_NESTED')
      path = line.slice(8); lines = []
      assert.ok(!blocks.has(path), `PROPOSAL_DUPLICATE: ${path}`)
    } else if (line.startsWith('# END ')) {
      assert.equal(line.slice(6), path, 'PROPOSAL_END')
      blocks.set(path, lines.join('\n')); path = undefined
    } else if (path) lines.push(line)
    else assert.ok(!line || line.startsWith('#'), 'PROPOSAL_OUTSIDE_BLOCK')
  }
  assert.equal(path, undefined, 'PROPOSAL_UNCLOSED')
  return blocks
}
const blocks = proposals(proposal)

function checkBuzz(text) {
  const rows = parse(text, 'buzz.service')
  const values = (key) => rows.filter((r) => r.key === key).map((r) => r.value)
  assert.deepEqual(values('UMask'), ['0077'], 'BUZZ_UMASK')
  const caps = values('CapabilityBoundingSet')
  assert.equal(caps.length, 1, 'BUZZ_CAPABILITIES')
  assert.ok(caps[0].startsWith('~'), 'BUZZ_HELPER_CAPABILITIES')
  const denied = caps[0].slice(1).split(/\s+/)
  for (const cap of deniedCaps) assert.ok(denied.includes(cap), `BUZZ_CAPABILITIES: ${cap}`)
  for (const cap of ['CAP_SETUID', 'CAP_SETGID', 'CAP_SETPCAP', 'CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_SYS_CHROOT', 'CAP_CHOWN']) {
    assert.ok(!denied.includes(cap), `BUZZ_HELPER_CAPABILITIES: ${cap}`)
  }
  for (const key of ['NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'PrivateTmp', 'PrivateDevices', 'ProtectKernelTunables', 'ProtectKernelModules', 'ProtectKernelLogs', 'ProtectControlGroups', 'RestrictAddressFamilies', 'RestrictNamespaces', 'LockPersonality', 'MemoryDenyWriteExecute', 'SystemCallFilter']) {
    assert.equal(values(key).length, 0, `BUZZ_NEEDS_STAGING: ${key}`)
  }
}

test('every source unit and per-unit proposal has structural syntax and directive reasons', (t) => {
  assert.deepEqual([...blocks.keys()].sort(), units, 'PROPOSAL_COVERAGE')
  for (const path of units) {
    parse(readFileSync(join(root, path), 'utf8'), path)
    parse(blocks.get(path), path, true)
  }
  t.diagnostic(`STRUCTURAL: ${units.length} units, ${blocks.size} per-unit drop-ins`)
})

test('Buzz restrictions preserve rootless Podman and watch recovery prerequisites', () => {
  for (const path of buzz) checkBuzz(readFileSync(join(root, path), 'utf8'))
})

test('removing or relaxing every applied Buzz protection is detected', (t) => {
  let killed = 0
  for (const path of buzz) {
    const source = readFileSync(join(root, path), 'utf8')
    for (const mutant of [source.replace(/^UMask=.*\n/m, ''), source.replace('UMask=0077', 'UMask=0022'), source.replace(/^CapabilityBoundingSet=.*\n/m, ''), ...deniedCaps.map((cap) => source.replace(cap, ''))]) {
      assert.throws(() => checkBuzz(mutant), /BUZZ_(UMASK|CAPABILITIES)/)
      killed++
    }
  }
  t.diagnostic(`MUTATION: ${killed}/${killed} applied-protection deletions/relaxations killed (source assertions, not kernel probes)`)
})

test('structural fallback refuses malformed hardening and timer execution directives', () => {
  for (const mutant of ['[Service]\nNoNewPrivileges=yes # inline reason', '[Service]\nProtectSystem=strcit', '[Service]\nUMask=0088', '[Timer]\nPrivateTmp=yes', '[Service]\nReadWritePaths=relative/path', '[Service]\nInventedHardening=yes', 'UMask=0077']) {
    assert.throws(() => parse(mutant, 'mutant.service'), /UNIT_/)
  }
  assert.throws(() => parse('[Service]\nUMask=0077', 'mutant.timer'), /TIMER_EXECUTION/)
})

// Verification uses inert executable/dependency fixtures; it never starts a service or contacts a manager.
function verifyUnit(tool, scratch, path, dropIn) {
  const unitRoot = mkdtempSync(join(scratch, 'root-'))
  const unitDir = join(unitRoot, 'etc/systemd/system')
  mkdirSync(unitDir, { recursive: true })
  const source = render(readFileSync(join(root, path), 'utf8'))
  const name = basename(path).replace(/\.in$/, '').replace('@.', '@hardening.')
  const write = (file, data, mode = 0o644) => {
    mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, data, { mode })
  }
  // Supply only missing deployment dependencies and executable paths, never replace tested directive values.
  const rows = parse(source, path)
  const dependencies = rows.filter((r) => ['After', 'Before', 'Requires', 'Wants', 'BindsTo', 'PartOf', 'OnFailure', 'Unit'].includes(r.key)).flatMap((r) => r.value.split(/\s+/))
  dependencies.push('sysinit.target', 'basic.target', 'shutdown.target', 'sockets.target', 'timers.target', name.replace(/\.timer$/, '.service'))
  for (const dependency of new Set(dependencies)) {
    if (dependency === name) continue
    assert.match(dependency, /^[a-zA-Z0-9@_.-]+\.(service|target|timer)$/)
    const content = dependency.endsWith('.service') ? '[Service]\nType=oneshot\nExecStart=/bin/true\n' : dependency.endsWith('.timer') ? '[Timer]\nOnBootSec=1h\n' : ''
    write(join(unitDir, dependency), `[Unit]\nDescription=Inert syntax fixture\n${content}`)
  }
  for (const executable of ['/bin/true', ...rows.filter((r) => /^Exec/.test(r.key)).map((r) => r.value.match(/^[+!:@-]*(\/\S+)/)[1])]) {
    write(join(unitRoot, executable), '#!/bin/sh\nexit 0\n', 0o755)
  }
  write(join(unitDir, name), source)
  const invoke = () => {
    const result = spawnSync(tool, ['verify', `--root=${unitRoot}`, '--man=no', name], { encoding: 'utf8', timeout: 30000, env: { ...process.env, SYSTEMD_LOG_COLOR: '0', SYSTEMD_LOG_LEVEL: 'warning' } })
    assert.ifError(result.error)
    assert.equal(result.status, 0, `SYSTEMD_VERIFY: ${path}\n${result.stdout}${result.stderr}`)
    assert.doesNotMatch(result.stderr, /Unknown (?:key|lvalue|section)|Failed to parse|Invalid (?:argument|section|syntax)|Assignment outside|Missing '='/i, `SYSTEMD_DIAGNOSTIC: ${path}`)
  }
  invoke()
  write(join(unitDir, `${name}.d/50-hardening.conf`), render(dropIn))
  invoke()
}

test('systemd-analyze verifies each base unit and its proposed drop-in when available', (t) => {
  const probe = spawnSync('systemd-analyze', ['--version'], { encoding: 'utf8' })
  if (probe.error?.code === 'ENOENT') {
    t.skip('systemd-analyze unavailable; structural check ran; Linux parsing and runtime remain UNPERFORMED')
    return
  }
  assert.ifError(probe.error)
  assert.equal(probe.status, 0, probe.stderr)
  const scratch = mkdtempSync(join(here, '.verify-'))
  t.after(() => rmSync(scratch, { recursive: true, force: true }))
  for (const path of units) verifyUnit('systemd-analyze', scratch, path, blocks.get(path))
  t.diagnostic(`SYSTEMD_VERIFY: ${units.length} bases + ${units.length} drop-ins; inert dependencies/executables, no runtime enforcement tested`)
})
