// The release mounts and permits the retained HTTP relay only with an explicit option.
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { generated, source, root, builder, rows } from './helpers/release-composition.mjs'
import { mountedPluginRows } from '../plugins/aukora-composition-gate/src/plugin-set.mjs'
import { createPolicy, DEFAULT_ALLOW_TOOLS } from '../plugins/aukora-action-gate/lib/policy.mjs'
import { readSettings } from '../plugins/aukora-action-gate/lib/index.mjs'

const relay = 'aukora-relay-auma'
const tools = ['relay_read', 'relay_post']

function copied(input = source, withLegacyRelay = false) {
  const parent = join(root, '.runtime')
  mkdirSync(parent, { recursive: true })
  const target = mkdtempSync(join(parent, 'legacy-relay-release-'))
  try {
    return JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import ast, json, sys
from pathlib import Path
source = sys.stdin.read()
path, destination, selected = sys.argv[1:]
ns = dict(__file__=path, __name__='legacy_relay_fixture')
exec(compile(source, path, 'exec'), ns)
main = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
arguments = []
for node in main.body:
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'assert_harness_clean': break
    arguments.append(node)
sys.argv = [path, '--to', destination] + (['--with-legacy-relay'] if selected == 'true' else [])
exec(compile(ast.Module(body=arguments, type_ignores=[]), path, 'exec'), ns)
target = Path(destination)
gate_out = target / 'plugins/aukora-composition-gate'
gate_out.mkdir(parents=True)
ns.update(target=target, gate_out=gate_out, LANE_PLUGINS=('aukora-relay-auma',))
for node in main.body:
    carry = isinstance(node, ast.For) and isinstance(node.iter, ast.Name) and node.iter.id == 'LANE_PLUGINS'
    gate_copy = isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple) and any(isinstance(n, ast.Constant) and n.value == 'policy.json' for n in node.iter.elts)
    relay_choice = isinstance(node, ast.If) and ast.unparse(node.test) in ('args.with_legacy_relay', 'not args.with_legacy_relay')
    overlay_copy = isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'copy2' and any(isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.endswith('.patch.yml') for n in ast.walk(node))
    if carry or gate_copy or relay_choice or overlay_copy:
        exec(compile(ast.Module(body=[node], type_ignores=[]), path, 'exec'), ns)
print(json.dumps(dict(policy=json.loads((gate_out / 'policy.json').read_text()),
                     patches={p.name: p.read_text() for p in target.glob('*.patch.yml')},
                     overlay=(target / 'action-gate.patch.yml').read_text(),
                     carried=(target / 'plugins/aukora-relay-auma/lib/index.mjs').is_file())))
`, builder, target, String(withLegacyRelay)], { cwd: root, input, encoding: 'utf8', timeout: 5000 }))
  } finally { rmSync(target, { recursive: true, force: true }) }
}

function check(input = source, withLegacyRelay = false, fallback = createPolicy) {
  const fixture = generated(input, { includeUpstream: false, withLegacyRelay })
  const release = copied(input, withLegacyRelay)
  const composition = rows(fixture.patches['aukora-composition.patch.yml'], 'default')
  const gate = composition.find(row => row.id === 'aukora-action-gate')
  const overlay = rows(release.overlay, 'overlay').find(row => row.id === 'aukora-action-gate')
  const settings = readSettings({ home: '/synthetic/home', supportRoot: '/synthetic/support',
    dshHome: '/synthetic/state/home', auraDir: '/synthetic/aura', repoRoots: [], releaseRoots: [],
    extraWritableRoots: [], networkAllow: [], allowLoopback: false })
  assert.equal(release.carried, true, 'existing HTTP clients retain the source')
  assert.ok(composition.some(row => row.id === 'aukora-buzz-door'))
  for (const tool of tools) {
    assert.equal(gate.config.allowTools.includes(tool), withLegacyRelay, `default ${tool}`)
    assert.equal(overlay.config.allowTools.includes(tool), withLegacyRelay, `copied overlay ${tool}`)
    const result = createPolicy({ ...settings, allowTools: gate.config.allowTools }).judge({ tool, args: {} })
    assert.equal(result.decision, withLegacyRelay ? 'allow' : 'deny', tool)
    assert.equal(fallback(settings).judge({ tool, args: {} }).rule, 'authority:tool-not-approved', `fallback ${tool}`)
  }
  const mounted = composition.find(row => row.id === relay)
  assert.equal(Boolean(mounted), withLegacyRelay, 'legacy mount selection')
  if (mounted) assert.deepEqual({ name: mounted.name, config: mounted.config }, {
    name: './plugins/aukora-relay-auma/lib/index.mjs', config: {
      keyFile: '/synthetic/home/.config/aukora-relay/auma.key', gateSocket: '/run/aukora-gate/gate.sock',
      workspaceRoots: ['/synthetic/home/workspaces'],
    },
  })
  const patches = { ...fixture.patches, ...release.patches }
  const mountedIds = [...new Set(Object.entries(patches).filter(([name]) => name !== 'demo-governed.patch.yml')
    .flatMap(([, patch]) => mountedPluginRows(patch.replaceAll('/synthetic/release/', './')).map(row => row.id)))].sort()
  assert.deepEqual(release.policy.pluginSet, mountedIds, 'the copied policy matches every emitted mounting patch')
  if (withLegacyRelay) assert.deepEqual(release.policy, JSON.parse(readFileSync(join(root, 'plugins/aukora-composition-gate/policy.json'), 'utf8')))
}

test('default release omits the legacy mount and tools; explicit option restores the previous configuration', () => {
  for (const tool of tools) assert.ok(!DEFAULT_ALLOW_TOOLS.includes(tool))
  check()
  check(source, true)
})

test('removing a release selection or default refusal fails its control', async t => {
  for (const [name, before, after, selected] of [
    ['mount-default', "if not with_legacy_relay:\n        return ''", "if False:\n        return ''", false],
    ['tool-default', 'if with_legacy_relay:\n        anchor', 'if True:\n        anchor', false],
    ['policy-default', "if not with_legacy_relay:\n        policy['pluginSet']", "if False:\n        policy['pluginSet']", false],
    ['opt-in-mount', 'legacy_relay_rows(args.with_legacy_relay)', 'legacy_relay_rows(False)', true],
  ]) {
    assert.equal(source.split(before).length, 2, `${name}: exact mutation target`)
    assert.throws(() => check(source.replace(before, after), selected), { code: 'ERR_ASSERTION' }, name)
    t.diagnostic(`MUTATION CAUGHT ${name}`)
  }
  const policyURL = pathToFileURL(join(root, 'plugins/aukora-action-gate/lib/policy.mjs'))
  const original = readFileSync(policyURL, 'utf8')
  const marker = 'export const DEFAULT_ALLOW_TOOLS = Object.freeze([\n'
  assert.equal(original.split(marker).length, 2)
  const mutant = original.replace(marker, `${marker}  'relay_read', 'relay_post',\n`)
    .replace(/from (['"])(\.[^'"]+)\1/gu,
      (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, policyURL).href)}`)
  const fallback = await import(`data:text/javascript;base64,${Buffer.from(mutant).toString('base64')}`)
  assert.throws(() => check(source, false, fallback.createPolicy), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION CAUGHT fallback-tool-default')
})

test('legacy tool insertion refuses a missing reviewed anchor; removing the guard fails its control', t => {
  const read = "text = (ROOT / 'overlays' / 'action-gate.patch.yml').read_text(encoding='utf-8')"
  assert.equal(source.split(read).length, 2)
  const malformed = source.replace(read, "text = 'missing-anchor\\n'")
  const run = input => execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import sys
path = sys.argv[1]
ns = dict(__file__=path, __name__='legacy_anchor_fixture')
exec(compile(sys.stdin.read(), path, 'exec'), ns)
ns['action_gate_overlay'](True)
`, builder], { cwd: root, input, encoding: 'utf8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] })
  const control = input => assert.throws(() => run(input), /legacy-relay:action-gate-anchor/u)
  control(malformed)
  const guard = 'if text.count(anchor) != 1:'
  assert.equal(malformed.split(guard).length, 2)
  assert.throws(() => control(malformed.replace(guard, 'if False:')), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION CAUGHT legacy-tool-anchor')
})
