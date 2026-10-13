// Browser profiles remove network mounts and refuse effect providers in every shipped preset.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { generated, rows, root, builder, source } from './helpers/release-composition.mjs'

const run = (body, input = source, args = [], env = {}) => spawnSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import ast, hashlib, json, os, sys, tarfile
from pathlib import Path
from types import SimpleNamespace
source = sys.stdin.read()
ns = dict(__file__=sys.argv[1], __name__='browser_profile_test')
exec(compile(source, sys.argv[1], 'exec'), ns)
${body}
`, builder, ...args], { cwd: root, input, encoding: 'utf8', timeout: 10000,
  env: { PATH: process.env.PATH, HOME: '/synthetic/home', ...env } })

function success(result) { assert.equal(result.status, 0, result.stderr); return result.stdout }
function mutated(before, after) {
  assert.equal(source.split(before).length, 2, `mutation anchor: ${before}`)
  return source.replace(before, after)
}

const inspect = String.raw`
main = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
loop = next(n for n in main.body if isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == 'LANE_PLUGINS')
target = Path(sys.argv[2])
ns.update(target=target, LANE_PLUGINS=('aukora-relay-auma', 'aukora-buzz-door'), args=SimpleNamespace(browser_node=True))
exec(compile(ast.Module(body=[loop], type_ignores=[]), sys.argv[1], 'exec'), ns)
assert not (target/'plugins/aukora-relay-auma').exists(), 'browser copied legacy relay'
assert not (target/'plugins/aukora-buzz-door').exists(), 'browser copied Buzz'
policy = ns['composition_gate_policy'](browser_node=True)
assert 'aukora-relay-auma' not in policy['pluginSet'], 'browser policy includes relay'
assert 'aukora-buzz-door' not in policy['pluginSet'], 'browser policy includes Buzz'
assert 'aukora-browser-refusal' in policy['pluginSet'], 'browser refusal missing from approval policy'
`
function scratch(t) {
  const path = mkdtempSync(join(root, '.browser-profile-test-'))
  t.after(() => rmSync(path, { recursive: true, force: true }))
  return path
}

test('browser profile omits both network plugins from copied bytes, mounted rows, permissions and policy', t => {
  const dir = scratch(t)
  success(run(inspect, source, [dir]))
  const patch = generated(undefined, { browserNode: true, includeUpstream: false }).patches['aukora-composition.patch.yml']
  assert.equal(rows(patch, 'browser').some(row => ['aukora-relay-auma', 'aukora-buzz-door'].includes(row.id)), false)
  for (const tool of ['buzz_read', 'buzz_post', 'buzz_post_receipt', 'relay_read', 'relay_post']) {
    assert.equal(patch.includes(`          - ${tool}\n`), false)
  }
  assert.equal(patch.includes('worktreesRoot:'), false)
  const omission = mutated("if args.browser_node and plugin in ('aukora-relay-auma', 'aukora-buzz-door'):", 'if False:')
  assert.notEqual(run(inspect, omission, [dir]).status, 0, 'network copy mutation survived')
  const policy = mutated("policy['pluginSet'] = [name for name in policy['pluginSet'] if name != 'aukora-buzz-door']", 'pass')
  assert.notEqual(run(inspect, policy, [scratch(t)]).status, 0, 'Buzz policy mutation survived')
  const mount = generated(mutated("def buzz_door_rows(browser_node: bool = False) -> str:\n    \"\"\"The browser-only profile has no Buzz door.\"\"\"\n    if browser_node:", "def buzz_door_rows(browser_node: bool = False) -> str:\n    \"\"\"The browser-only profile has no Buzz door.\"\"\"\n    if False:"), { browserNode: true, includeUpstream: false })
  assert.ok(rows(mount.patches['aukora-composition.patch.yml'], 'mutant').some(row => row.id === 'aukora-buzz-door'))
  const policyGuard = mutated("policy['pluginSet'] = sorted(policy['pluginSet'] + ['aukora-browser-refusal'])", 'pass')
  assert.notEqual(run(inspect, policyGuard, [scratch(t)]).status, 0, 'refusal policy mutation survived')
  for (const [guard, assertion] of [
    ["text = re.sub(r'^          - (?:buzz_read|buzz_post|buzz_post_receipt)\\n', '', text, flags=re.M)", text => assert.equal(text.includes('          - buzz_post\n'), false)],
    ["text = re.sub(r'^        worktreesRoot:.*\\n', '', text, flags=re.M)", text => assert.equal(text.includes('worktreesRoot:'), false)],
  ]) {
    const output = generated(mutated(guard, 'pass'), { browserNode: true, includeUpstream: false }).patches['aukora-composition.patch.yml']
    assert.throws(() => assertion(output), { code: 'ERR_ASSERTION' })
  }
  t.diagnostic('MUTATION browser network profile: 6/6 killed (copy, policy, mount, refusal policy, Buzz tools, self-change)')
})

test('browser options refuse conflicting profiles before harness or filesystem inspection', t => {
  const check = (extra, env = {}, input = source) => run(`
def inspected(*args): raise AssertionError('harness reached before refusal')
ns['assert_harness_clean'] = inspected
sys.argv = [sys.argv[1], '--to', '/synthetic/release', '--browser-node', *sys.argv[2:]]
ns['main']()
`, input, extra, env)
  for (const [extra, env, refusal, guard] of [
    [['--with-legacy-relay'], {}, 'browser-node:legacy-relay', 'if browser_node and with_legacy_relay:'],
    [['--development'], {}, 'browser-node:development', 'if browser_node and development:'],
    [[], { AUKORA_COMPOSITION_OVERLAY: '/synthetic/restore-effects.yml' }, 'browser-node:composition-overlay', "if browser_node and os.environ.get('AUKORA_COMPOSITION_OVERLAY', '').strip():"],
  ]) {
    const result = check(extra, env)
    assert.equal(result.status, 1); assert.ok(result.stderr.includes(refusal), result.stderr)
    const mutant = check(extra, env, mutated(guard, 'if False:'))
    assert.ok(mutant.stderr.includes('harness reached before refusal'), 'option mutation not detected')
  }
  t.diagnostic('MUTATION browser argument refusals: 3/3 killed')
})

const presets = String.raw`
target = Path(sys.argv[2])
archive = ns['ROOT']/'vendor/dsh-source.tar.gz'
pin = json.loads((ns['ROOT']/'upstream-dsh.json').read_text())
assert hashlib.sha256(archive.read_bytes()).hexdigest() == pin['archiveSha256']
with tarfile.open(archive, 'r:gz') as tar:
    for item in tar.getmembers():
        path = item.name.partition('/')[2]
        if item.isfile() and path.startswith('packages/preset/agent-presets/presets/') and path.endswith('agent.cordis.yml'):
            file = target/path; file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(tar.extractfile(item).read())
core = target/'presets/core/agent.cordis.yml'; core.parent.mkdir(parents=True)
core.write_bytes((ns['ROOT']/'presets/core/agent.cordis.yml').read_bytes())
ns['install_browser_profile'](target)
prefix = '# aukora-browser-node-profile '
text = (target/'browser-node-profile.patch.yml').read_text()
assert text.startswith(prefix)
profile = json.loads(text[len(prefix):])
assert profile['kind'] == 'aukora-browser-node-profile' and profile['formatVersion'] == 1
assert profile['relay'] is False and profile['buzz'] is False
assert profile['refusalEntry'] == ns['BROWSER_REFUSAL_ENTRY']
assert profile['refusalSha256'] == hashlib.sha256((target/profile['refusalEntry']).read_bytes()).hexdigest()
assert len(profile['presets']) == 5, 'all four pinned presets and core must be restricted'
for name, digest in profile['presets'].items():
    text = (target/name).read_text()
    assert hashlib.sha256(text.encode()).hexdigest() == digest
    import re
    for match in re.finditer(r'^( *)- id: ([\w-]+)[ \t]*$', text, re.M):
        if match[2] in ns['BROWSER_DISABLED_ROWS']:
            indent = len(match[1]); block = text[match.end():]
            stop = re.search(r'^ {0,'+str(indent)+r'}- id:', block, re.M)
            if stop: block = block[:stop.start()]
            assert re.search(r'^'+' '*(indent+2)+r'disabled: true$', block, re.M), name+': '+match[2]
print('PASS browser preset fixture: 5 pinned/source presets disabled; covered marker hashes match')
`
test('browser restrictions reach nested and preset-local providers from the pinned archive', t => {
  const dir = scratch(t)
  assert.match(success(run(presets, source, [dir])), /PASS browser preset fixture: 5/u)
  const patch = generated(undefined, { browserNode: true, includeUpstream: false }).patches['aukora-composition.patch.yml']
  const disabled = JSON.parse(success(run("print(json.dumps(ns['BROWSER_DISABLED_ROWS']))")))
  const emitted = rows(patch, 'browser')
  for (const id of disabled) assert.equal(emitted.findLast(row => row.id === id)?.disabled, true, id)
  const presetMutation = mutated("if not match or match[2] not in BROWSER_DISABLED_ROWS:", 'if True:')
  assert.notEqual(run(presets, presetMutation, [scratch(t)]).status, 0, 'preset removal mutation survived')
  const hostMutation = mutated("''.join(f'- id: {name}\\n  disabled: true\\n' for name in BROWSER_DISABLED_ROWS)", "''")
  const mutantRows = rows(generated(hostMutation, { browserNode: true, includeUpstream: false }).patches['aukora-composition.patch.yml'], 'mutant')
  assert.notEqual(mutantRows.findLast(row => row.id === 'tool-fs')?.disabled, true, 'host removal mutation survived')
  t.diagnostic('MUTATION browser provider disabling: 2/2 killed (host, presets)')
})

test('browser refusal is a global monotonic denial including tools registered after startup', async t => {
  const code = JSON.parse(success(run("print(json.dumps(ns['BROWSER_REFUSAL_SOURCE']))")))
  const mount = async source => import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
  const verify = plugin => {
    assert.deepEqual(plugin.inject, ['tools'])
    let globalGuard, unregister = 0
    const ctx = { effect(create) { create() }, tools: { guard(check) { globalGuard = check; return () => { unregister++ } } } }
    plugin.apply(ctx)
    assert.equal(typeof globalGuard, 'function', 'global guard not mounted')
    for (const name of ['bash', 'read', 'write', 'edit', 'subagent', 'run_code', 'ask_model', 'new_dynamic_effect']) {
      assert.equal(globalGuard({ name, agent: { forgedApproval: true }, args: {} }), 'browser-node:effect-providers-disabled')
    }
    assert.equal(unregister, 0, 'startup removed its own refusal')
  }
  const plugin = await mount(code)
  verify(plugin)
  const registration = "  ctx.effect(() => ctx.tools.guard(() => 'browser-node:effect-providers-disabled'))"
  assert.equal(code.split(registration).length, 2)
  const missingRegistration = await mount(code.replace(registration, ''))
  assert.throws(() => verify(missingRegistration), { code: 'ERR_ASSERTION' })
  assert.equal(code.split("() => 'browser-node:effect-providers-disabled'").length, 2)
  const missingDenial = await mount(code.replace("() => 'browser-node:effect-providers-disabled'", '() => undefined'))
  assert.throws(() => verify(missingDenial), { code: 'ERR_ASSERTION' })
  const patch = generated(undefined, { browserNode: true, includeUpstream: false }).patches['aukora-composition.patch.yml']
  assert.equal(rows(patch, 'browser').find(row => row.id === 'aukora-browser-refusal')?.name,
    './plugins/aukora-action-gate/lib/browser-refusal.mjs')
  const entry = "+ f'      name: ./{BROWSER_REFUSAL_ENTRY}\\n'"
  const missingMount = mutated(entry, "+ ''")
  assert.throws(() => rows(generated(missingMount, { browserNode: true, includeUpstream: false }).patches['aukora-composition.patch.yml'], 'mutant'), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION browser tool refusal: 3/3 killed (registration, denial, mount); synthetic registry, no runtime containment proof')
})


test('browser profile refuses missing, symlinked and ambiguous preset inputs', t => {
  for (const [body, refusal, before, after] of [
    ["ns['install_browser_profile'](Path(sys.argv[2]))", 'browser-node:presets-missing', 'if not presets:', 'if False:'],
    ["target=Path(sys.argv[2]); (target/'agent.cordis.yml').symlink_to(ns['ROOT']/'presets/core/agent.cordis.yml'); ns['install_browser_profile'](target)", 'browser-node:preset-symlink', 'if preset.is_symlink():', 'if False:'],
    ["ns['restrict_browser_preset']('- id: tool-bash\\n  disabled: false\\n  disabled: false\\n')", 'browser-node:preset-disabled-duplicate', 'if len(disabled) > 1:', 'if False:'],
  ]) {
    const result = run(body, source, [scratch(t)])
    assert.equal(result.status, 1); assert.ok(result.stderr.includes(refusal), result.stderr)
    // Symlink mutation would write another directory: intercept writes after the guard to keep this source-only.
    const mutationBody = refusal === 'browser-node:preset-symlink' ? body.replace("ns['install_browser_profile'](target)", "original_write=Path.write_text; Path.write_text=lambda file, *args, **kwargs: None if file.is_symlink() else original_write(file, *args, **kwargs); ns['install_browser_profile'](target)") : body
    const mutation = run(mutationBody, mutated(before, after), [scratch(t)])
    assert.equal(mutation.status, 0, mutation.stderr)
  }
  t.diagnostic('MUTATION browser preset input refusals: 3/3 killed')
})
