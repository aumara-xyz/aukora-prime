// Packaging fixture only: executes the materializer's copy loop and composition expression, not a full release cut.
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { recordPluginSet, mountedPluginRows } from '../plugins/aukora-composition-gate/src/plugin-set.mjs'

const root = new URL('../', import.meta.url)
test('Buzz release carries the sibling closure, mounts the configured door and records its dependency bytes', t => {
  const dir = mkdtempSync(join(tmpdir(), 'buzz-release-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const result = JSON.parse(execFileSync('python3', ['-B', '-c', `
import ast, importlib.util, json
from types import SimpleNamespace
from pathlib import Path
spec = importlib.util.spec_from_file_location('materializer', 'scripts/materialize-aukora-release.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
target = Path(__import__('sys').argv[1])
tree = ast.parse(Path(m.__file__).read_text())
main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
loop = next(n for n in main.body if isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == 'LANE_PLUGINS')
# Execute the actual carry implementation for these two plugins; no clean-tree guard is bypassed for a release cut.
ns = dict(vars(m), target=target, LANE_PLUGINS=('aukora-buzz-door', 'aukora-nostr'))
exec(compile(ast.Module(body=[loop], type_ignores=[]), m.__file__, 'exec'), ns)
imports = next(n for n in main.body if isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == 'RELEASE_IMPORT_FILES')
ns['RELEASE_IMPORT_FILES'] = tuple(name for name in m.RELEASE_IMPORT_FILES if name.startswith('packages/boundary-gate/'))
exec(compile(ast.Module(body=[imports], type_ignores=[]), m.__file__, 'exec'), ns)
patch = target / 'aukora-composition.patch.yml'; patch.write_text('')
write = next(n for n in ast.walk(main) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == 'default_patch' and n.func.attr == 'write_text')
patch.write_text(eval(compile(ast.Expression(write.args[0]), m.__file__, 'eval'), dict(vars(m), target=target, default_patch=patch, args=SimpleNamespace(kira_openviking_home=None))))
print(json.dumps({'lanes': m.LANE_PLUGINS, 'gaps': m.release_import_gaps(target)}))
`, dir], { cwd: root, encoding: 'utf8' }))
  for (const id of ['aukora-buzz-door', 'aukora-nostr']) assert.ok(result.lanes.includes(id))
  assert.deepEqual(result.gaps, [])
  const checkoutChecker = 'plugins/aukora-buzz-door/bin/verify-channel-receipt.mjs'
  assert.ok(existsSync(new URL(checkoutChecker, root)), 'the stranger checker is available in the checkout')
  assert.equal(existsSync(join(dir, checkoutChecker)), false, 'the checkout-only stranger checker is deliberately not shipped')
  assert.ok(existsSync(join(dir, 'plugins/aukora-nostr/lib/vendor/noble-curves/curves/secp256k1.js')))
  const patch = readFileSync(join(dir, 'aukora-composition.patch.yml'), 'utf8')
  const rows = mountedPluginRows(patch)
  const row = rows.find(r => r.id === 'aukora-buzz-door')
  assert.equal(row.entry, 'plugins/aukora-buzz-door/lib/index.mjs')
  assert.ok(patch.includes('      name: ./plugins/aukora-buzz-door/lib/index.mjs\n'))
  assert.match(patch, /id: aukora-relay-auma[\s\S]*id: aukora-buzz-door[\s\S]*id: aukora-kira/u)
  const buzz = patch.split('    - id: aukora-buzz-door\n')[1].split('    - id:')[0]
  for (const env of [
    { HOME: '/home/harness' },
    { HOME: '/home/harness', AUKORA_BUZZ_CHANNEL: 'attacker-channel', AUKORA_BUZZ_OWNER_PUBKEY: 'f'.repeat(64), AUKORA_BUZZ_SESSION: 'attacker-session' },
  ]) {
    const config = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', `
import assert from 'node:assert/strict'
import { runInNewContext } from 'node:vm'
const config = {}
const scalar = value => value.startsWith('!!js ') ? runInNewContext(value.slice(5), { process: { env: process.env } }) : value
let key
for (const line of process.argv[1].split('      config:\\n')[1].trimEnd().split('\\n')) {
  const field = /^        ([A-Za-z]+):(?: (.*))?$/.exec(line)
  if (field) { key = field[1]; config[key] = field[2] === undefined ? [] : scalar(field[2]); continue }
  const item = /^          - (.+)$/.exec(line)
  assert.ok(item && Array.isArray(config[key]), 'unsupported composition row')
  config[key].push(scalar(item[1]))
}
console.log(JSON.stringify(config))
`, buzz], { env, encoding: 'utf8' }))
    assert.deepEqual(config, {
      keyFile: '/home/harness/.config/aukora-buzz/auma.key',
      gateSocket: '/run/aukora-gate/gate.sock',
      workspaceRoots: ['/home/harness/workspaces'],
      configFile: '/home/harness/.config/aukora-buzz/door.json',
    })
  }
  const policy = JSON.parse(readFileSync(new URL('plugins/aukora-composition-gate/policy.json', root)))
  assert.ok(policy.pluginSet.includes(row.id))
  assert.ok(!policy.pluginSet.includes('aukora-nostr'))
  assert.deepEqual(policy.pluginSet, [...policy.pluginSet].sort())
  const record = recordPluginSet({ root: dir, rows: [row] })
  assert.equal(record.count, 1)
  assert.equal(Object.hasOwn(record.artifacts[row.id].files, checkoutChecker), false, 'the checkout-only checker is outside the runtime plugin set')
  assert.ok(record.artifacts[row.id].files['plugins/aukora-nostr/lib/event.mjs'])
  assert.ok(record.artifacts[row.id].files['plugins/aukora-nostr/lib/vendor/noble-curves/curves/secp256k1.js'])
  for (const name of ['ledger.mjs', 'receipts.mjs']) assert.ok(record.artifacts[row.id].files[`packages/boundary-gate/src/${name}`])
  const tools = readFileSync(new URL('overlays/action-gate.patch.yml', root), 'utf8')
  for (const name of ['relay_read', 'relay_post', 'buzz_read', 'buzz_post', 'buzz_post_receipt']) assert.ok(tools.includes(`          - ${name}\n`))
})
