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
patch = target / 'aukora-composition.patch.yml'; patch.write_text('')
write = next(n for n in ast.walk(main) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == 'default_patch' and n.func.attr == 'write_text')
patch.write_text(eval(compile(ast.Expression(write.args[0]), m.__file__, 'eval'), dict(vars(m), target=target, default_patch=patch)))
print(json.dumps({'lanes': m.LANE_PLUGINS, 'gaps': m.release_import_gaps(target)}))
`, dir], { cwd: root, encoding: 'utf8' }))
  for (const id of ['aukora-buzz-door', 'aukora-nostr']) assert.ok(result.lanes.includes(id))
  assert.deepEqual(result.gaps, [])
  assert.ok(existsSync(join(dir, 'plugins/aukora-nostr/lib/vendor/noble-curves/curves/secp256k1.js')))
  const patch = readFileSync(join(dir, 'aukora-composition.patch.yml'), 'utf8')
  const rows = mountedPluginRows(patch)
  const row = rows.find(r => r.id === 'aukora-buzz-door')
  assert.equal(row.entry, 'plugins/aukora-buzz-door/lib/index.mjs')
  assert.ok(patch.includes('      name: ./plugins/aukora-buzz-door/lib/index.mjs\n'))
  assert.match(patch, /id: aukora-relay-auma[\s\S]*id: aukora-buzz-door[\s\S]*id: aukora-kira/u)
  const buzz = patch.split('    - id: aukora-buzz-door\n')[1].split('    - id:')[0]
  assert.match(buzz, /keyFile: !!js process.env.HOME \+ '\/\.config\/aukora-buzz\/auma.key'/u)
  assert.match(buzz, /gateSocket: \/run\/aukora-gate\/gate.sock/u)
  assert.match(buzz, /workspaceRoots:\n          - !!js process.env.HOME \+ '\/workspaces'/u)
  for (const [key, env] of [['channel', 'CHANNEL'], ['ownerPubkey', 'OWNER_PUBKEY'], ['sessionId', 'SESSION']]) {
    assert.ok(buzz.includes(`${key}: !!js process.env.AUKORA_BUZZ_${env}`))
  }
  const policy = JSON.parse(readFileSync(new URL('plugins/aukora-composition-gate/policy.json', root)))
  assert.ok(policy.pluginSet.includes(row.id))
  assert.ok(!policy.pluginSet.includes('aukora-nostr'))
  assert.deepEqual(policy.pluginSet, [...policy.pluginSet].sort())
  const record = recordPluginSet({ root: dir, rows: [row] })
  assert.equal(record.count, 1)
  assert.ok(record.artifacts[row.id].files['plugins/aukora-nostr/lib/event.mjs'])
  assert.ok(record.artifacts[row.id].files['plugins/aukora-nostr/lib/vendor/noble-curves/curves/secp256k1.js'])
  const tools = readFileSync(new URL('overlays/action-gate.patch.yml', root), 'utf8')
  for (const name of ['relay_read', 'relay_post', 'buzz_read', 'buzz_post']) assert.ok(tools.includes(`          - ${name}\n`))
})
