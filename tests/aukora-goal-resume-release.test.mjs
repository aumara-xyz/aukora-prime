// Generated and optional goal-resume rows supply the marker home used at mount.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { runInNewContext } from 'node:vm'
import { apply, markerFor } from '../plugins/aukora-goal-resume/lib/index.mjs'

const materializer = new URL('../scripts/materialize-aukora-release.py', import.meta.url)
const source = readFileSync(materializer, 'utf8')
const overlay = readFileSync(new URL('../overlays/goal-resume.patch.yml', import.meta.url), 'utf8')
const render = (input = source) => {
  const result = spawnSync('python3', ['-B', '-c', `
import ast, sys
from pathlib import Path
from types import SimpleNamespace
source = sys.stdin.read(); path = sys.argv[1]
ns = dict(__file__=path, __name__='materializer_test')
exec(compile(source, path, 'exec'), ns)
main = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
ns.update(target=Path('/synthetic/release'), args=SimpleNamespace(kira_openviking_home=None, kira_project_map=None), hmr_row=ns['hmr_disable_row'](False))
for variable in ('patch', 'default_patch'):
    call = next(n for n in ast.walk(main) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name) and n.func.value.id == variable and n.func.attr == 'write_text')
    patch = eval(compile(ast.Expression(call.args[0]), path, 'eval'), ns)
    ns['default_patch'] = SimpleNamespace(read_text=lambda **kw: patch)
print(patch)
`, materializer.pathname], { input, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  return result.stdout
}

function configFor(patch, home) {
  assert.equal(patch.split('- id: aukora-goal-resume\n').length, 2)
  const row = patch.split('- id: aukora-goal-resume\n')[1].split(/\n\s*- (?:id|insert):/u)[0]
  assert.match(row, /name: \.\/plugins\/aukora-goal-resume\/lib\/index\.mjs\n/u)
  const expression = /^ {6}config:\n {8}stateDir: !!js (.+)$/mu.exec(row)?.[1]
  assert.ok(expression, 'goal-resume row must supply config.stateDir')
  const stateDir = runInNewContext(expression, { dshHomePath: (...parts) => join(home, ...parts) })
  assert.equal(stateDir, join(home, 'goal-resume-state'))
  return { stateDir }
}

test('default composition and optional overlay derive goal state from the deployment home', () => {
  for (const home of ['/var/lib/aukora-host/home', '/Users/synthetic/Library/Application Support/AUKORA/state/home']) {
    configFor(render(), home)
    configFor(overlay, home)
  }
})

test('mounted generated config re-arms eligible goals and consumes only clean-stop markers', async t => {
  const parent = new URL('../.runtime/', import.meta.url)
  mkdirSync(parent, { recursive: true })
  const home = mkdtempSync(join(parent.pathname, 'goal-wiring-'))
  t.after(() => rmSync(home, { recursive: true, force: true }))
  const config = configFor(render(), home)
  const agents = ['active', 'paused', 'complete', 'disarmed', 'armed'].map(sessionId => ({ sessionId }))
  const views = new Map(agents.map(agent => [agent, { id: `goal-${agent.sessionId}`, revision: 7,
    phase: agent.sessionId === 'paused' || agent.sessionId === 'complete' ? agent.sessionId : 'active',
    activation: agent.sessionId === 'disarmed' ? 'disarmed' : 'armed', alreadyArmed: agent.sessionId === 'armed' }]))
  const resumed = [], warnings = [], disposers = [], logs = []
  const ctx = {
    agents: { roots: () => agents, get: id => agents.find(agent => agent.sessionId === id) },
    goals: { get: agent => views.get(agent), resume: (agent, ref) => resumed.push([agent.sessionId, ref]) },
    logger: { warn: line => warnings.push(line) }, log: { info: line => logs.push(line) },
    effect: create => disposers.push(create()),
  }
  const mount = async () => { apply(ctx, config); await new Promise(resolve => setImmediate(resolve)) }
  await mount()
  assert.deepEqual(warnings, [])
  assert.deepEqual(resumed, [['active', { id: 'goal-active', revision: 7 }]])
  assert.ok(logs.some(line => line.includes('unclean start')))
  assert.equal(existsSync(markerFor(config.stateDir)), false, 'boot must not mark a subsequent crash clean')
  disposers.pop()()
  assert.equal(existsSync(markerFor(config.stateDir)), true, 'clean disposal writes a usable state directory')
  resumed.length = 0
  await mount()
  assert.deepEqual(resumed, [], 'clean stop must not re-arm')
  assert.equal(existsSync(markerFor(config.stateDir)), false, 'clean marker is consumed')
  await mount()
  assert.deepEqual(resumed, [['active', { id: 'goal-active', revision: 7 }]], 'unclean restart re-arms again')
})

test('removing either config or stateDir wiring fails the same configuration check', () => {
  const from = "        '      config:\\n'\n        \"        stateDir: !!js dshHomePath('goal-resume-state')\\n\"\n"
  assert.equal(source.split(from).length, 2, 'unique builder mutation target')
  assert.throws(() => configFor(render(source.replace(from, '')), '/synthetic/home'), { code: 'ERR_ASSERTION' })
  assert.throws(() => configFor(render(source.replace(from, from.replace("        '      config:\\n'\n", ''))), '/synthetic/home'), { code: 'ERR_ASSERTION' })
  const line = "        stateDir: !!js dshHomePath('goal-resume-state')\n"
  assert.equal(overlay.split(line).length, 2, 'unique overlay mutation target')
  assert.throws(() => configFor(overlay.replace(line, ''), '/synthetic/home'), { code: 'ERR_ASSERTION' })
  assert.throws(() => configFor(overlay.replace('      config:\n', ''), '/synthetic/home'), { code: 'ERR_ASSERTION' })
})
