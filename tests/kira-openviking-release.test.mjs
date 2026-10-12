// Execute the materializer's argument and row expressions without cutting a release.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const materializer = new URL('../scripts/materialize-aukora-release.py', import.meta.url)
const source = readFileSync(materializer, 'utf8')
const door = readFileSync(new URL('../ops/systemd/aukora-viking-door.service.in', import.meta.url), 'utf8')
const server = readFileSync(new URL('../ops/systemd/aukora-openviking.service.in', import.meta.url), 'utf8')
const home = '/var/lib/aukora-host/openviking'
const projectFile = '/var/lib/aukora-host/kira-projects.json'
const render = (args = [], input = source) => spawnSync('python3', ['-B', '-c', `
import ast, json, sys
from pathlib import Path
from types import SimpleNamespace
source = sys.stdin.read()
path = sys.argv[1]
ns = dict(__file__=path, __name__='materializer_test')
exec(compile(source, path, 'exec'), ns)
main = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
arguments = []
for node in main.body:
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'assert_harness_clean':
        break
    arguments.append(node)
sys.argv = [path, '--to', '/synthetic/release', *sys.argv[2:]]
exec(compile(ast.Module(body=arguments, type_ignores=[]), path, 'exec'), ns)
ns.update(target=Path('/synthetic/release'), default_patch=SimpleNamespace(read_text=lambda **kw: ''), release_root='/synthetic/release')
rows = {}
for node in ast.walk(main):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != 'write_text':
        continue
    target = node.func.value
    name = 'aukora-composition.patch.yml' if isinstance(target, ast.Name) and target.id == 'default_patch' else None
    if isinstance(target, ast.BinOp) and isinstance(target.left, ast.Name) and target.left.id == 'target' and isinstance(target.right, ast.Constant):
        name = target.right.value
    if name in ('aukora-composition.patch.yml', 'aukora-lanes.patch.yml', 'aukora-deployment-overlay.patch.yml'):
        rows[name] = eval(compile(ast.Expression(node.args[0]), path, 'eval'), ns)
print(json.dumps(rows))
`, materializer.pathname, ...args], { input, encoding: 'utf8' })

const validateProject = (selected, input = source) => spawnSync('python3', ['-B', '-c', `
import sys
source = sys.stdin.read()
path = sys.argv[1]
ns = dict(__file__=path, __name__='materializer_test')
exec(compile(source, path, 'exec'), ns)
def inspected(source):
    raise SystemExit('harness-inspected')
ns['assert_harness_clean'] = inspected
sys.argv = [path, '--to', '/synthetic/release', '--kira-project-map', sys.argv[2]]
ns['main']()
`, materializer.pathname, selected], { input, encoding: 'utf8' })

function assertRows(input = source) {
  for (const selected of [undefined, home, '/synthetic/open"viking quoted']) {
    const result = render(selected === undefined ? [] : ['--kira-openviking-home', selected], input)
    assert.equal(result.status, 0, result.stderr)
    const rows = JSON.parse(result.stdout)
    assert.equal(Object.keys(rows).length, 3)
    for (const [name, patch] of Object.entries(rows)) {
      const kira = patch.split('- id: aukora-kira\n')[1]?.split(/\n\s*- id:/u)[0]
      assert.ok(kira, `${name}: missing Kira row`)
      assert.match(kira, /retrieval: lexical\n/u)
      assert.match(kira, /memoryOwner:\n[\s\S]*stateDir:[\s\S]*subject:[\s\S]*permittedPrivacy: \[local\]/u)
      if (selected === undefined) assert.equal(kira.includes('openVikingHome:'), false)
      else {
        const value = /^\s*openVikingHome: (.+)$/mu.exec(kira)?.[1]
        assert.ok(value, `${name}: missing OpenViking home`)
        assert.equal(JSON.parse(value), selected, `${name}: OpenViking home changed`)
      }
    }
  }
}

function assertRelativeRefusal(input = source) {
  const result = render(['--kira-openviking-home', 'relative/openviking'], input)
  assert.equal(result.status, 1)
  assert.match(result.stderr, /materialize-release-failed: kira-openviking-home-not-absolute/u)
}

function assertControlRefusal(input = source) {
  for (const selected of ['/synthetic/line\nbreak', '/synthetic/control\u007f']) {
    const result = render(['--kira-openviking-home', selected], input)
    assert.equal(result.status, 1)
    assert.match(result.stderr, /materialize-release-failed: kira-openviking-home-invalid/u)
  }
}

function assertDoor(unit = door) {
  assert.ok(server.includes(`serve ${home}\n`))
  assert.ok(unit.includes(`Environment=AUKORA_OPENVIKING_HOME=${home}\n`))
}

function assertProjectRows(input = source) {
  for (const selected of [undefined, projectFile, '/synthetic/project" mapping.json']) {
    const args = ['--kira-openviking-home', home, ...(selected === undefined ? [] : ['--kira-project-map', selected])]
    const result = render(args, input)
    assert.equal(result.status, 0, result.stderr)
    const rows = JSON.parse(result.stdout)
    assert.equal(Object.keys(rows).length, 3)
    for (const [name, patch] of Object.entries(rows)) {
      const kira = patch.split('- id: aukora-kira\n')[1]?.split(/\n\s*- id:/u)[0]
      assert.ok(kira, `${name}: missing Kira row`)
      assert.equal(JSON.parse(/^\s*openVikingHome: (.+)$/mu.exec(kira)?.[1]), home)
      if (selected === undefined) assert.equal(kira.includes('projectIdentityFile:'), false)
      else {
        const value = /^\s*projectIdentityFile: (.+)$/mu.exec(kira)?.[1]
        assert.ok(value, `${name}: missing project mapping file`)
        assert.equal(JSON.parse(value), selected, `${name}: project mapping path changed`)
      }
    }
  }
}

function assertProjectRelativeRefusal(input = source) {
  const result = validateProject('relative/kira-projects.json', input)
  assert.equal(result.status, 1)
  assert.match(result.stderr, /materialize-release-failed: kira-project-map-not-absolute/u)
  assert.doesNotMatch(result.stderr, /harness-inspected/u)
}

function assertProjectControlRefusal(input = source) {
  for (const selected of ['/synthetic/line\nbreak.json', '/synthetic/control\u007f.json']) {
    const result = validateProject(selected, input)
    assert.equal(result.status, 1)
    assert.match(result.stderr, /materialize-release-failed: kira-project-map-invalid/u)
    assert.doesNotMatch(result.stderr, /harness-inspected/u)
  }
}

function assertProjectNormalizedRefusal(input = source) {
  for (const selected of ['/synthetic/../kira-projects.json', '//synthetic/kira-projects.json']) {
    const result = validateProject(selected, input)
    assert.equal(result.status, 1)
    assert.match(result.stderr, /materialize-release-failed: kira-project-map-not-normalized/u)
    assert.doesNotMatch(result.stderr, /harness-inspected/u)
  }
}

test('OpenViking opt-in reaches all release rows, preserves lexical default and quotes the path', () => assertRows())
test('relative OpenViking homes refuse before harness inspection or any release copy', () => assertRelativeRefusal())
test('control-bearing OpenViking homes refuse before harness inspection or any release copy', () => assertControlRefusal())
test('the installed memory door uses the OpenViking service home', () => assertDoor())
test('project mapping opt-in reaches all release rows as a quoted path and stays absent by default', () => assertProjectRows())
test('relative project mapping paths refuse before harness inspection', () => assertProjectRelativeRefusal())
test('control-bearing project mapping paths refuse before harness inspection', () => assertProjectControlRefusal())
test('unnormalized project mapping paths refuse before harness inspection', () => assertProjectNormalizedRefusal())

test('configuration protection mutants fail their checks', () => {
  const changes = [
    ['absolute-home', 'if not home.is_absolute():', 'if False:', assertRelativeRefusal],
    ['control-home', 'if any(ord(char) < 32 or ord(char) == 127 for char in str(home)):', 'if False:', assertControlRefusal],
    ['default-unconfigured', "if home is None:\n        return ''", "if home is None:\n        home = Path('/synthetic/implicit')", assertRows],
    ['quote-home', 'json.dumps(str(home))', 'str(home)', assertRows],
    ['absolute-project-file', 'if not file.is_absolute():', 'if False:', assertProjectRelativeRefusal],
    ['control-project-file', 'if any(ord(char) < 32 or ord(char) == 127 for char in str(file)):', 'if False:', assertProjectControlRefusal],
    ['normalized-project-file', "if str(file) != os.path.normpath(str(file)) or str(file).startswith('//'):", 'if False:', assertProjectNormalizedRefusal],
    ['default-project-unconfigured', "if file is None:\n        return ''", "if file is None:\n        file = Path('/synthetic/implicit.json')", assertProjectRows],
    ['quote-project-file', 'json.dumps(str(file))', 'str(file)', assertProjectRows],
    ['project-validation-before-harness', '    kira_project_mapping_config(args.kira_project_map, 8)\n', '', assertProjectRelativeRefusal],
  ]
  for (const [name, from, to, check] of changes) {
    assert.equal(source.split(from).length - 1, 1, `${name}: mutation target`)
    assert.throws(() => check(source.replace(from, to)), undefined, `${name}: survived`)
  }
  const row = '+ kira_openviking_config(args.kira_openviking_home, '
  const positions = [...source.matchAll(/\+ kira_openviking_config\(args\.kira_openviking_home, [48]\)/gu)]
  assert.equal(positions.length, 3)
  for (const [index, match] of positions.entries()) {
    assert.ok(match[0].startsWith(row))
    const mutant = source.slice(0, match.index) + "+ ''" + source.slice(match.index + match[0].length)
    assert.throws(() => assertRows(mutant), undefined, `row-${index}: survived`)
  }
  const projectPositions = [...source.matchAll(/\+ kira_project_mapping_config\(args\.kira_project_map, [48]\)/gu)]
  assert.equal(projectPositions.length, 3)
  for (const [index, match] of projectPositions.entries()) {
    const mutant = source.slice(0, match.index) + "+ ''" + source.slice(match.index + match[0].length)
    assert.throws(() => assertProjectRows(mutant), undefined, `project-row-${index}: survived`)
  }
  assert.throws(() => assertDoor(door.replace(`Environment=AUKORA_OPENVIKING_HOME=${home}\n`, '')), undefined, 'door-home: survived')
  process.stdout.write('kira-release: 17/17 configuration mutants killed\n')
})
