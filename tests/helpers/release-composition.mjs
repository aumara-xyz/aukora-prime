// Read emitted release composition without materializing a release.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'

export const root = fileURLToPath(new URL('../../', import.meta.url))
export const builder = join(root, 'scripts/materialize-aukora-release.py')
export const source = readFileSync(builder, 'utf8')
export const release = '/synthetic/release'

export function generated(input = source, { home = '/synthetic/home', includeUpstream = true, withLegacyRelay = false, browserNode = false } = {}) {
  return JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import ast, hashlib, json, re, sys, tarfile
from pathlib import Path
from types import SimpleNamespace
source = sys.stdin.read()
path = sys.argv[1]
ns = dict(__file__=path, __name__='mount_fixture')
exec(compile(source, path, 'exec'), ns)
main = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
patches = {}
class Patch:
    def __init__(self, name): self.name = name
    def read_text(self, **kwargs): return patches.get(self.name, '')
ns.update(target=Path('/synthetic/release'), args=SimpleNamespace(development=False, kira_openviking_home=None, kira_project_map=None,
          with_legacy_relay=sys.argv[3] == 'true', browser_node=sys.argv[4] == 'true'),
          patch=Patch('aukora-composition.patch.yml'), default_patch=Patch('aukora-composition.patch.yml'),
          hmr_row=ns['hmr_disable_row'](False))
for node in main.body:
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call): continue
    call = node.value
    if not isinstance(call.func, ast.Attribute) or call.func.attr != 'write_text': continue
    target = call.func.value
    name = 'aukora-composition.patch.yml' if isinstance(target, ast.Name) and target.id in ('patch', 'default_patch') else None
    if isinstance(target, ast.BinOp) and isinstance(target.left, ast.Name) and target.left.id == 'target' and isinstance(target.right, ast.Constant):
        name = target.right.value
    if name and name.endswith('.patch.yml'):
        patches[name] = eval(compile(ast.Expression(call.args[0]), path, 'eval'), ns)
archive = ns['ROOT'] / 'vendor/dsh-source.tar.gz'
if sys.argv[2] == 'false' or not archive.is_file():
    # A checkout without the pinned harness archive (CI, a node) still checks every row that names this
    # repository's own files; rows naming harness packages are reported as not inspected.
    print(json.dumps(dict(patches=patches, upstream=None)))
    raise SystemExit(0)
pin = json.loads((ns['ROOT'] / 'upstream-dsh.json').read_text())
if hashlib.sha256(archive.read_bytes()).hexdigest() != pin['archiveSha256']:
    raise SystemExit('overlay-mount:harness-archive-pin')
with tarfile.open(archive, 'r:gz') as tar:
    package_roots = set()
    for patch in patches.values():
        for match in re.finditer(r'^\\s*name: (?:\\./|/synthetic/release/)(packages/[^\\n]+?)/lib/index.js$', patch, re.M):
            package_roots.add(match.group(1) + '/src/')
    upstream = {}
    for entry in tar.getmembers():
        path = entry.name.partition('/')[2]
        if entry.isfile() and any(path.startswith(prefix) for prefix in package_roots) and path.endswith('.ts'):
            upstream[path] = tar.extractfile(entry).read().decode('utf-8')
print(json.dumps(dict(patches=patches, upstream=upstream)))
`, builder, String(includeUpstream), String(withLegacyRelay), String(browserNode)], { cwd: root, input, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: home }, timeout: 10000 }))
}

function withoutComment(text) {
  let quote
  for (let i = 0; i < text.length; i++) {
    const char = text[i]
    if (quote) { if (char === quote && text[i - 1] !== '\\') quote = undefined; continue }
    if (char === '"' || char === "'") quote = char
    if (char === '#' && (i === 0 || /\s/u.test(text[i - 1]))) return text.slice(0, i).trim()
  }
  return text.trim()
}

function splitFlow(text) {
  const parts = []
  let quote, depth = 0, start = 0
  for (let i = 0; i < text.length; i++) {
    const char = text[i]
    if (quote) { if (char === quote && text[i - 1] !== '\\') quote = undefined; continue }
    if (char === '"' || char === "'") quote = char
    else if (char === '[' || char === '{') depth++
    else if (char === ']' || char === '}') depth--
    else if (char === ',' && depth === 0) { parts.push(text.slice(start, i).trim()); start = i + 1 }
  }
  parts.push(text.slice(start).trim())
  return parts.filter(Boolean)
}

function configParser({ home = '/synthetic/home', dshHome = home, cwd = root } = {}) {
  const context = vm.createContext(Object.create(null), { codeGeneration: { strings: false, wasm: false } })
  vm.runInContext(`
    const process = Object.freeze({ env: Object.freeze({ HOME: ${JSON.stringify(home)} }), cwd: () => ${JSON.stringify(cwd)} });
    const dshHomePath = (...parts) => [${JSON.stringify(dshHome)}, ...parts].join('/');
    // The harness evaluates row config with its loader context; the synthetic one carries the web runtime's hosts.
    const ctx = Object.freeze({ webRuntime: Object.freeze({ trustedHosts: Object.freeze([]) }), webStartup: Object.freeze({}) });
  `, context, { timeout: 100 })
  function scalar(input) {
    const value = withoutComment(input)
    if (value.startsWith('!!js ')) return vm.runInContext(value.slice(5), context, { timeout: 100 })
    if (value.startsWith('[') && value.endsWith(']')) return splitFlow(value.slice(1, -1)).map(scalar)
    if (value.startsWith('{') && value.endsWith('}')) return Object.fromEntries(splitFlow(value.slice(1, -1)).map(part => {
      const pair = /^([^:]+):\s*(.*)$/u.exec(part)
      assert.ok(pair, 'release-composition:unsupported-flow-map')
      return [scalar(pair[1]), scalar(pair[2])]
    }))
    if (value.startsWith('"')) return JSON.parse(value)
    if (value.startsWith("'")) { assert.ok(value.endsWith("'"), 'release-composition:unterminated-string'); return value.slice(1, -1).replaceAll("''", "'") }
    if (value === 'true') return true
    if (value === 'false') return false
    if (value === 'null' || value === '~') return null
    if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(value)) return Number(value)
    assert.ok(!/^[!&*|>]/u.test(value), `release-composition:unsupported-scalar: ${value}`)
    return value
  }
  function block(lines, offset = 0) {
    const indent = lines[offset].indent
    const sequence = lines[offset].text.startsWith('- ')
    const result = sequence ? [] : {}
    let next = offset
    while (next < lines.length && lines[next].indent === indent) {
      const text = lines[next].text
      const pair = sequence ? /^- (.*)$/u.exec(text) : /^([^:]+):\s*(.*)$/u.exec(text)
      assert.ok(pair, `release-composition:unsupported-config: ${text}`)
      const value = sequence ? pair[1] : pair[2]
      next++
      let parsed
      if (!value && lines[next]?.indent > indent) ({ value: parsed, next } = block(lines, next))
      else parsed = value ? scalar(value) : null
      if (sequence) result.push(parsed)
      else result[pair[1]] = parsed
    }
    return { value: result, next }
  }
  return lines => {
    if (!lines.length) return {}
    const result = block(lines)
    assert.equal(result.next, lines.length, 'release-composition:unparsed-config')
    return result.value
  }
}

export function rows(patch, label, options) {
  const result = []
  const parseConfig = configParser(options)
  const lines = patch.split('\n')
  let row
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]
    const id = /^(\s*)- id: (\S+)\s*$/u.exec(line)
    if (id) { row = { id: id[2], indent: id[1].length, label }; result.push(row); continue }
    const anonymous = /^(\s*)- name: (.+?)\s*$/u.exec(line)
    if (anonymous) {
      row = { id: '<anonymous>', indent: anonymous[1].length, label, name: anonymous[2].replace(/^(['"])(.*)\1$/u, '$2') }
      result.push(row); continue
    }
    const name = /^(\s*)name: (.+?)\s*$/u.exec(line)
    if (name) {
      assert.ok(row && name[1].length === row.indent + 2, `overlay-mount:unmatched-name: ${label}`)
      row.name = name[2].replace(/^(['"])(.*)\1$/u, '$2')
    }
    const disabled = /^(\s*)disabled: (true|false)\s*$/u.exec(line)
    if (disabled && row && disabled[1].length === row.indent + 2) row.disabled = disabled[2] === 'true'
    const config = /^(\s*)config:\s*$/u.exec(line)
    if (config && row && config[1].length === row.indent + 2) {
      const values = []
      while (index + 1 < lines.length) {
        const following = lines[index + 1]
        const text = withoutComment(following)
        if (!text) { index++; continue }
        const indent = /^\s*/u.exec(following)[0].length
        if (indent <= config[1].length) break
        values.push({ text, indent })
        index++
      }
      row.config = parseConfig(values)
    }
  }
  for (const row of result) {
    row.config ??= {}
    assert.ok(row.name || row.indent === 0, `overlay-mount:insert-without-name: ${label}:${row.id}`)
  }
  return result
}

export function sourcePath(name) {
  let path = name.startsWith(`${release}/`) ? name.slice(release.length + 1) : name.replace(/^\.\//u, '')
  path = path.replace(/^plugins\/aukora-face-([^/]+)\//u, 'plugins/aukora-face/$1/')
  if (path === 'plugins/aukora-aura-association/lib/index.js') path = 'scripts/aura/composition/association-plugin.js'
  return resolve(root, path)
}

