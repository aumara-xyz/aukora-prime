// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual host module, invented protected inputs only. Fixtures are retained:
// no cleanup, permission modification, operational inputs or network calls.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { registerHooks } from 'node:module'

const moduleUrl = new URL('../lib/post-policy.mjs', import.meta.url)
const baselineSource = fs.readFileSync(moduleUrl, 'utf8')
const baseline = await import(moduleUrl.href)
const uid = process.getuid?.()
if (!Number.isSafeInteger(uid) || uid <= 0) throw new Error('non-root fixture reader required')
const checksRoot = fs.realpathSync(path.dirname(fileURLToPath(import.meta.url)))
const fixtureParent = path.join(checksRoot, '.post-policy-fixtures')
if (!fs.existsSync(fixtureParent)) fs.mkdirSync(fixtureParent, { mode: 0o700 })
const fixtureParentStat = fs.lstatSync(fixtureParent)
if (!fixtureParentStat.isDirectory() || fixtureParentStat.isSymbolicLink()
  || fixtureParentStat.uid !== uid || (fixtureParentStat.mode & 0o077) !== 0)
  throw new Error('private invented fixture parent required')
const runRoot = fs.mkdtempSync(path.join(fixtureParent, 'retained-'))
let fixtureCounter = 0
const sources = new Map()
const hooks = registerHooks({
  load(url, context, nextLoad) {
    if (sources.has(url)) return { format: 'module', source: sources.get(url), shortCircuit: true }
    return nextLoad(url, context)
  },
})
class MechanismAssertion extends Error {
  constructor(message) { super(message); this.name = 'MechanismAssertion' }
}
const check = (condition, message) => { if (!condition) throw new MechanismAssertion(message) }
function codeOf(fn) {
  try { fn(); return 'ALLOWED' } catch (error) {
    return error instanceof Error && ['REFUSED', 'UNAVAILABLE'].includes(error.code) ? error.code : 'OTHER_ERROR'
  }
}
function expectCode(fn, expected, label) { check(codeOf(fn) === expected, label) }
function write(file, value, mode = 0o600) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, mode)
  try { fs.writeFileSync(fd, value); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
}
const whole = () => ({ kind: 'whole-utf8', pointer: '' })
const selected = pointer => ({ kind: 'json-pointer', pointer })
const values = Object.freeze([
  'river lantern paper hollow',
  'glass kite meadow note',
  'lake birch station word',
  'glow frost paper ember',
])
function fixture(api = baseline) {
  const root = path.join(runRoot, 'case-' + String(++fixtureCounter))
  fs.mkdirSync(root, { mode: 0o700 })
  const files = api.PROTECTED_CATEGORIES.map((category, index) => {
    const file = path.join(root, 'invented-' + String(index))
    write(file, values[index])
    return { category, path: file, owner_uid: uid, selectors: [whole()] }
  })
  return {
    root, files, config: { ...api.POST_POLICY_PROFILE, reader_uid: uid, files },
    extra(name, content, mode = 0o600) {
      const file = path.join(root, name); write(file, content, mode); return file
    },
  }
}
const ordinary = 'A brief status update for the project.'
const embedded = value => 'A note includes ' + value + ' and stops.'
const cases = [
  ['ordinary-post-and-closed-output', api => {
    const f = fixture(api), policy = api.createProtectedPostPolicy(f.config)
    check(Object.isFrozen(policy), 'policy must be frozen')
    check(Object.keys(policy).sort().join(',') === 'assertAllowed,forbiddenDigestCheck', 'no policy data exporter')
    check(JSON.stringify(policy) === '{}', 'closure must not serialize protected data')
    check(policy.assertAllowed(ordinary) === undefined, 'ordinary post allowed')
    check(policy.forbiddenDigestCheck(ordinary) === false, 'ordinary digest decision false')
  }],
  ['required-category-closure', api => {
    const f = fixture(api)
    f.config.files = f.files.slice(0, -1)
    expectCode(() => api.createProtectedPostPolicy(f.config), 'UNAVAILABLE', 'missing category refuses')
  }],
  ['all-four-embedded-values', api => {
    const f = fixture(api), policy = api.createProtectedPostPolicy(f.config)
    for (const value of values) {
      expectCode(() => policy.assertAllowed(embedded(value)), 'REFUSED', 'embedded protected value refuses')
      check(policy.forbiddenDigestCheck(embedded(value)) === true, 'digest decision true')
    }
  }],
  ['shape-catalogue-and-explicit-shapes', api => {
    const f = fixture(api), policy = api.createProtectedPostPolicy(f.config)
    const inputs = [
      'https://invented-user:invented-pass@example.invalid/',
      'f'.repeat(64),
      '-----BEGIN PRIVATE KEY-----\ninvented fixture material\n-----END PRIVATE KEY-----',
      'Bearer invented-fixture-material',
      'api_key = invented-fixture-material',
      'password: invented-fixture-material',
    ]
    for (const input of inputs) expectCode(() => policy.assertAllowed(input), 'REFUSED', 'secret-shaped text refuses')
  }],
  ['missing-malformed-policy', api => {
    for (const input of [undefined, null, {}, [], { ...api.POST_POLICY_PROFILE, reader_uid: uid, files: [] }])
      expectCode(() => api.createProtectedPostPolicy(input), 'UNAVAILABLE', 'incomplete policy refuses')
    const f = fixture(api)
    f.config.algorithm = 'invented-unapproved-algorithm'
    expectCode(() => api.createProtectedPostPolicy(f.config), 'UNAVAILABLE', 'unsupported profile refuses')
  }],
  ['config-accessor-extra-field-sparse-array', api => {
    const f = fixture(api)
    let invoked = 0
    Object.defineProperty(f.config, 'reader_uid', { get() { invoked++; return uid }, enumerable: true })
    expectCode(() => api.createProtectedPostPolicy(f.config), 'UNAVAILABLE', 'accessor config refuses')
    check(invoked === 0, 'accessor not invoked')
    const extra = fixture(api)
    extra.config.enabled = true
    expectCode(() => api.createProtectedPostPolicy(extra.config), 'UNAVAILABLE', 'unknown field refuses')
    const sparse = fixture(api)
    sparse.files.length += 1
    expectCode(() => api.createProtectedPostPolicy(sparse.config), 'UNAVAILABLE', 'sparse files refuses')
  }],
  ['proxy-objects-refuse-before-traps', api => {
    for (const level of ['config', 'file', 'selector']) {
      const f = fixture(api)
      let invoked = 0
      const trap = () => { invoked++; throw new Error('unexpected proxy trap') }
      const handler = { get: trap, getPrototypeOf: trap, ownKeys: trap, getOwnPropertyDescriptor: trap }
      if (level === 'config') f.config = new Proxy(f.config, handler)
      if (level === 'file') f.files[0] = new Proxy(f.files[0], handler)
      if (level === 'selector') f.files[0].selectors[0] = new Proxy(f.files[0].selectors[0], handler)
      expectCode(() => api.createProtectedPostPolicy(f.config), 'UNAVAILABLE', 'proxy object refuses')
      check(invoked === 0, 'proxy object traps must not execute')
    }
  }],
  ['proxy-arrays-refuse-before-traps', api => {
    for (const level of ['files', 'selectors']) {
      const f = fixture(api)
      let invoked = 0
      const trap = () => { invoked++; throw new Error('unexpected proxy trap') }
      const handler = { get: trap, ownKeys: trap, getOwnPropertyDescriptor: trap }
      if (level === 'files') f.config.files = new Proxy(f.files, handler)
      if (level === 'selectors') f.files[0].selectors = new Proxy(f.files[0].selectors, handler)
      expectCode(() => api.createProtectedPostPolicy(f.config), 'UNAVAILABLE', 'proxy array refuses')
      check(invoked === 0, 'proxy array traps must not execute')
    }
  }],
  ['custom-array-prototypes-refuse-before-callbacks', api => {
    for (const kind of ['map-getter', 'map-function', 'selectors-subclass']) {
      const f = fixture(api)
      let invoked = 0
      if (kind === 'selectors-subclass') {
        class InventedSelectors extends Array {
          static get [Symbol.species]() { invoked++; return Array }
          map(callback) { invoked++; return super.map(callback) }
        }
        f.files[0].selectors = new InventedSelectors(whole())
      } else {
        const prototype = Object.create(Array.prototype)
        const map = function (...args) { invoked++; return Array.prototype.map.apply(this, args) }
        if (kind === 'map-getter') Object.defineProperty(prototype, 'map', { get() { invoked++; return map } })
        else Object.defineProperty(prototype, 'map', { value: map })
        Object.setPrototypeOf(f.files, prototype)
      }
      expectCode(() => api.createProtectedPostPolicy(f.config), 'UNAVAILABLE', 'custom array prototype refuses')
      check(invoked === 0, 'custom array map/getter/species must not execute')
    }
  }],
  ['malformed-configured-paths', api => {
    for (const value of [7, null, 'relative-invented-file', '/invented/../file', '/invented//file',
      '/invented/\u0000file', '/invented/\ud800file']) {
      const f = fixture(api)
      f.files[0].path = value
      expectCode(() => api.createProtectedPostPolicy(f.config), 'UNAVAILABLE', 'malformed path must refuse during capture')
    }
  }],
  ['frozen-config-snapshot', api => {
    const f = fixture(api), policy = api.createProtectedPostPolicy(f.config)
    f.files[0].path = f.extra('benign-replacement', 'unrelated invented wording')
    expectCode(() => policy.assertAllowed(embedded(values[0])), 'REFUSED', 'caller mutation cannot retarget captured policy')
    check(policy.forbiddenDigestCheck(ordinary) === false, 'caller mutation cannot break captured policy')
  }],
  ['strict-json-selector-and-trimming', api => {
    const f = fixture(api), literal = '\t  ' + values[0] + '  \n'
    f.files[0].path = f.extra('selected-json', JSON.stringify({ 'a/b': { '~ref': literal }, other: 'different invented value' }))
    f.files[0].selectors = [selected('/a~1b/~0ref')]
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(embedded(values[0])), 'REFUSED', 'trimmed selected value refuses')
    expectCode(() => policy.assertAllowed(embedded(literal)), 'REFUSED', 'literal selected value refuses')
    check(policy.forbiddenDigestCheck('different invented value') === false, 'unselected JSON value is not implicitly protected')
  }],
  ['whole-file-literal-and-trimming', api => {
    const f = fixture(api)
    f.files[0].path = f.extra('literal-whitespace', '\t  ' + values[0] + '  \n')
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(embedded(values[0])), 'REFUSED', 'trimmed whole value refuses')
    expectCode(() => policy.assertAllowed(embedded('\t  ' + values[0] + '  \n')), 'REFUSED', 'literal whole value refuses')
  }],
  ['unicode-byte-window-and-post-cap', api => {
    const f = fixture(api), value = 'invented meadow naïve λ'
    f.files[0].path = f.extra('unicode-value', value)
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed('前置 ' + value + ' 後置'), 'REFUSED', 'Unicode embedded bytes refuse')
    policy.assertAllowed('λ'.repeat(1000))
    expectCode(() => policy.assertAllowed('λ'.repeat(1001)), 'REFUSED', 'UTF-8 byte cap independent of code-unit count')
  }],
  ['per-post-refresh', api => {
    const f = fixture(api), policy = api.createProtectedPostPolicy(f.config)
    check(policy.forbiddenDigestCheck(ordinary) === false, 'initial read allowed')
    const replacement = 'new invented winter field'
    fs.writeFileSync(f.files[0].path, replacement)
    expectCode(() => policy.assertAllowed(embedded(replacement)), 'REFUSED', 'new protected value observed next post')
    check(policy.forbiddenDigestCheck(embedded(values[0])) === false, 'old value not silently retained')
  }],
  ['missing-protected-file', api => {
    const f = fixture(api)
    f.files[0].path = path.join(f.root, 'never-created')
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'missing file not success')
  }],
  ['unreadable-protected-file', api => {
    const f = fixture(api)
    f.files[0].path = f.extra('unreadable', 'invented inaccessible value', 0o000)
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'unreadable file not success')
  }],
  ['public-file-custody', api => {
    const f = fixture(api)
    f.files[0].path = f.extra('public-fixture', values[0], 0o644)
    check((fs.lstatSync(f.files[0].path).mode & 0o077) !== 0, 'public fixture created with intended mode')
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'public file refuses')
  }],
  ['expected-file-owner', api => {
    const f = fixture(api)
    f.files[0].owner_uid = uid + 1
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'wrong expected owner refuses')
  }],
  ['executable-file-refuses', api => {
    const f = fixture(api)
    f.files[0].path = f.extra('executable-fixture', values[0], 0o700)
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'executable file refuses')
  }],
  ['symbolic-file-refuses', api => {
    const f = fixture(api), target = f.extra('symlink-target', values[0])
    const link = path.join(f.root, 'symlink-fixture')
    fs.symlinkSync(target, link)
    f.files[0].path = link
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'symlink file refuses')
  }],
  ['hardlinked-file-refuses', api => {
    const f = fixture(api), target = f.extra('hardlink-target', values[0])
    const link = path.join(f.root, 'hardlink-fixture')
    fs.linkSync(target, link)
    f.files[0].path = link
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'hardlinked file refuses')
  }],
  ['symbolic-ancestor-refuses', api => {
    const f = fixture(api), actual = path.join(f.root, 'actual-dir'), link = path.join(f.root, 'linked-dir')
    fs.mkdirSync(actual, { mode: 0o700 })
    write(path.join(actual, 'invented-value'), values[0])
    fs.symlinkSync(actual, link)
    f.files[0].path = path.join(link, 'invented-value')
    const policy = api.createProtectedPostPolicy(f.config)
    expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'symlink ancestor refuses')
  }],
  ['stale-earlier-ancestor-final-pass', api => {
    const f = fixture(api), policy = api.createProtectedPostPolicy(f.config)
    const original = fs.lstatSync
    let observed = 0
    fs.lstatSync = function (file, ...args) {
      const stat = original.call(fs, file, ...args)
      if (file !== f.root || ++observed <= 8) return stat
      // Four files each snapshot/recheck this same directory. Only the final
      // all-file custody pass sees invented changed metadata. No OS race,
      // permission modification or directory replacement is performed.
      const changed = Object.assign(Object.create(Object.getPrototypeOf(stat)), stat)
      changed.mtimeMs += 1
      return changed
    }
    try {
      expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'earlier ancestor must be rechecked after all reads')
      check(observed === 9, 'final custody pass actually reached')
    } finally { fs.lstatSync = original }
  }],
  ['file-and-projection-size-bounds', api => {
    for (const content of ['', ' '.repeat(3), 'z'.repeat(2001), 'z'.repeat(65537)]) {
      const f = fixture(api)
      f.files[0].path = f.extra('bounded-input', content)
      const policy = api.createProtectedPostPolicy(f.config)
      expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'unsupported protected size refuses')
    }
  }],
  ['unsupported-utf8-and-bom', api => {
    for (const content of [Buffer.from([0xc3, 0x28]), Buffer.from([0xef, 0xbb, 0xbf, 0x61])]) {
      const f = fixture(api)
      f.files[0].path = f.extra('unsupported-encoding', content)
      const policy = api.createProtectedPostPolicy(f.config)
      expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'unsupported encoding refuses')
    }
  }],
  ['json-duplicate-keys-and-nonstring-values', api => {
    for (const content of ['{"entry":"one","entry":"two"}', '{"entry":7}', '{"entry":null}', '{"other":"one"}']) {
      const f = fixture(api)
      f.files[0].path = f.extra('invalid-json-selector', content)
      f.files[0].selectors = [selected('/entry')]
      const policy = api.createProtectedPostPolicy(f.config)
      expectCode(() => policy.assertAllowed(ordinary), 'UNAVAILABLE', 'invalid selected JSON refuses')
    }
  }],
  ['duplicate-path-selector-and-pointer-grammar', api => {
    const duplicate = fixture(api)
    duplicate.files[1].path = duplicate.files[0].path
    expectCode(() => api.createProtectedPostPolicy(duplicate.config), 'UNAVAILABLE', 'duplicate path refuses')
    const selector = fixture(api)
    selector.files[0].selectors.push(whole())
    expectCode(() => api.createProtectedPostPolicy(selector.config), 'UNAVAILABLE', 'duplicate selector refuses')
    const pointer = fixture(api)
    pointer.files[0].selectors = [selected('/entry~2')]
    expectCode(() => api.createProtectedPostPolicy(pointer.config), 'UNAVAILABLE', 'invalid pointer escape refuses')
  }],
  ['post-text-bounds', api => {
    const f = fixture(api), policy = api.createProtectedPostPolicy(f.config)
    for (const input of ['', ' ', 'x\u0000y', '\ud800', 'a'.repeat(2001)])
      expectCode(() => policy.assertAllowed(input), 'REFUSED', 'invalid post refuses')
    policy.assertAllowed('Ordinary text.\nNext line.\tTab retained.')
  }],
  ['closed-generic-errors', api => {
    const f = fixture(api), policy = api.createProtectedPostPolicy(f.config)
    let error
    try { policy.assertAllowed(embedded(values[0])) } catch (caught) { error = caught }
    check(error?.name === 'PostPolicyError' && error?.code === 'REFUSED', 'typed refusal')
    check(error?.message === 'relay post refused', 'generic refusal message')
    check(!Object.hasOwn(error, 'path') && !Object.hasOwn(error, 'digest') && !Object.hasOwn(error, 'value'), 'no diagnostic exporter')
    const missing = fixture(api)
    missing.files[0].path = path.join(missing.root, 'never-created')
    let unavailable
    try { api.createProtectedPostPolicy(missing.config).assertAllowed(ordinary) } catch (caught) { unavailable = caught }
    check(unavailable?.message === 'relay post policy unavailable', 'filesystem error scrubbed')
  }],
]
function replaceUnique(source, before, after) {
  check(source.split(before).length === 2, 'mutation anchor must be unique')
  return source.replace(before, after)
}
const mutations = [
  { id: 'shapes-removed', caseId: 'shape-catalogue-and-explicit-shapes',
    change: source => replaceUnique(source, 'if (shaped(text)) return true', 'if (false && shaped(text)) return true') },
  { id: 'digest-match-removed', caseId: 'all-four-embedded-values',
    change: source => replaceUnique(source, 'if (hashes.has(digest(bytes.subarray(start, start + length)))) return true',
      'if (false && hashes.has(digest(bytes.subarray(start, start + length)))) return true') },
  { id: 'private-file-custody-removed', caseId: 'public-file-custody',
    change: source => replaceUnique(source, '(stat.mode & 0o077) !== 0', 'false') },
  { id: 'file-owner-removed', caseId: 'expected-file-owner',
    change: source => replaceUnique(source, 'stat.uid !== uid ||', 'false ||') },
  { id: 'required-category-removed', caseId: 'required-category-closure',
    change: source => replaceUnique(source, 'if (!PROTECTED_CATEGORIES.every(category => categories.has(category))) unavailable()',
      'if (false) unavailable()') },
  { id: 'proxy-object-guard-removed', caseId: 'proxy-objects-refuse-before-traps',
    change: source => replaceUnique(source, 'types.isProxy(value) || Array.isArray(value)', 'Array.isArray(value)') },
  { id: 'proxy-array-guard-removed', caseId: 'proxy-arrays-refuse-before-traps',
    change: source => replaceUnique(source, 'if (types.isProxy(value) || !Array.isArray(value)', 'if (!Array.isArray(value)') },
  { id: 'array-prototype-guard-removed', caseId: 'custom-array-prototypes-refuse-before-callbacks',
    change: source => replaceUnique(source, ' || Object.getPrototypeOf(value) !== Array.prototype\n', '\n') },
  { id: 'path-nul-guard-removed', caseId: 'malformed-configured-paths',
    change: source => replaceUnique(source, " || file.path.includes('\\0')", '') },
  { id: 'path-unicode-guard-removed', caseId: 'malformed-configured-paths',
    change: source => replaceUnique(source, '!file.path.isWellFormed() || ', '') },
  { id: 'config-snapshot-removed', caseId: 'frozen-config-snapshot',
    change: source => replaceUnique(source, 'return Object.freeze({ reader_uid: input.reader_uid, files: Object.freeze(files) })',
      'return input') },
  { id: 'strict-utf8-removed', caseId: 'unsupported-utf8-and-bom',
    change: source => replaceUnique(source, "new TextDecoder('utf-8', { fatal: true })", "new TextDecoder('utf-8', { fatal: false })") },
  { id: 'final-ancestor-recheck-removed', caseId: 'stale-earlier-ancestor-final-pass',
    change: source => replaceUnique(source, 'if (!identity(before, current)) unavailable()\n    recheckAncestors(ancestors)',
      'if (!identity(before, current)) unavailable()\n    // Final ancestor guard removed by this control.') },
  { id: 'per-post-refresh-removed', caseId: 'per-post-refresh',
    change: source => replaceUnique(replaceUnique(source, 'let config\n', 'let config; let cachedForbidden\n'),
      'const forbidden = protectedDigests(config)', 'const forbidden = cachedForbidden ??= protectedDigests(config)') },
]
const results = []
for (const [id, run] of cases) {
  try { run(baseline); results.push({ id, status: 'PASS' }) }
  catch { results.push({ id, status: 'FAIL' }) }
}
const mutationResults = []
if (process.argv.includes('--mutations')) {
  for (const mutation of mutations) {
    try {
      const changed = mutation.change(baselineSource)
      const url = moduleUrl.href + '?check-mutant=' + mutation.id + '-' + randomUUID()
      sources.set(url, changed)
      const api = await import(url)
      const selectedCase = cases.find(([id]) => id === mutation.caseId)
      check(Boolean(selectedCase), 'mutation mechanism case exists')
      try { selectedCase[1](api); mutationResults.push({ id: mutation.id, status: 'SURVIVED' }) }
      catch (error) {
        // These are original assertion failures after successful module import,
        // not syntax failures, failing mutation construction or changed tests.
        mutationResults.push({ id: mutation.id,
          status: error instanceof MechanismAssertion ? 'KILLED' : 'CONTROL_ERROR' })
      }
    } catch { mutationResults.push({ id: mutation.id, status: 'CONTROL_ERROR' }) }
  }
}
hooks.deregister()
const failed = results.filter(result => result.status !== 'PASS').length
const survived = mutationResults.filter(result => result.status !== 'KILLED').length
console.log(JSON.stringify({
  scope: 'actual-module-synthetic-host-policy',
  cases: results, mutation_controls: mutationResults,
  passed: results.length - failed, failed,
  killed: mutationResults.length - survived, surviving_or_invalid: survived,
  fixtures: 'RETAINED', filesystem_deletes: 0, permission_changes: 0,
  operational_inputs: 0, network_calls: 0,
  production_binding: 'UNPERFORMED', installed_custody: 'UNPERFORMED',
}))
process.exitCode = failed || survived ? 1 : 0
