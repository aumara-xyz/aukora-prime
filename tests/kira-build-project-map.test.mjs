#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Synthetic legacy aliases preserve notes, require review and refuse unsafe output. */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import * as fs from 'node:fs'
import { registerHooks } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = fileURLToPath(import.meta.url), root = dirname(dirname(here))
const toolUrl = new URL('../scripts/kira/build-project-map.mjs', import.meta.url).href
const loaderUrl = new URL('../plugins/aukora-kira/lib/project-mapping.mjs', import.meta.url).href
const hashScope = value => `project:${createHash('sha256').update(value).digest('hex')}`
const id = n => `rem:${n.toString(16).padStart(64, '0')}`
const alpha = '/synthetic/workspaces/alpha', beta = '/synthetic/workspaces/beta'
const mutations = {
  path: ["if (typeof path !== 'string' || !isAbsolute(path) || normalize(path) !== path\n    || /[\\u0000-\\u001f\\u007f]/u.test(path)) refuse('path-invalid')", ''],
  'state-readonly': ["if (out === stateDir || out.startsWith(stateDir.endsWith(sep) ? stateDir : `${stateDir}${sep}`)) refuse('output-in-state')", ''],
  'directory-nofollow': ['constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW', 'constants.O_RDONLY | constants.O_DIRECTORY'],
  'directory-kind': ["if (!parent.stat.isDirectory()) refuse('directory-invalid')", ''],
  'output-parent': ["if (protectedOutput && (parent.stat.uid !== 0 && parent.stat.uid !== process.getuid?.()\n        || (parent.stat.mode & 0o022) !== 0)) refuse('output-parent-unprotected')", ''],
  'directory-stable': ["if (!same(parent.stat, fstatSync(parent.fd), ['dev', 'ino', 'uid', 'mode'])\n        || !same(parent.stat, lstatSync(parent.path), ['dev', 'ino', 'uid', 'mode'])) refuse('directory-changed')", 'if (false) refuse(\'directory-changed\')'],
  'note-nofollow': ['constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK', 'constants.O_RDONLY | constants.O_NONBLOCK'],
  'note-nonblock': ['constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK', 'constants.O_RDONLY | constants.O_NOFOLLOW'],
  'note-readonly': ['constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK', 'constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK'],
  'note-regular': ["if (!before.isFile() || before.nlink !== 1) refuse('note-file-invalid')", "if (before.nlink !== 1) refuse('note-file-invalid')"],
  'note-links': ["if (!before.isFile() || before.nlink !== 1) refuse('note-file-invalid')", "if (!before.isFile()) refuse('note-file-invalid')"],
  'note-size': ["if (before.size > MAX_BYTES) refuse('note-too-large')", ''],
  'note-growth': ["if (used > MAX_BYTES) refuse('note-too-large')", ''],
  'note-stable': ["if (used !== before.size || !same(before, fstatSync(fd), ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']))\n      refuse('note-changed')", ''],
  'note-json': ["parseStrictText(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, used)), 'note')", "JSON.parse(bytes.subarray(0, used).toString('utf8'))"],
  'note-count': ["if (names.length > MAX_RECORDS) refuse('too-many-notes')", ''],
  'note-name': ["if (!/^[0-9a-f]{64}\\.json$/u.test(name)) refuse('note-name-invalid')", ''],
  'note-id': ["if (!note || typeof note !== 'object' || Array.isArray(note) || !RECORD_ID.test(note.id)\n        || note.id.slice(note.id.indexOf(':') + 1) !== name.slice(0, -5)) refuse('note-id-invalid')", ''],
  'note-scope': ["if (typeof note.scope !== 'string' || !/^(?:owner|agent|project:unresolved|project:[0-9a-f]{64}|project:id:[a-z0-9][a-z0-9._-]{0,79})$/u.test(note.scope))\n        refuse('note-scope-invalid')", ''],
  'store-stable': ["if (names.join('\\n') !== readdirSync(store.source).filter(name => name.endsWith('.json') && !['ack.json', 'retry.json'].includes(name)).sort().join('\\n'))\n      refuse('store-changed')", ''],
  'scope-ambiguity': ["if (matched.has(scope) && matched.get(scope) !== project.project_id) refuse('legacy-scope-ambiguous')", ''],
  'project-match': ["if (!found) refuse('project-unmatched')", ''],
  'output-size': ["if (bytes.length > MAX_BYTES) refuse('output-too-large')", ''],
  'output-exclusive': ['constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW', 'constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW'],
  'output-mode': ['fchmodSync(fd, 0o644)', 'fchmodSync(fd, 0o664)'],
  'output-progress': ["if (count <= 0) refuse('output-write-failed')", "if (count <= 0) { written = bytes.length; break }"],
}

if (process.argv[2] === '--child') {
  const mutation = process.argv[3]
  const scratch = fs.mkdtempSync(join(root, '.kira-project-map-test-'))
  fs.chmodSync(scratch, 0o700)
  const fixture = globalThis.projectMapFixture = { root: scratch, descriptors: new Map(), opened: [], fields: new Map(), reads: 0 }
  const shim = `import * as fs from 'node:fs'; export * from 'node:fs'; import { join } from 'node:path';
    const fixture = globalThis.projectMapFixture;
    const changed = (stat, fields) => Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, fields);
    const nominal = path => { const p = String(path), match = /^\\/proc\\/self\\/fd\\/(\\d+)\\/(.*)$/u.exec(p);
      return match ? join(fixture.descriptors.get(Number(match[1])).path, match[2]) : p; };
    const fields = p => p !== fixture.root && !p.startsWith(fixture.root + '/') ? { mode: 0o40755, uid: 0 } : fixture.fields.get(p) ?? {};
    export const openSync = (path, flags, mode) => { const p = nominal(path), directory = (flags & fs.constants.O_DIRECTORY) !== 0;
      fixture.opened.push({ path: p, flags, directory }); fixture.beforeOpen?.(p, directory, flags);
      const fd = fs.openSync(path, flags, mode); fixture.descriptors.set(fd, { path: p, directory, fstats: 0 }); fixture.afterOpen?.(p, directory, flags); return fd; };
    export const closeSync = fd => { fixture.descriptors.delete(fd); fs.closeSync(fd); };
    export const fstatSync = fd => { const descriptor = fixture.descriptors.get(fd), stat = fs.fstatSync(fd); descriptor.fstats++;
      return changed(stat, descriptor.directory ? fields(descriptor.path) : { ...(fixture.noteFields ?? {}),
        ...(descriptor.fstats > 1 ? fixture.afterNoteFields ?? {} : {}) }); };
    export const lstatSync = path => changed(fs.lstatSync(path), fields(String(path)));
    export const readdirSync = path => { const p = nominal(path); if (fixture.names && p.endsWith('/remembered')) {
      fixture.reads++; return fixture.names(fixture.reads); } return fs.readdirSync(path); };
    export const writeSync = (...args) => fixture.zeroWrite ? 0 : fs.writeSync(...args);`
  const shimUrl = `data:text/javascript,${encodeURIComponent(shim)}`
  let applied = 0
  const hook = registerHooks({
    resolve(specifier, context, next) {
      return specifier === 'node:fs' && [toolUrl, loaderUrl].includes(context.parentURL)
        ? { url: shimUrl, shortCircuit: true } : next(specifier, context)
    },
    load(url, context, next) {
      const loaded = next(url, context)
      if (!mutation || url !== toolUrl) return loaded
      const source = String(loaded.source), [before, after] = mutations[mutation]
      assert.equal(source.split(before).length, 2, 'mutation uniquely removes a production protection')
      applied++
      return { ...loaded, source: source.replace(before, after) }
    },
  })
  try {
    const { buildProjectMap, projectMapArgs, formatProjectMapReport } = await import(toolUrl)
    const { loadProjectIdentityFile } = await import(loaderUrl)
    if (mutation) assert.equal(applied, 1, 'mutation loaded production code')
    const stateDir = join(scratch, 'state'), remembered = join(stateDir, 'remembered')
    fs.mkdirSync(remembered, { recursive: true, mode: 0o700 })
    const note = (n, scope) => ({ id: id(n), scope, confidence: 0.75, text: 'Synthetic private statement.', subject: 'synthetic-subject', key: 'synthetic-key' })
    const path = n => join(remembered, `${id(n).slice(4)}.json`)
    const save = (n, value) => fs.writeFileSync(path(n), `${JSON.stringify(value)}\n`, { mode: 0o600 })
    save(1, note(1, hashScope(alpha))); save(2, note(2, hashScope(join(alpha, '.git'))))
    save(3, note(3, hashScope(join(beta, '.git')))); save(4, note(4, 'project:unresolved'))
    save(5, note(5, hashScope('/synthetic/unmatched'))); save(6, note(6, 'owner'))
    save(7, note(7, hashScope(alpha)))
    for (const name of ['ack.json', 'retry.json']) fs.writeFileSync(join(remembered, name), '{"private":"not a note"}\n')
    const projects = [{ project_id: 'alpha', workspace_roots: [alpha] }, { project_id: 'beta', workspace_roots: [beta] }]
    let sequence = 0
    const input = overrides => ({ stateDir, projects, out: join(scratch, `map-${sequence++}.json`), ...overrides })
    const refuses = (args, code) => assert.throws(() => buildProjectMap(args), error => error.code === `kira.build-project-map:${code}`,
      `${code} protection`)
    const original = fs.readdirSync(remembered).map(name => [name, fs.readFileSync(join(remembered, name))])
    const beforeUmask = process.umask(0o002)
    const good = input(), report = buildProjectMap(good)
    process.umask(beforeUmask)
    assert.equal(fs.statSync(good.out).mode & 0o777, 0o644, 'explicit 0644 protection under umask 002')
    assert.equal(report.notes, 7); assert.equal(report.projects, 2); assert.equal(report.scopes, 3); assert.equal(report.mapped, 4)
    assert.equal(report.unmatched.length, 2)
    const rendered = formatProjectMapReport(report)
    assert.equal(rendered, `kira-build-project-map: notes=7 projects=2 scopes=3 mapped=4 unmatched=2\nunmatched scope=${hashScope('/synthetic/unmatched')} notes=1\nunmatched scope=project:unresolved notes=1\n`, 'counts-only output protection')
    for (const value of ['Synthetic private statement.', 'synthetic-subject', 'synthetic-key', id(1)])
      assert.equal(rendered.includes(value), false, 'report excludes note fields and record ids')
    const raw = JSON.parse(fs.readFileSync(good.out, 'utf8'))
    assert.equal(raw.version, 1); assert.equal(raw.alias_table.status, 'draft')
    assert.equal(raw.alias_table.entries.length, 3)
    assert.equal(raw.alias_table.entries.flatMap(entry => entry.record_ids).sort().join(','), [id(1), id(2), id(3), id(7)].join(','), 'every matched id is individually listed')
    let resolver = loadProjectIdentityFile(good.out)
    assert.equal(resolver.scopeOf({ session: { header: { cwd: alpha } } }), 'project:id:alpha', 'loader accepts generated project roots')
    assert.equal(resolver.resolveLegacyScope(hashScope(alpha), id(1)), null, 'draft does not attach legacy memory')
    const reviewed = input({ reviewId: 'synthetic-owner-review' })
    buildProjectMap(reviewed); resolver = loadProjectIdentityFile(reviewed.out)
    assert.equal(resolver.resolveLegacyScope(hashScope(alpha), id(1)), 'project:id:alpha', 'reviewed alias attaches exact listed id')
    assert.equal(resolver.resolveLegacyScope(hashScope(join(alpha, '.git')), id(2)), 'project:id:alpha', 'Git legacy form is mapped')
    assert.equal(resolver.resolveLegacyScope(hashScope(alpha), id(3)), null, 'alias does not attach an unlisted id')
    assert.equal(fs.readdirSync(remembered).length, original.length, 'scan does not create state files')
    for (const [name, bytes] of original) assert.equal(fs.readFileSync(join(remembered, name)).equals(bytes), true, 'scan preserves every note and metadata byte')
    const readFlags = fixture.opened.filter(row => row.path === path(1)).at(-1).flags
    assert.equal(readFlags & (fs.constants.O_WRONLY | fs.constants.O_RDWR), 0, 'note readonly protection')
    assert.equal(readFlags & fs.constants.O_NOFOLLOW, fs.constants.O_NOFOLLOW, 'note nofollow protection')
    assert.equal(readFlags & fs.constants.O_NONBLOCK, fs.constants.O_NONBLOCK, 'note nonblock protection')
    for (const row of fixture.opened.filter(row => row.directory)) assert.equal(row.flags & fs.constants.O_NOFOLLOW, fs.constants.O_NOFOLLOW, 'directory nofollow protection')
    assert.equal(fixture.descriptors.size, 0, 'all held descriptors are closed')
    const args = projectMapArgs([stateDir, '--project', `alpha=${alpha}`, '--project', `beta=${beta}`, '--out', good.out, '--owner-reviewed', 'synthetic-review'])
    assert.equal(args.projects.length, 2); assert.equal(args.reviewId, 'synthetic-review')
    for (const argv of [[], ['--out', 'x'], [stateDir], [stateDir, '--project', 'x', '--out', 'x'], [stateDir, '--unknown', 'x'],
      [stateDir, '--project', `alpha=${alpha}`, '--out', 'x', '--out', 'y'], [stateDir, '--project', `alpha=${alpha}`, '--out', 'x', '--owner-reviewed', '--out']])
      assert.throws(() => projectMapArgs(argv), error => error.code === 'kira.build-project-map:usage', 'argument refusal')
    for (const state of ['relative', `${stateDir}/../state`, `${stateDir}\n`]) refuses(input({ stateDir: state }), 'path-invalid')
    refuses(input({ out: 'relative.json' }), 'path-invalid')
    refuses(input({ out: join(stateDir, 'mapping.json') }), 'output-in-state')
    for (const given of [undefined, [], [{ project_id: 'INVALID', workspace_roots: [alpha] }],
      [{ project_id: 'alpha', workspace_roots: ['relative'] }], [{ project_id: 'alpha', workspace_roots: [alpha, alpha] }]])
      refuses(input({ projects: given }), 'projects-invalid')
    refuses(input({ reviewId: '' }), 'projects-invalid')
    refuses(input({ projects: [{ project_id: 'nothing', workspace_roots: ['/synthetic/nothing'] }] }), 'project-unmatched')
    refuses(input({ projects: [{ project_id: 'alpha', workspace_roots: [alpha] }, { project_id: 'collision', workspace_roots: [join(alpha, '.git')] }] }), 'legacy-scope-ambiguous')
    const existing = fs.readFileSync(good.out)
    refuses(input({ out: good.out }), 'output-exists')
    assert.equal(fs.readFileSync(good.out).equals(existing), true, 'existing output bytes are preserved')
    const symlinkOut = join(scratch, 'symlink-map.json')
    fs.symlinkSync(good.out, symlinkOut); refuses(input({ out: symlinkOut }), 'output-exists')
    const linkedState = join(scratch, 'linked-state'); fs.symlinkSync(stateDir, linkedState)
    refuses(input({ stateDir: linkedState }), 'directory-unavailable')
    fixture.fields.set(remembered, { mode: 0o100600 }); refuses(input(), 'directory-invalid'); fixture.fields.clear()
    for (const fields of [{ mode: 0o40775 }, { mode: 0o40707 }, { uid: (process.getuid() || 1000) + 1000 }]) {
      fixture.fields.set(scratch, fields); refuses(input(), 'output-parent-unprotected'); fixture.fields.clear()
    }
    fixture.afterNoteFields = { mtimeMs: -1 }; refuses(input(), 'note-changed'); fixture.afterNoteFields = undefined
    fixture.noteFields = { size: 1024 * 1024 + 1 }; refuses(input(), 'note-too-large'); fixture.noteFields = undefined
    fixture.noteFields = { mode: 0o40700 }; refuses(input(), 'note-file-invalid'); fixture.noteFields = undefined
    const linked = join(remembered, 'linked.json'); fs.linkSync(path(1), linked)
    refuses(input(), 'note-file-invalid'); fs.unlinkSync(linked)
    fs.renameSync(path(1), `${path(1)}.kept`); fs.symlinkSync(`${path(1)}.kept`, path(1))
    refuses(input(), 'note-unavailable'); fs.unlinkSync(path(1)); fs.renameSync(`${path(1)}.kept`, path(1))
    const saved = fs.readFileSync(path(1))
    fs.writeFileSync(path(1), ' '.repeat(1024 * 1024 + 1)); fixture.noteFields = { size: 1024 * 1024 }
    refuses(input(), 'note-too-large'); fixture.noteFields = undefined; fs.writeFileSync(path(1), saved)
    for (const bytes of ['{"id":"' + id(1) + '","id":"' + id(1) + '","scope":"' + hashScope(alpha) + '"}', '{',
      '{"id":"' + id(1) + '","scope":"' + hashScope(alpha) + '","n":9007199254740993}', Buffer.from([0xff])]) {
      fs.writeFileSync(path(1), bytes); refuses(input(), 'note-json-invalid')
    }
    fs.writeFileSync(path(1), saved)
    for (const value of [note(100, hashScope(alpha)), { ...note(1, hashScope(alpha)), id: 'not-an-id' }]) {
      save(1, value); refuses(input(), 'note-id-invalid')
    }
    save(1, note(1, 'arbitrary-private-value')); refuses(input(), 'note-scope-invalid'); fs.writeFileSync(path(1), saved)
    fs.writeFileSync(join(remembered, 'other.json'), saved); refuses(input(), 'note-name-invalid'); fs.unlinkSync(join(remembered, 'other.json'))
    const names = fs.readdirSync(remembered)
    fixture.reads = 0; fixture.names = () => Array(100_001).fill('not-read.json'); refuses(input(), 'too-many-notes'); fixture.names = undefined
    fixture.reads = 0; fixture.names = n => n === 1 ? names : [...names, `${id(100).slice(4)}.json`]
    refuses(input(), 'store-changed'); fixture.names = undefined
    fixture.afterOpen = (p, directory) => {
      if (directory || p !== path(7)) return
      fixture.afterOpen = undefined
      fs.renameSync(remembered, `${remembered}-held`); fs.mkdirSync(remembered, { mode: 0o700 })
    }
    try { refuses(input(), 'directory-changed') }
    finally { fixture.afterOpen = undefined; fs.rmSync(remembered, { recursive: true }); fs.renameSync(`${remembered}-held`, remembered) }
    refuses(input({ projects: [{ project_id: 'alpha', workspace_roots: [alpha, '/synthetic/' + 'x'.repeat(1024 * 1024)] }] }), 'output-too-large')
    fixture.zeroWrite = true; refuses(input(), 'output-write-failed'); fixture.zeroWrite = false
    const failure = spawnSync(process.execPath, [fileURLToPath(new URL(toolUrl)), stateDir, '--project', `alpha=${alpha}`, '--out', join(scratch, 'cli-out.json'), '--unrecognized', 'private-value'], { encoding: 'utf8', timeout: 3000 })
    assert.equal(failure.status, 1); assert.equal(failure.stdout, ''); assert.equal(failure.stderr, 'kira.build-project-map:usage\n', 'CLI emits only a named refusal')
    fs.writeFileSync(path(1), '{"text":"synthetic-never-print",')
    const unreadable = spawnSync(process.execPath, [fileURLToPath(new URL(toolUrl)), stateDir, '--project', `alpha=${alpha}`, '--out', join(scratch, 'cli-out.json')], { encoding: 'utf8', timeout: 3000 })
    assert.equal(unreadable.status, 1); assert.equal(unreadable.stdout, '')
    assert.equal(unreadable.stderr, 'kira.build-project-map:note-json-invalid\n', 'CLI hides note text on malformed bytes')
    assert.equal(fixture.descriptors.size, 0, 'refusals close retained descriptors')
    process.stdout.write('kira-build-project-map: PASS synthetic mappings and refusal guards\n')
  } catch (error) {
    process.stderr.write(`kira-build-project-map: FAIL ${error instanceof assert.AssertionError ? `assertion: ${error.message.split('\n')[0]}` : 'unexpected refusal'}\n`)
    process.exitCode = 1
  } finally { hook.deregister(); fs.rmSync(scratch, { recursive: true, force: true }) }
} else {
  const run = mutation => spawnSync(process.execPath, [here, '--child', ...(mutation ? [mutation] : [])], { encoding: 'utf8', timeout: 5000 })
  const baseline = run()
  assert.equal(baseline.status, 0, baseline.stderr || 'synthetic project map checks pass')
  process.stdout.write(baseline.stdout)
  let detected = 0
  for (const mutation of Object.keys(mutations)) {
    const result = run(mutation)
    assert.equal(result.status, 1, `mutation ${mutation} must fail its protection check`)
    assert.equal(result.error, undefined, `mutation ${mutation} check stays bounded`)
    assert.match(result.stderr, /^kira-build-project-map: FAIL assertion: /u, `mutation ${mutation} fails a regression assertion`)
    assert.doesNotMatch(result.stderr, /mutation uniquely removes|mutation loaded production/u, `mutation ${mutation} actually loaded`)
    detected++
  }
  process.stdout.write(`kira-build-project-map: PASS ${detected}/${Object.keys(mutations).length} production protection mutations detected\n`)
}
