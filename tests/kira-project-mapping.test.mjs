#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Isolated startup mappings attach project recall and name an unmapped workspace.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, constants, linkSync, mkdirSync, mkdtempSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const file = fileURLToPath(import.meta.url), root = dirname(dirname(file))
const loaderUrl = new URL('../plugins/aukora-kira/lib/project-mapping.mjs', import.meta.url).href
const subject = `aukora:1:${'75'.repeat(32)}`
const roots = { alpha: '/synthetic/projects/alpha', beta: '/synthetic/projects/beta', unmapped: '/synthetic/projects/unmapped' }
const mapping = { version: 1, projects: ['alpha', 'beta'].map(project_id => ({ project_id, workspace_roots: [roots[project_id]] })) }
const text = 'The heliotrope cabinet contains the spare compass.'
const agentAt = (cwd, id = 'synthetic-project-session') => ({ session: { id, header: { cwd } } })
const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? undefined : process.argv[mutantAt + 1]
const mutations = {
  path: ['project-mapping.mjs', "if (typeof file !== 'string' || !isAbsolute(file) || normalize(file) !== file\n    || /[\\u0000-\\u001f\\u007f]/u.test(file)) refuse('path-invalid')", ''],
  isolation: ['project-mapping.mjs', "if (typeof process.getuid !== 'function' || typeof constants.O_NOFOLLOW !== 'number'\n    || typeof constants.O_NONBLOCK !== 'number' || typeof constants.O_DIRECTORY !== 'number') refuse('isolation-unavailable')", ''],
  'parent-kind': ['project-mapping.mjs', "if (!stat.isDirectory() || stat.isSymbolicLink()) refuse('parent-invalid')", ''],
  'parent-owner': ['project-mapping.mjs', "if (!owned(stat)) refuse('parent-owner')", ''],
  'parent-mode': ['project-mapping.mjs', "if ((stat.mode & 0o022) !== 0) refuse('parent-writable')", ''],
  ancestry: ['project-mapping.mjs', "['/', ...dirname(file).split('/').filter(Boolean)]", "['/']"],
  'parent-nofollow': ['project-mapping.mjs', 'constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW', 'constants.O_RDONLY | constants.O_DIRECTORY'],
  'parent-binding': ['project-mapping.mjs', "if (['dev', 'ino', 'uid', 'mode'].some(key => parent.stat[key] !== stat[key] || stat[key] !== current[key]))\n        refuse('parent-changed')", ''],
  'parent-held-metadata': ['project-mapping.mjs', 'const stat = fstatSync(fd)', "const stat = lstatSync(globalThis.projectMappingFixture.descriptors.get(fd).path)"],
  nofollow: ['project-mapping.mjs', 'constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK', 'constants.O_RDONLY | constants.O_NONBLOCK'],
  nonblock: ['project-mapping.mjs', 'constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK', 'constants.O_RDONLY | constants.O_NOFOLLOW'],
  readonly: ['project-mapping.mjs', 'constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK', 'constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK'],
  'file-kind': ['project-mapping.mjs', '!before.isFile() || before.nlink !== 1', 'before.nlink !== 1'],
  'file-links': ['project-mapping.mjs', '!before.isFile() || before.nlink !== 1', '!before.isFile()'],
  'file-owner': ['project-mapping.mjs', "if (!owned(before)) refuse('file-owner')", ''],
  'file-mode': ['project-mapping.mjs', "if ((before.mode & 0o022) !== 0) refuse('file-writable')", ''],
  'size-before': ['project-mapping.mjs', "if (before.size > MAX_BYTES) refuse('file-too-large')", ''],
  'size-read': ['project-mapping.mjs', "if (used > MAX_BYTES) refuse('file-too-large')", ''],
  stable: ['project-mapping.mjs', "if (used !== before.size || ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']\n      .some(key => before[key] !== after[key])) refuse('file-changed')", ''],
  strict: ['project-mapping.mjs', "parseStrictJson(buffer.subarray(0, used).toString('utf8'))", "JSON.parse(buffer.subarray(0, used).toString('utf8'))"],
  conflict: ['index.js', "if (record.projectIdentity !== undefined && record.projectIdentityFile !== undefined)\n    refuse('project-identity-ambiguous', 'name exactly one project identity source')", ''],
  wiring: ['index.js', 'record.projectIdentityFile !== undefined ? loadProjectIdentityFile(record.projectIdentityFile)', 'record.projectIdentityFile !== undefined ? undefined'],
  'tool-notice': ['index.js', 'return { ...final, project: projectRecallState(exec?.agent, projectIdentity), status:', 'return { ...final, status:'],
  'output-schema': ['tools.mjs', "          project: { type: 'object', additionalProperties: false, properties: {\n            state: { type: 'string', enum: ['mapped', 'unmapped', 'none'] },\n            scope: { type: 'string' }, reason: { type: 'string', enum: ['no-project-mapped'] }, message: { type: 'string' },\n          }, required: ['state'] },\n", ''],
  'service-notice': ['index.js', ', project: projectRecallState({ session: currentSession }, projectIdentity)', ''],
  'pre-step-notice': ['index.js', "if (project.state === 'unmapped') diagnostics.diagnostics.push({ reason: project.reason })", ''],
  'recent-notice': ['project-memory.mjs', "if (scope === null) return { snippets: [], projectState: true, availability: 'undetermined', reason: 'no-project-mapped', message: 'no project mapped' }", "if (scope === null) return { snippets: [], projectState: true, availability: 'undetermined', reason: 'host-project-scope-unavailable' }"],
  'render-notice': ['injection.mjs', "recent.reason === 'no-project-mapped'", 'false'],
  'diagnostic-notice': ['injection.mjs', "'content-hash-mismatch', 'unmapped', 'no-project-mapped', 'unreadable'", "'content-hash-mismatch', 'unmapped', 'unreadable'"],
  'pre-step-render': ['injection.mjs', "if (diagnostics.some(item => item.reason === 'no-project-mapped'))\n    lines.push('PROJECT STATE: no project mapped; project history is unattached.')", ''],
}

if (process.argv[2] === '--child') {
  const [mode, scratch, project = 'alpha'] = process.argv.slice(3)
  const mutation = process.env.KIRA_PROJECT_MAPPING_MUTANT
  if (mutation) assert.ok(mutations[mutation], 'known production guard removal')
  // The sandbox's shared /private/tmp ancestry cannot be made host-owned here.
  // Only this loader's outside ancestors are synthetic; fixture metadata stays real.
  globalThis.projectMappingFixture = { root: scratch, overrides: new Map(), opened: [], descriptors: new Map(), fstats: 0 }
  const shim = `import * as fs from 'node:fs'; export * from 'node:fs'; import { join } from 'node:path';
    const fixture = globalThis.projectMappingFixture;
    const changed = (stat, fields) => Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, fields);
    const parentFields = p => p !== fixture.root && !p.startsWith(fixture.root + '/')
      ? { mode: 0o40755, uid: 0 } : fixture.overrides.get(p) ?? {};
    const nominal = path => {
      const p = String(path), match = /^\\/proc\\/self\\/fd\\/(\\d+)\\/(.*)$/u.exec(p);
      return match ? join(fixture.descriptors.get(Number(match[1])).path, match[2]) : p;
    };
    export const existsSync = path => path === '/proc/self/fd' && fixture.fallback ? false : fs.existsSync(path);
    export const lstatSync = path => {
      const stat = fs.lstatSync(path), p = String(path);
      return changed(stat, parentFields(p));
    };
    export const openSync = (path, flags) => {
      const p = nominal(path), directory = (flags & fs.constants.O_DIRECTORY) !== 0;
      fixture.opened.push(flags); fixture.beforeOpen?.(p, directory, flags);
      const fd = fs.openSync(path, flags);
      fixture.descriptors.set(fd, { path: p, directory }); return fd;
    };
    export const closeSync = fd => { fixture.descriptors.delete(fd); fs.closeSync(fd); };
    export const fstatSync = fd => {
      const stat = fs.fstatSync(fd), descriptor = fixture.descriptors.get(fd);
      if (descriptor.directory) return changed(stat, fixture.heldFields?.(descriptor.path) ?? parentFields(descriptor.path));
      const number = ++fixture.fstats;
      return changed(stat, { ...(fixture.fileFields ?? {}), ...(number > 1 ? fixture.afterFields ?? {} : {}) });
    };`
  const shimUrl = `data:text/javascript,${encodeURIComponent(shim)}`
  let applied = 0
  const hook = registerHooks({
    resolve(specifier, context, next) {
      return specifier === 'node:fs' && context.parentURL === loaderUrl
        ? { url: shimUrl, shortCircuit: true } : next(specifier, context)
    },
    load(url, context, next) {
      const loaded = next(url, context)
      if (!mutation || url !== new URL(`../plugins/aukora-kira/lib/${mutations[mutation][0]}`, import.meta.url).href) return loaded
      const source = String(loaded.source), [, before, after] = mutations[mutation]
      assert.equal(source.split(before).length, 2, `unique production mutation: ${mutation}`)
      applied++
      return { ...loaded, source: source.replace(before, after) }
    },
  })
  try {
    const { loadProjectIdentityFile } = await import('../plugins/aukora-kira/lib/project-mapping.mjs')
    const { apply, readConfig } = await import('../plugins/aukora-kira/lib/index.js')
    const { projectRecent } = await import('../plugins/aukora-kira/lib/project-memory.mjs')
    const { recalledContextLine } = await import('../plugins/aukora-kira/lib/injection.mjs')
    if (mutation) assert.equal(applied, 1, 'production mutation was loaded')
    const mappingFile = join(scratch, 'projects.json')
    const config = { retrieval: 'lexical', projectIdentityFile: mappingFile,
      memoryOwner: { stateDir: join(scratch, 'home/kira-memory'), subject } }
    if (mode === 'guards') {
      const fixture = globalThis.projectMappingFixture
      const good = join(scratch, 'guards/good.json'), parent = dirname(good)
      mkdirSync(parent, { recursive: true, mode: 0o700 })
      const content = JSON.stringify(mapping)
      writeFileSync(good, content, { mode: 0o600 })
      const load = target => { fixture.fstats = 0; return loadProjectIdentityFile(target) }
      const refused = (target, code) => assert.throws(() => load(target), error => error.code === `kira.project-map:${code}`
        && error.message === error.code, `mapping ${code} protection`)
      let resolver
      assert.doesNotThrow(() => { resolver = load(good) }, 'valid isolated mapping must load')
      assert.equal(resolver.scopeOf(agentAt(roots.alpha)), 'project:id:alpha')
      const flags = fixture.opened.at(-1)
      assert.equal(flags & constants.O_NOFOLLOW, constants.O_NOFOLLOW, 'mapping nofollow protection')
      assert.equal(flags & constants.O_NONBLOCK, constants.O_NONBLOCK, 'mapping nonblock protection')
      assert.equal(flags & (constants.O_WRONLY | constants.O_RDWR), 0, 'mapping readonly protection')
      for (const flags of fixture.opened.slice(0, -1)) {
        assert.equal(flags & constants.O_DIRECTORY, constants.O_DIRECTORY, 'mapping parent directory protection')
        assert.equal(flags & constants.O_NOFOLLOW, constants.O_NOFOLLOW, 'mapping parent nofollow protection')
      }
      assert.equal(fixture.descriptors.size, 0, 'mapping closes retained ancestors')
      for (const path of [42, 'relative.json', join(parent, 'x') + '/../good.json', good + '\n']) refused(path, 'path-invalid')
      const getuid = process.getuid
      try { process.getuid = undefined; refused(good, 'isolation-unavailable') } finally { process.getuid = getuid }
      fixture.overrides.set(parent, { uid: (process.getuid() || 1000) + 1000 })
      refused(good, 'parent-owner'); fixture.overrides.clear()
      for (const mode of [0o720, 0o702]) { chmodSync(parent, mode); refused(good, 'parent-writable') }
      chmodSync(parent, 0o700)
      chmodSync(scratch, 0o722); refused(good, 'parent-writable'); chmodSync(scratch, 0o700)
      const linkedParent = join(scratch, 'linked-parent')
      symlinkSync(parent, linkedParent); refused(join(linkedParent, 'good.json'), 'parent-invalid')
      fixture.overrides.set(parent, { mode: 0o100600 }); refused(good, 'parent-invalid'); fixture.overrides.clear()
      fixture.heldFields = path => path === parent ? { uid: (process.getuid() || 1000) + 1000 } : undefined
      refused(good, 'parent-owner'); fixture.heldFields = undefined
      for (const fallback of [false, true]) for (const replacement of ['directory', 'symlink']) for (const level of ['parent', 'ancestor']) {
        fixture.fallback = fallback
        const replaced = level === 'parent' ? parent : scratch, moved = replaced + '-retained', alternate = replaced + '-alternate'
        fixture.beforeOpen = (path, directory) => {
          if (directory || path !== good) return
          fixture.beforeOpen = undefined
          renameSync(replaced, moved)
          const target = replacement === 'symlink' ? alternate : replaced
          const targetFile = level === 'parent' ? join(target, 'good.json') : join(target, 'guards/good.json')
          mkdirSync(dirname(targetFile), { recursive: true, mode: 0o700 })
          writeFileSync(targetFile, JSON.stringify({ version: 1, projects: [{ project_id: 'different', workspace_roots: [roots.alpha] }] }), { mode: 0o600 })
          if (replacement === 'symlink') symlinkSync(alternate, replaced)
        }
        try { refused(good, 'parent-changed') }
        finally {
          fixture.beforeOpen = undefined; rmSync(replaced, { recursive: true }); rmSync(alternate, { recursive: true, force: true })
          renameSync(moved, replaced)
        }
        assert.equal(fixture.descriptors.size, 0, 'mapping closes descriptors after parent replacement')
      }
      fixture.fallback = false
      fixture.fileFields = { uid: (process.getuid() || 1000) + 1000 }
      refused(good, 'file-owner'); fixture.fileFields = { uid: 0 }
      assert.equal(load(good).scopeOf(agentAt(roots.beta)), 'project:id:beta', 'root-owned mapping is accepted')
      fixture.fileFields = {}
      for (const mode of [0o620, 0o602]) { chmodSync(good, mode); refused(good, 'file-writable') }
      chmodSync(good, 0o600)
      const linkedFile = join(parent, 'linked.json'), hardlink = join(parent, 'hard.json')
      symlinkSync(good, linkedFile); refused(linkedFile, 'file-symlink')
      linkSync(good, hardlink); refused(good, 'file-invalid'); rmSync(hardlink)
      fixture.fileFields = { mode: 0o40700 }; refused(good, 'file-invalid'); fixture.fileFields = {}
      fixture.fileFields = { size: 1024 * 1024 + 1 }; refused(good, 'file-too-large'); fixture.fileFields = {}
      const big = join(parent, 'big.json')
      writeFileSync(big, ' '.repeat(1024 * 1024 + 1), { mode: 0o600 })
      fixture.fileFields = { size: 1024 * 1024 }; refused(big, 'file-too-large'); fixture.fileFields = {}
      for (const key of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']) {
        fixture.afterFields = { [key]: -1 }; refused(good, 'file-changed')
      }
      fixture.afterFields = {}
      fixture.fileFields = { size: Buffer.byteLength(content) + 1 }; refused(good, 'file-changed'); fixture.fileFields = {}
      for (const bytes of ['{"version":1,"version":1,"projects":[]}', '{', '{"version":1,"projects":[],"x":9007199254740993}']) {
        writeFileSync(good, bytes); refused(good, 'json-invalid')
      }
      writeFileSync(good, content)
      assert.throws(() => readConfig({ ...config, projectIdentity: mapping }), error => error.code === 'kira.config:project-identity-ambiguous', 'mapping conflict protection')
      assert.equal(load(good).scopeOf(agentAt(roots.unmapped)), null)
      writeFileSync(good, JSON.stringify({ version: 1, projects: [] }))
      assert.equal(resolver.scopeOf(agentAt(roots.alpha)), 'project:id:alpha', 'mapping stays a startup snapshot')
      const recent = projectRecent([], { subject, permittedPrivacy: ['local'] }, null)
      assert.equal(recent.reason, 'no-project-mapped', 'projectRecent unmapped named result')
      assert.equal(recent.message, 'no project mapped')
      assert.match(recalledContextLine({ availability: 'empty', snippets: [] }, recent), /PROJECT STATE: no project mapped/u, 'unmapped result is rendered plainly')
      process.stdout.write(JSON.stringify({ guards: true }) + '\n')
    } else {
      const tools = new Map(), services = new Map(), handlers = new Map(), disposers = []
      const agent = agentAt(roots[project], `synthetic-${project}-session`), sessions = new Map([[agent.session.id, agent.session]])
      const ctx = {
        tools: { register: tool => tools.set(tool.name, tool) }, sessions: { get: id => sessions.get(id) },
        provide: (name, service) => services.set(name, service),
        effect: fn => { const dispose = fn(); if (typeof dispose === 'function') disposers.push(dispose) },
        on: (name, handler) => { handlers.set(name, handler); return () => handlers.delete(name) },
        inject: () => {}, reflect: { get: () => undefined }, logger: { info() {}, warn() {}, debug() {} },
      }
      globalThis.fetch = async () => { throw Error('lexical project fixture must not fetch') }
      try {
        await apply(ctx, config)
        const answer = mode === 'remember' ? await tools.get('kira_remember').execute({ text }, { agent })
          : mode === 'service' ? await services.get('kira.recall').recall('heliotrope', agent.session)
            : await tools.get('kira_recall').execute({ text: 'heliotrope' }, { agent })
        if (mode === 'tool' || mode === 'pre-step') {
          const schema = tools.get('kira_recall').output.schema
          assert.equal(schema.additionalProperties, false)
          assert.deepEqual(schema.properties.project, { type: 'object', additionalProperties: false, properties: {
            state: { type: 'string', enum: ['mapped', 'unmapped', 'none'] },
            scope: { type: 'string' }, reason: { type: 'string', enum: ['no-project-mapped'] }, message: { type: 'string' },
          }, required: ['state'] }, 'native output schema declares the project notice')
          assert.ok(answer.project, 'native recall returns its declared project notice')
          for (const [key, value] of Object.entries(answer.project)) {
            const field = schema.properties.project.properties[key]
            assert.ok(field, `native project notice field ${key} is declared`)
            assert.equal(typeof value, field.type)
            if (field.enum) assert.ok(field.enum.includes(value), `native project notice field ${key} is allowed`)
          }
        }
        if (mode === 'remember') {
          const { preTurnRecallFilter } = await import('../plugins/aukora-kira/lib/memory-frame.mjs')
          assert.deepEqual(preTurnRecallFilter(answer.notes[0], { attachedProjects: ['project:id:alpha'], now: new Date().toISOString() }),
            { ok: false, why: 'model-authored-never-pre-turn' }, 'mapping keeps agent-authored notes out of automatic context')
        }
        if (mode === 'pre-step') {
          const reply = await handlers.get('agent/pre-step')({ agent }, async () => ({ kind: 'continue', messages: [{ role: 'user', content: 'heliotrope' }] }))
          assert.match(JSON.stringify(reply.messages), /no-project-mapped/u, 'pre-step names unmapped project')
          assert.match(JSON.stringify(reply.messages), /PROJECT STATE: no project mapped; project history is unattached/u, 'pre-step renders unmapped project plainly')
        }
        process.stdout.write(JSON.stringify({ answer, pid: process.pid }) + '\n')
      } finally { for (const dispose of disposers.reverse()) dispose() }
    }
  } finally { hook.deregister() }
} else if (process.argv.includes('--mutate')) {
  for (const name of Object.keys(mutations)) {
    const child = spawnSync(process.execPath, [file, '--mutant', name], { cwd: root, encoding: 'utf8', timeout: 60_000 })
    assert.equal(child.status, 1, `mapping mutation ${name} must fail`)
    assert.match(child.stderr, /AssertionError/u, `mapping mutation ${name} must fail an assertion`)
    assert.doesNotMatch(child.stderr, /unique production mutation|production mutation was loaded/u, `mapping mutation ${name} must execute its guard removal`)
    console.log(`kira-project-mapping mutation ${name}: CAUGHT`)
  }
  console.log(`kira-project-mapping mutations: ${Object.keys(mutations).length} caught, 0 survived`)
} else {
  const scratchRoot = join(root, '.scratch')
  mkdirSync(scratchRoot, { recursive: true })
  const scratch = mkdtempSync(join(scratchRoot, 'kira-project-mapping-'))
  chmodSync(scratch, 0o700)
  const run = (mode, project) => {
    const child = spawnSync(process.execPath, [file, '--child', mode, scratch, ...(project ? [project] : [])], {
      cwd: root, encoding: 'utf8', timeout: 30_000, env: { ...process.env,
        KIRA_PROJECT_MAPPING_MUTANT: mutant ?? '', AUKORA_STATE: scratch,
        AUKORA_ROOM_LOG: join(scratch, 'absent-room.log'), AUKORA_OPENVIKING_HOME: join(scratch, 'home/openviking') },
    })
    assert.equal(child.status, 0, child.stderr)
    return JSON.parse(child.stdout)
  }
  try {
    writeFileSync(join(scratch, 'projects.json'), JSON.stringify(mapping), { mode: 0o600 })
    run('guards')
    const saved = run('remember', 'alpha')
    assert.equal(saved.answer.remembered, 1)
    assert.equal(saved.answer.notes[0].scope, 'project:id:alpha', 'startup mapping scopes remembered note')
    assert.equal(saved.answer.notes[0].attributedTo, 'agent')
    const check = (mode, project) => {
      const reply = run(mode, project), answer = reply.answer
      assert.notEqual(reply.pid, saved.pid, 'project recall must restart in a fresh process')
      assert.deepEqual(answer.project, project === 'unmapped'
        ? { state: 'unmapped', reason: 'no-project-mapped', message: 'no project mapped' }
        : { state: 'mapped', scope: `project:id:${project}` }, `${mode} names mapped or unmapped project`)
      const notes = mode === 'service' ? answer.notes : answer.remembered.notes
      assert.equal(notes.length, project === 'alpha' ? 1 : 0, `${mode} does not cross project mapping`)
      if (project === 'alpha') {
        assert.equal(notes[0].id, saved.answer.ids[0]); assert.equal(notes[0].text, text)
        assert.equal(notes[0].grantsAuthority, false)
      }
    }
    for (const mode of ['tool', 'service']) for (const project of ['alpha', 'beta', 'unmapped']) check(mode, project)
    run('pre-step', 'unmapped')
    console.log('kira-project-mapping: 9 passed, 0 failed (fresh processes; two mapped projects, unmapped notice, isolated config, parent replacement refused; SOURCE fixtures, no installed containment)')
  } finally { rmSync(scratch, { recursive: true, force: true }) }
}
