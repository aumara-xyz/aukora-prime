#!/usr/bin/env node
/** Production identity/scope predicates with synthetic current-scheme notes.
 * SOURCE: no live workspace admission, note migration or owner review occurs. */
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { zstdCompressSync } from 'node:zlib'

const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
const mutations = {
  'unreviewed-aliases': ["if (aliasTable.status === 'owner-reviewed') reviewedAliases.set(entry.legacy_scope, alias)", 'reviewedAliases.set(entry.legacy_scope, alias)'],
  'alias-record-allowlist': ['alias.recordIds.has(String(note?.id ?? note?.recordId))', 'true'],
  'alias-canonical-unattached': ['(context?.attachedProjects ?? []).includes(alias.canonicalScope)', 'true'],
  'workspace-ambiguity': ["if (workspaceMap.has(root)) throw invalid('workspace-alias-ambiguous')", 'if (false) throw invalid(\'workspace-alias-ambiguous\')'],
  'unknown-workspace-fallback': ['if (!root || !workspaceMap.has(root)) return null', 'if (!root) return null; if (!workspaceMap.has(root)) return projects[0]?.project_id ?? null'],
  'missing-child-scope': ["    if (typeof run?.scope !== 'string' || run.scope === '') {\n      logger?.warn?.('aukora-kira: child capture deferred; retained scope unavailable')\n      return\n    }\n", '', 'memory-remembered-hook.mjs', ['scope: run.scope,', "scope: run?.scope ?? 'owner',"]],
  'unresolved-project-recovery': ["if (scope === 'project:unresolved') return", 'if (false) return', 'memory-remembered-hook.mjs'],
}
let mutated = 0
if (mutant !== null) {
  assert.ok(mutations[mutant], 'known production guard-removal control')
  const target = new URL(`../plugins/aukora-kira/lib/${mutations[mutant][2] ?? 'project-identity.mjs'}`, import.meta.url).href
  registerHooks({ load(url, context, nextLoad) {
    const loaded = nextLoad(url, context)
    if (url !== target) return loaded
    const source = String(loaded.source), [guard, removed, , additional] = mutations[mutant]
    assert.equal(source.split(guard).length - 1, 1, 'exact production mutation site')
    mutated++
    let changed = source.replace(guard, removed)
    if (additional) {
      assert.equal(changed.split(additional[0]).length - 1, 1, 'exact prior fallback restoration site')
      changed = changed.replace(additional[0], additional[1])
    }
    return { ...loaded, source: changed }
  } })
}
const { createProjectIdentityResolver, isProjectScopeAttached, stableProjectScope } = await import('../plugins/aukora-kira/lib/project-identity.mjs')
const { projectScopeOf, captureScopeOf, visibleRemembered, projectRecent, rememberedSnippet } = await import('../plugins/aukora-kira/lib/project-memory.mjs')
const { buildRememberedNote, recomputeNoteId, canonicalOf, sha256Hex } = await import('../plugins/aukora-kira/lib/memory-tiers.mjs')
const { filterMemoryRecords } = await import('../plugins/aukora-kira/lib/recall-filter/filter.mjs')
const { recallFilter, preTurnRecallFilter } = await import('../plugins/aukora-kira/lib/memory-frame.mjs')
const { registerRememberedCapture } = await import('../plugins/aukora-kira/lib/memory-remembered-hook.mjs')
const { recentSessionHeaders, readMemoryTurn } = await import('../plugins/aukora-kira/lib/session-read.mjs')
const subject = `aukora:1:${'7c'.repeat(32)}`, legacyScope = `project:${sha256Hex('/synthetic/previous/.git')}`
const roots = ['/synthetic/projects/observatory', '/synthetic/moved/observatory', '/synthetic/worktrees/observatory-fix']
const agentAt = cwd => ({ session: { id: 'synthetic-project-session', header: { cwd } } })
const noteAt = (index, scope = legacyScope) => {
  const statement = `Synthetic observatory finding ${index}: the calibration record is intact. 星🌒`
  return buildRememberedNote({ subject, scope, category: 'fact', statement, attributedTo: 'agent',
    evidence: [{ log: 'synthetic-only', turn: index + 1, turnDigest: 'fixture-unlinked', quote: statement }],
    validFrom: '2026-10-05', observedAt: '2026-10-05T00:00:00Z', confidence: 0.8, sensitivity: 'none', privacy: 'local',
    source: { state: 'UNLINKED', cited: false, because: 'synthetic current-scheme fixture; no session event claimed' },
    salt: sha256Hex(`synthetic-project-note-${index}`) })
}
const notes = Array.from({ length: 46 }, (_, index) => noteAt(index))
const policy = { subject, permittedPrivacy: ['local'] }
const configOf = (status = 'owner-reviewed') => ({ version: 1,
  projects: [{ project_id: 'observatory', workspace_roots: [...roots] }, { project_id: 'unrelated', workspace_roots: ['/synthetic/unrelated'] }],
  alias_table: { version: 1, status, ...(status === 'owner-reviewed' ? { review_id: 'synthetic-owner-review-only' } : {}),
    entries: [{ legacy_scope: legacyScope, project_id: 'observatory', record_ids: notes.map(note => note.id) }] } })
const governedContext = (resolver, agent) => ({ ...policy, ...resolver.contextFor(agent), nowMs: Date.parse('2026-10-05T12:00:00Z'),
  now: '2026-10-05T12:00:00Z', forgotten: new Set(), states: new Map() })
const filtered = (records, context) => {
  const report = { dropped: 0, reasons: {} }
  return { records: filterMemoryRecords(records, context, report), report }
}
const hookFixture = () => {
  const home = mkdtempSync(join(tmpdir(), 'kira-project-capture-'))
  const handlers = new Map(), warnings = [], remembered = [], captured = []
  const parent = agentAt(roots[0])
  let policyReads = 0
  const dispose = registerRememberedCapture({
    on: (name, handler) => { assert.equal(handlers.has(name), false); handlers.set(name, handler); return () => handlers.delete(name) },
    agents: { currentInitiator: () => parent }, logger: { warn: line => warnings.push(line) },
  }, {
    stateDir: join(home, 'kira-memory'), sessionsRoot: home, releaseRoot: join(home, 'release'),
    projectIdentity: createProjectIdentityResolver(configOf()),
    policyOf: async () => { policyReads++; return { subject, privacy: 'local' } },
    memory: { remember: async input => { remembered.push(input); return { remembered: 1 } },
      captureTurn: async (input, policy) => { captured.push({ input, policy }); return { remembered: 1 } } },
  })
  return { home, handlers, warnings, remembered, captured, policyReads: () => policyReads,
    cleanup: () => { dispose(); rmSync(home, { recursive: true, force: true }) } }
}
const writeSyntheticSession = (home, id, cwd) => {
  const file = join(home, 'sessions', 'synthetic-project', id, 'session.jsonl.zstd')
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  const events = [{ type: 'session', id, cwd, title: 'Synthetic scope fixture' },
    { type: 'user/message', seq: 1, time: 1_791_158_400_000,
      data: { id: `synthetic-${id}-ask`, source: { kind: 'user' }, content: `The synthetic observatory ${id} keeps calibration records.` } },
    { type: 'assistant/message', seq: 2, time: 1_791_158_400_001,
      data: { turn: 1, message: { role: 'assistant', source: { kind: 'model' },
        content: [{ type: 'text', text: `Synthetic finding for ${id}: calibration is intact.` }] } } }]
  writeFileSync(file, Buffer.concat(events.map(event => zstdCompressSync(Buffer.from(`${JSON.stringify(event)}\n`)))), { mode: 0o600 })
}
let passed = 0, total = 0
async function arm(name, run) {
  total++
  try { await run(); passed++; process.stdout.write(`PASS ${name}\n`) }
  catch (error) { process.exitCode = 1; process.stderr.write(`FAIL ${name}: ${error.message}\n`) }
}

await arm('stable identity survives explicit moves, worktrees and resolver recreation', () => {
  const config = configOf(), resolver = createProjectIdentityResolver(config)
  const expected = stableProjectScope('observatory')
  for (const root of roots) {
    assert.equal(projectScopeOf(agentAt(root), resolver), expected)
    assert.equal(projectScopeOf(agentAt(root + '/'), resolver), expected)
    assert.equal(projectScopeOf(agentAt(root + '/./'), resolver), expected)
    assert.equal(projectScopeOf(agentAt(root), createProjectIdentityResolver(structuredClone(config))), expected)
  }
  assert.equal(projectScopeOf(agentAt(roots[0] + '/nested'), resolver), null, 'a nested directory needs its own host binding')
  assert.equal(projectScopeOf(agentAt('/synthetic/not-configured'), resolver), null)
})
await arm('missing host identity refuses without cwd hashing or model metadata fallback', () => {
  assert.equal(projectScopeOf(agentAt(roots[0])), null)
  const resolver = createProjectIdentityResolver(configOf())
  assert.equal(projectScopeOf(agentAt('relative/path'), resolver), null)
  assert.equal(projectScopeOf({ session: { header: { project_id: 'observatory' } } }, resolver), null)
  assert.equal(projectScopeOf({ project_id: 'observatory', session: { header: { cwd: '/synthetic/unknown', projectScope: 'project:id:observatory' } } }, resolver), null)
  assert.deepEqual(createProjectIdentityResolver().contextFor(agentAt(roots[0])).attachedProjects, [])
  assert.equal(captureScopeOf(agentAt(roots[0])), 'project:unresolved')
  assert.equal(captureScopeOf(agentAt('/synthetic/unknown'), resolver), 'project:unresolved')
  assert.equal(captureScopeOf(agentAt(roots[0]), resolver), 'project:id:observatory')
  assert.equal(captureScopeOf({ session: { header: {} } }, resolver), 'owner')
  const unresolved = { ...notes[0], scope: captureScopeOf(agentAt(roots[0])) }
  assert.deepEqual(recallFilter(unresolved, governedContext(resolver, agentAt(roots[0]))), { ok: false, why: 'scope-not-attached' })
})
await arm('reviewed 46-record aliases pass real recall filters without altering historical bytes or IDs', () => {
  const before = notes.map(note => canonicalOf(note)), resolver = createProjectIdentityResolver(configOf())
  const context = governedContext(resolver, agentAt(roots[1]))
  assert.deepEqual(context.attachedProjects, ['project:id:observatory'], 'legacy scope is never blanket attached')
  assert.equal(filtered(notes, context).records.length, 46)
  assert.ok(notes.every(note => recallFilter(note, context).ok))
  assert.equal(visibleRemembered(notes, policy, projectScopeOf(agentAt(roots[1]), resolver), context).length, 46)
  const recent = projectRecent(notes, policy, 'project:id:observatory', new Map(), { projectContext: context })
  assert.equal(recent.availability, 'found'); assert.equal(recent.snippets.length, 3)
  const preview = resolver.previewMigration(notes, { expectedCount: 46 })
  assert.equal(preview.status, 'ready-for-review'); assert.equal(preview.writes, false); assert.equal(preview.grantsAuthority, false)
  assert.equal(preview.mappings.length, 46)
  assert.ok(preview.mappings.every(one => one.to_scope === 'project:id:observatory' && one.preserve_record_id && one.preserve_canonical_bytes))
  assert.deepEqual(notes.map(note => canonicalOf(note)), before)
  assert.ok(notes.every(note => recomputeNoteId(note) === note.id))
})
await arm('unreviewed, unlisted and detached aliases retain scope-not-attached', () => {
  const resolver = createProjectIdentityResolver(configOf()), unlisted = noteAt(46)
  for (const [note, context] of [
    [notes[0], governedContext(createProjectIdentityResolver(configOf('draft')), agentAt(roots[0]))],
    [unlisted, governedContext(resolver, agentAt(roots[0]))],
    [notes[0], governedContext(resolver, agentAt('/synthetic/unrelated'))],
    [notes[0], governedContext(resolver, agentAt('/synthetic/unknown'))],
  ]) {
    assert.equal(isProjectScopeAttached(note, context), false)
    assert.deepEqual(recallFilter(note, context), { ok: false, why: 'scope-not-attached' })
    const result = filtered([note], context)
    assert.equal(result.records.length, 0); assert.equal(result.report.reasons['scope-not-attached'], 1)
  }
})
await arm('ambiguous paths, aliases and record mappings fail normalization', () => {
  let config = configOf(); config.projects[1].workspace_roots.push(roots[0])
  assert.throws(() => createProjectIdentityResolver(config), /workspace-alias-ambiguous/u)
  config = configOf(); config.projects[1].workspace_roots.push(roots[0] + '/')
  assert.throws(() => createProjectIdentityResolver(config), /workspace-alias-ambiguous/u)
  config = configOf(); config.projects.push({ project_id: 'observatory', workspace_roots: ['/synthetic/other'] })
  assert.throws(() => createProjectIdentityResolver(config), /project-id-ambiguous/u)
  config = configOf(); config.alias_table.entries.push(structuredClone(config.alias_table.entries[0]))
  assert.throws(() => createProjectIdentityResolver(config), /legacy-alias-ambiguous/u)
  config = configOf(); config.alias_table.entries.push({ legacy_scope: `project:${'9e'.repeat(32)}`, project_id: 'unrelated', record_ids: [notes[0].id] })
  assert.throws(() => createProjectIdentityResolver(config), /alias-record-ambiguous/u)
  config = configOf(); delete config.alias_table.review_id
  assert.throws(() => createProjectIdentityResolver(config), /alias-review-missing/u)
})
await arm('configuration snapshot and immutable alias view prevent later widening', () => {
  const config = configOf(), resolver = createProjectIdentityResolver(config), context = governedContext(resolver, agentAt(roots[0]))
  config.projects[0].workspace_roots.push('/synthetic/not-configured')
  config.alias_table.entries[0].record_ids.push(noteAt(46).id)
  assert.equal(resolver.scopeOf(agentAt('/synthetic/not-configured')), null)
  assert.equal(isProjectScopeAttached(noteAt(46), context), false)
  assert.throws(() => context.projectAliases[0].record_ids.push(noteAt(46).id), TypeError)
  assert.equal(isProjectScopeAttached(notes[0], { ...context, projectAliases: structuredClone(context.projectAliases) }), false)
})
await arm('migration preview is incomplete for missing review, unmapped IDs or count disagreement', () => {
  const resolver = createProjectIdentityResolver(configOf())
  assert.equal(resolver.previewMigration(notes, { expectedCount: 47 }).status, 'incomplete')
  const incomplete = resolver.previewMigration([...notes, noteAt(46)], { expectedCount: 47 })
  assert.equal(incomplete.status, 'incomplete'); assert.equal(incomplete.unresolved.length, 1)
  assert.equal(createProjectIdentityResolver(configOf('draft')).previewMigration(notes, { expectedCount: 46 }).mappings.length, 0)
  assert.throws(() => resolver.previewMigration([...notes, notes[0]]), /migration-record-invalid/u)
})
await arm('owner notes survive absent project attachment while privacy and pre-turn policy remain intact', () => {
  const resolver = createProjectIdentityResolver(configOf()), context = governedContext(resolver, agentAt('/synthetic/unknown'))
  const ownerNote = noteAt(47, 'owner')
  assert.equal(filtered([ownerNote], context).records.length, 1)
  assert.equal(visibleRemembered([ownerNote], policy, null, context).length, 1)
  const attached = governedContext(resolver, agentAt(roots[0]))
  assert.equal(filtered([{ ...notes[0], privacy: 'private' }], attached).records.length, 0)
  assert.deepEqual(preTurnRecallFilter(notes[0], attached), { ok: false, why: 'model-authored-never-pre-turn' })
  assert.deepEqual(recallFilter({ ...notes[0], category: 'instruction' }, attached), { ok: false, why: 'instruction-never-pre-turn' })
  assert.equal(projectRecent(notes, policy, null).availability, 'undetermined')
})
await arm('project selection cannot be widened by a different or multiple attached project context', () => {
  const resolver = createProjectIdentityResolver(configOf()), unrelated = noteAt(48, 'project:id:unrelated')
  const context = governedContext(resolver, agentAt('/synthetic/unrelated'))
  assert.equal(projectRecent([unrelated], policy, 'project:id:observatory', new Map(), { projectContext: context }).snippets.length, 0)
  assert.equal(visibleRemembered([unrelated], policy, 'project:id:observatory', context).length, 0)
  const multiple = { ...governedContext(resolver, agentAt(roots[0])), attachedProjects: ['project:id:observatory', 'project:id:unrelated'] }
  assert.equal(projectRecent([...notes, unrelated], policy, 'project:id:observatory', new Map(), { projectContext: multiple }).snippets.length, 3)
  assert.ok(projectRecent([...notes, unrelated], policy, 'project:id:observatory', new Map(), { projectContext: multiple }).snippets.every(one => one.scope === legacyScope))
})
await arm('project snippet preserves typed parent and displayed UTF8 hash domains', () => {
  const statement = 'A'.repeat(599) + '🌒' + ' calibration remains intact. 星'
  const note = { ...notes[0], statement, text: statement, contentHash: sha256Hex(statement) }
  const snippet = rememberedSnippet(note)
  assert.equal(snippet.text, 'A'.repeat(599), 'truncation cannot display half a surrogate')
  assert.equal(snippet.statementHash, sha256Hex(statement)); assert.equal(snippet.contentHash, sha256Hex(statement))
  assert.equal(snippet.partHash, sha256Hex(snippet.text))
  assert.deepEqual(snippet.byteRange, { start: 0, end: 599, unit: 'utf8-bytes' })
  assert.notEqual(snippet.partHash, snippet.statementHash)
})
await arm('actual child capture defers missing retained scope and preserves a known run scope', async () => {
  const fixture = hookFixture()
  try {
    const completed = { runId: 'synthetic-run', id: 'synthetic-child', provider: 'synthetic-only', stopReason: 'completed',
      lastAssistantMessage: [{ type: 'text', text: 'The synthetic calibration report is intact.' }] }
    await fixture.handlers.get('subagent/end')(completed)
    assert.equal(fixture.remembered.length, 0, 'a missing start cannot become owner memory')
    assert.equal(fixture.policyReads(), 0, 'no memory policy/store resolution before retained scope exists')
    assert.deepEqual(fixture.warnings, ['aukora-kira: child capture deferred; retained scope unavailable'])
    await fixture.handlers.get('subagent/start')({ runId: completed.runId })
    await fixture.handlers.get('subagent/end')(completed)
    assert.equal(fixture.remembered.length, 1)
    assert.equal(fixture.remembered[0].scope, 'project:id:observatory')
    assert.equal(fixture.remembered[0].source.state, 'UNLINKED', 'host summary does not invent a session receipt')
    await fixture.handlers.get('subagent/end')(completed)
    assert.equal(fixture.remembered.length, 1, 'consumed run cannot capture again using owner fallback')
  } finally { fixture.cleanup() }
})
await arm('actual recovery skips unresolved projects while resolved identity still reads its own synthetic history', async () => {
  const fixture = hookFixture()
  try {
    writeSyntheticSession(fixture.home, 'synthetic-unmapped-alpha', '/synthetic/unmapped-alpha')
    writeSyntheticSession(fixture.home, 'synthetic-unmapped-beta', '/synthetic/unmapped-beta')
    writeSyntheticSession(fixture.home, 'synthetic-known-observatory', roots[0])
    assert.equal(recentSessionHeaders(fixture.home).length, 3, 'readable native-shaped fixtures are present')
    assert.equal(readMemoryTurn({ stateRoot: fixture.home, sessionId: 'synthetic-unmapped-alpha' }).findings.length, 1,
      'guard removal has actual historical text available to capture')
    await fixture.handlers.get('agent/created')({ agent: agentAt('/synthetic/unmapped-alpha') })
    await fixture.handlers.get('agent/created')({ agent: agentAt('/synthetic/unmapped-beta') })
    assert.equal(fixture.captured.length, 0, 'unknown projects cannot coalesce into one recovery bucket')
    assert.equal(fixture.policyReads(), 0)
    await fixture.handlers.get('agent/created')({ agent: agentAt(roots[1]) })
    assert.equal(fixture.captured.length, 2, 'resolved moved workspace recovers its owner turn and finding')
    assert.ok(fixture.captured.every(one => one.policy.scope === 'project:id:observatory'
      && one.input.sessionId === 'synthetic-known-observatory'))
    assert.deepEqual(fixture.warnings, [])
  } finally { fixture.cleanup() }
})
if (mutant !== null) assert.equal(mutated, 1, 'actual production module was mutated')
process.stdout.write(`${passed}/${total} project identity SOURCE groups passed${mutant === null ? '' : `; mutant=${mutant}`}\n`)
