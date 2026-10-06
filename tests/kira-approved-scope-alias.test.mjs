#!/usr/bin/env node
/** Approved read-time scope projection against real Kira filters.
 * SOURCE fixtures only: no store, network, body reader, scratch files or cleanup.
 * Counts mirror the supplied metadata; all note statements below are synthetic. */
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { readFileSync } from 'node:fs'

const OLD_SCOPE = 'project:982deb07dba176b9f2b8bccaffec69e2f3f6421e13c993374edf9e226da1e45c'
const TARGET_SCOPE = 'project:ed9da107b1a136deb7876daa6602e67ade729ad169f5f2c4bbfd79745ce2c74b'
const OTHER_SCOPE = `project:${'ac'.repeat(32)}`
const THIRD_SCOPE = `project:${'bd'.repeat(32)}`
const REVIEW_ID = 'Sentinel_0f53fd759a488191b666f258b74f89c5'

// Focused controls replace production predicates in memory. No production
// module is edited and no test expectation is removed.
const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
const lookup = 'aliasViews.get(context?.projectAliases)?.get(scope)'
const mutations = {
  'scope-exact-match': [lookup,
    '(aliasViews.get(context?.projectAliases)?.get(scope) ?? [...(aliasViews.get(context?.projectAliases)?.values() ?? [])][0])'],
  'target-currently-attached': ['(context?.attachedProjects ?? []).includes(alias.canonicalScope)', 'true'],
  'unreviewed-scope-alias': ["if (config.status === 'owner-reviewed') reviewed.set(entry.from_scope, {", 'reviewed.set(entry.from_scope, {'],
  'branded-alias-view': [lookup,
    "(aliasViews.get(context?.projectAliases)?.get(scope) ?? (() => { const raw = context?.projectAliases?.find(entry => entry.legacy_scope === scope); return raw ? { canonicalScope: raw.canonical_scope, scopeWide: raw.scope_wide, recordIds: new Set(raw.record_ids ?? []) } : null })())"],
  'existing-alias-collision': ["if (aliases.has(from)) throw invalid('alias-view-ambiguous')", "if (false) throw invalid('alias-view-ambiguous')"],
  'attachment-snapshot': ['attachedProjects: Object.freeze([...attached])', 'attachedProjects: Object.freeze(attached)'],
  'record-specific-allowlist': ['alias.recordIds.has(String(note?.id ?? note?.recordId))', 'true'],
}
let mutationApplied = 0
if (mutant !== null) {
  assert.ok(mutations[mutant], 'known focused production mutation')
  const [guard, removed] = mutations[mutant]
  const target = new URL('../plugins/aukora-kira/lib/project-identity.mjs', import.meta.url).href
  registerHooks({ load(url, context, nextLoad) {
    const loaded = nextLoad(url, context)
    if (url !== target) return loaded
    const source = String(loaded.source)
    assert.equal(source.split(guard).length - 1, 1, 'exact production guard-removal site')
    mutationApplied++
    return { ...loaded, source: source.replace(guard, removed) }
  } })
}

const { createApprovedScopeAliasResolver, createProjectIdentityResolver, createProjectReadContextResolver, isProjectScopeAttached, resolvedProjectScopeOf } =
  await import('../plugins/aukora-kira/lib/project-identity.mjs')
const { captureScopeOf, visibleRemembered, projectRecent } = await import('../plugins/aukora-kira/lib/project-memory.mjs')
const { recallFilter, preTurnRecallFilter } = await import('../plugins/aukora-kira/lib/memory-frame.mjs')
const { filterMemoryRecords } = await import('../plugins/aukora-kira/lib/recall-filter/filter.mjs')
const { buildRememberedNote, canonicalOf, recomputeNoteId, sha256Hex } =
  await import('../plugins/aukora-kira/lib/memory-tiers.mjs')

const subject = `aukora:1:${'8d'.repeat(32)}`
const policy = { subject, permittedPrivacy: ['local'] }
const noteAt = (index, scope = OLD_SCOPE, attributedTo = 'agent') => {
  const statement = `Synthetic alias finding ${index}: the observatory calibration remains intact. 星🌒`
  return buildRememberedNote({ subject, scope, attributedTo, statement,
    category: 'fact', evidence: [{ log: 'synthetic-only', turn: index + 1,
      turnDigest: 'synthetic-unlinked', quote: statement }],
    validFrom: '2026-10-04', observedAt: `2026-10-04T00:${String(Math.floor(index / 60) % 60).padStart(2, '0')}:${String(index % 60).padStart(2, '0')}Z`,
    confidence: 0.8, sensitivity: 'none', privacy: 'local',
    source: { state: 'UNLINKED', cited: false, because: 'synthetic alias fixture; no session receipt claimed' },
    salt: sha256Hex(`synthetic-approved-scope-${index}-${scope}-${attributedTo}`) })
}
const oldNotes = Array.from({ length: 46 }, (_, index) => noteAt(index, OLD_SCOPE, index < 38 ? 'agent' : 'owner'))
const targetNotes = Array.from({ length: 85 }, (_, index) => noteAt(100 + index, TARGET_SCOPE))
const allNotes = [...oldNotes, ...targetNotes]
const filtered = (records, context) => {
  const report = { dropped: 0, reasons: {} }
  return { records: filterMemoryRecords(records, context, report), report }
}
const governed = context => ({ ...policy, nowMs: Date.parse('2026-10-06T00:41:00Z'),
  now: '2026-10-06T00:41:00Z', forgotten: new Set(), states: new Map(), ...context })
const configOf = (status = 'owner-reviewed') => ({ version: 1, status,
  ...(status === 'owner-reviewed' ? { review_id: REVIEW_ID } : {}),
  entries: [{ from_scope: OLD_SCOPE, to_scope: TARGET_SCOPE }] })
const approvedContext = (attachedProjects = [TARGET_SCOPE], config = configOf()) =>
  governed(createApprovedScopeAliasResolver(config).contextFor({ attachedProjects }))
const refusedByEveryRead = (note, context, selectedScope = context.attachedProjects[0] ?? TARGET_SCOPE) => {
  assert.equal(isProjectScopeAttached(note, context), false)
  assert.equal(resolvedProjectScopeOf(note, context), null)
  assert.deepEqual(recallFilter(note, context), { ok: false, why: 'scope-not-attached' })
  const answer = filtered([note], context)
  assert.equal(answer.records.length, 0)
  assert.deepEqual(answer.report, { dropped: 1, reasons: { 'scope-not-attached': 1 } })
  assert.equal(visibleRemembered([note], policy, selectedScope, context).length, 0)
  assert.equal(projectRecent([note], policy, selectedScope, new Map(), { projectContext: context }).snippets.length, 0)
}
let passed = 0, total = 0
async function arm(name, run) {
  total++
  try { await run(); passed++; process.stdout.write(`PASS ${name}\n`) }
  catch (error) { process.exitCode = 1; process.stderr.write(`FAIL ${name}: ${error.message}\n`) }
}

await arm('exact approved old scope joins only the already attached target in real recall paths', () => {
  const context = approvedContext(), before = allNotes.map(canonicalOf)
  assert.equal(oldNotes.length, 46); assert.equal(targetNotes.length, 85)
  assert.deepEqual(context.attachedProjects, [TARGET_SCOPE], 'the alias cannot attach its source or target')
  assert.equal(filtered(allNotes, context).records.length, 131, 'synthetic fixture count only, not live memory acceptance')
  assert.ok(allNotes.every(note => recallFilter(note, context).ok))
  assert.equal(visibleRemembered(allNotes, policy, TARGET_SCOPE, context).length, 131)
  const recent = projectRecent(oldNotes, policy, TARGET_SCOPE, new Map(), { projectContext: context })
  assert.equal(recent.availability, 'found'); assert.equal(recent.snippets.length, 3)
  assert.ok(recent.snippets.every(note => note.scope === OLD_SCOPE), 'historical scopes are retained in projected snippets')
  assert.equal(resolvedProjectScopeOf(oldNotes[0], context), TARGET_SCOPE)
  assert.equal(resolvedProjectScopeOf(targetNotes[0], context), TARGET_SCOPE)
  assert.deepEqual(allNotes.map(canonicalOf), before, 'read-time resolution changes no canonical field')
  assert.ok(allNotes.every(note => recomputeNoteId(note) === note.id))
  assert.ok(allNotes.every(note => note.grantsAuthority === false))
})
await arm('prepared metadata-only preview consumes the same exact reviewed factory contract', () => {
  const config = JSON.parse(readFileSync(new URL('../plugins/aukora-kira/docs/owner-review-46-note-alias.preview.json', import.meta.url), 'utf8'))
  assert.deepEqual(config, configOf(), 'preview artifact contains only the exact supplied pair and owner review reference')
  const resolver = createApprovedScopeAliasResolver(config)
  const context = governed(resolver.contextFor({ attachedProjects: [TARGET_SCOPE] }))
  assert.equal(filtered(allNotes, context).records.length, 131, 'in-memory synthetic source qualification only')
  assert.equal(visibleRemembered(oldNotes, policy, TARGET_SCOPE, context).length, 46)
  assert.deepEqual(context.attachedProjects, [TARGET_SCOPE])
  refusedByEveryRead(noteAt(234, OTHER_SCOPE), context)
  refusedByEveryRead(targetNotes[0], governed(resolver.contextFor({ attachedProjects: [OLD_SCOPE] })), OLD_SCOPE)
  assert.equal(resolver.description.writes, false); assert.equal(resolver.description.grantsAuthority, false)
})
await arm('trusted read composition uses existing attachment without changing capture identity', () => {
  const projectIdentity = createProjectIdentityResolver({ version: 1,
    projects: [{ project_id: 'synthetic-project', workspace_roots: ['/synthetic/read-composition'] }] })
  const agent = { session: { header: { cwd: '/synthetic/read-composition' } } }
  const attached = [TARGET_SCOPE], host = {
    contextFor(selected) { assert.equal(selected, agent); return { attachedProjects: attached } },
    scopeFor(selected) { assert.equal(selected, agent); return TARGET_SCOPE },
  }
  const reads = createProjectReadContextResolver({ projectIdentity,
    approvedScopeAliases: createApprovedScopeAliasResolver(configOf()), host })
  const context = governed(reads.contextFor(agent))
  assert.equal(reads.scopeOf(agent), TARGET_SCOPE)
  assert.equal(visibleRemembered(oldNotes, policy, reads.scopeOf(agent), context).length, 46)
  assert.deepEqual(context.attachedProjects, [TARGET_SCOPE])
  assert.equal(captureScopeOf(agent, projectIdentity), 'project:id:synthetic-project')
  host.contextFor = () => ({ attachedProjects: [OTHER_SCOPE] })
  host.scopeFor = () => OTHER_SCOPE
  assert.equal(reads.scopeOf(agent), TARGET_SCOPE, 'host callback identities are captured at composition')
  assert.equal(Object.isFrozen(attached), false, 'read projection never freezes the host attachment list')
  attached[0] = OTHER_SCOPE
  assert.deepEqual(context.attachedProjects, [TARGET_SCOPE], 'existing read snapshots remain unchanged')
  refusedByEveryRead(oldNotes[0], governed(reads.contextFor(agent)))
})
await arm('config alone and a selected scope cannot create the target attachment', () => {
  const projectIdentity = createProjectIdentityResolver({ version: 1,
    projects: [{ project_id: 'synthetic-project', workspace_roots: ['/synthetic/read-composition'] }] })
  const agent = { session: { header: { cwd: '/synthetic/read-composition' } } }
  const approvedScopeAliases = createApprovedScopeAliasResolver(configOf())
  const defaults = createProjectReadContextResolver({ projectIdentity, approvedScopeAliases })
  assert.equal(defaults.scopeOf(agent), 'project:id:synthetic-project')
  const context = governed(defaults.contextFor(agent))
  assert.deepEqual(context.attachedProjects, ['project:id:synthetic-project'])
  refusedByEveryRead(oldNotes[0], context)
  const selectedOnly = createProjectReadContextResolver({ projectIdentity, approvedScopeAliases,
    host: { contextFor: () => ({ attachedProjects: [] }), scopeFor: () => TARGET_SCOPE } })
  assert.equal(selectedOnly.scopeOf(agent), TARGET_SCOPE)
  refusedByEveryRead(oldNotes[0], governed(selectedOnly.contextFor(agent)))
})
await arm('trusted project adapter cannot override owner policy or session bindings', () => {
  const approvedScopeAliases = createApprovedScopeAliasResolver(configOf())
  for (const host of [null, {}, { contextFor() {} }, { contextFor() {}, scopeFor() {}, extra: true }])
    assert.throws(() => createProjectReadContextResolver({ approvedScopeAliases, host }), /project-read-host-invalid/u)
  for (const field of ['subject', 'permittedPrivacy', 'sessionId', 'owner', 'policyRevision']) {
    const reads = createProjectReadContextResolver({ approvedScopeAliases,
      host: { scopeFor: () => TARGET_SCOPE, contextFor: () => ({ attachedProjects: [TARGET_SCOPE], [field]: 'synthetic-canary' }) } })
    assert.throws(() => reads.contextFor({}), /project-read-context-invalid/u)
  }
  const invalidScope = createProjectReadContextResolver({ approvedScopeAliases,
    host: { scopeFor: () => 'owner', contextFor: () => ({ attachedProjects: [TARGET_SCOPE] }) } })
  assert.throws(() => invalidScope.scopeOf({}), /project-read-scope-invalid/u)
})
await arm('one-way mapping refuses reverse target lookup from the old attached project', () => {
  const context = approvedContext([OLD_SCOPE])
  assert.equal(filtered(oldNotes, context).records.length, 46, 'ordinary direct source attachment still works')
  refusedByEveryRead(targetNotes[0], context, OLD_SCOPE)
})
await arm('unrelated project notes remain scope-not-attached under the approved target', () => {
  const context = approvedContext()
  for (const scope of [OTHER_SCOPE, THIRD_SCOPE, 'project:id:unrelated', 'project:unresolved'])
    refusedByEveryRead(noteAt(220, scope), context)
})
await arm('mapping requires the exact target currently attached and never creates an attachment', () => {
  for (const attached of [[], [OTHER_SCOPE], [`${TARGET_SCOPE}/child`], [TARGET_SCOPE.toUpperCase()]]) {
    const context = approvedContext(attached)
    assert.deepEqual(context.attachedProjects, attached)
    refusedByEveryRead(oldNotes[0], context)
  }
})
await arm('source matching is exact, without prefix, suffix, case or whitespace widening', () => {
  const context = approvedContext()
  for (const scope of [OLD_SCOPE.slice(0, -1), `${OLD_SCOPE}0`, `${OLD_SCOPE}/child`, OLD_SCOPE.toUpperCase(), ` ${OLD_SCOPE}`, `${OLD_SCOPE} `])
    refusedByEveryRead(noteAt(221, scope), context)
})
await arm('draft and missing approval leave old records withheld in every read path', () => {
  const draft = approvedContext([TARGET_SCOPE], configOf('draft'))
  refusedByEveryRead(oldNotes[0], draft)
  const empty = governed(createApprovedScopeAliasResolver().contextFor({ attachedProjects: [TARGET_SCOPE] }))
  refusedByEveryRead(oldNotes[0], empty)
  assert.equal(filtered(targetNotes, empty).records.length, 85, 'direct attachment does not depend on aliases')
  assert.throws(() => createApprovedScopeAliasResolver({ ...configOf(), review_id: '' }), /alias-review-missing/u)
})
await arm('later config and attachment mutations cannot widen an existing context', () => {
  const config = configOf(), attached = [TARGET_SCOPE]
  const resolver = createApprovedScopeAliasResolver(config)
  const context = governed(resolver.contextFor({ attachedProjects: attached, sessionId: 'synthetic-host-session' }))
  assert.equal(Object.isFrozen(attached), false, 'snapshot does not mutate or freeze the caller host attachment list')
  config.entries[0].from_scope = OTHER_SCOPE; config.entries[0].to_scope = THIRD_SCOPE
  config.status = 'draft'; config.review_id = 'synthetic-edited-review'
  attached[0] = THIRD_SCOPE; attached.push(OTHER_SCOPE)
  assert.deepEqual(context.attachedProjects, [TARGET_SCOPE])
  assert.equal(context.sessionId, 'synthetic-host-session')
  assert.equal(resolvedProjectScopeOf(oldNotes[0], context), TARGET_SCOPE)
  refusedByEveryRead(noteAt(222, OTHER_SCOPE), context)
  assert.deepEqual(resolver.description.entries, [{ from_scope: OLD_SCOPE, to_scope: TARGET_SCOPE }])
  assert.equal(resolver.description.review_id, REVIEW_ID)
  assert.equal(resolver.description.writes, false); assert.equal(resolver.description.grantsAuthority, false)
  assert.throws(() => context.projectAliases.push({}), TypeError)
  assert.throws(() => { context.projectAliases[0].canonical_scope = THIRD_SCOPE }, TypeError)
  assert.throws(() => resolver.description.entries.push({}), TypeError)
})
await arm('unbranded cloned or constructed alias views cannot authorize a lookup', () => {
  const context = approvedContext()
  for (const projectAliases of [structuredClone(context.projectAliases),
    [{ legacy_scope: OLD_SCOPE, canonical_scope: TARGET_SCOPE, scope_wide: true }],
    [{ legacy_scope: OLD_SCOPE, canonical_scope: TARGET_SCOPE, record_ids: [oldNotes[0].id] }]])
    refusedByEveryRead(oldNotes[0], { ...context, projectAliases })
})
await arm('scope alias composition preserves existing exact-record alias guards', () => {
  const recordScope = `project:${'ce'.repeat(32)}`, listed = noteAt(230, recordScope), unlisted = noteAt(231, recordScope)
  const identity = createProjectIdentityResolver({ version: 1,
    projects: [{ project_id: 'synthetic-project', workspace_roots: ['/synthetic/approved-alias'] }],
    alias_table: { version: 1, status: 'owner-reviewed', review_id: 'synthetic-record-review',
      entries: [{ legacy_scope: recordScope, project_id: 'synthetic-project', record_ids: [listed.id] }] } })
  const previous = identity.contextFor({ session: { header: { cwd: '/synthetic/approved-alias' } } })
  const context = governed(createApprovedScopeAliasResolver(configOf()).contextFor({ ...previous,
    attachedProjects: [...previous.attachedProjects, TARGET_SCOPE] }))
  assert.equal(resolvedProjectScopeOf(listed, context), 'project:id:synthetic-project')
  assert.equal(filtered([listed], context).records.length, 1)
  refusedByEveryRead(unlisted, context, 'project:id:synthetic-project')
  assert.equal(resolvedProjectScopeOf(oldNotes[0], context), TARGET_SCOPE)
  const detached = { ...context, attachedProjects: [TARGET_SCOPE] }
  refusedByEveryRead(listed, detached)
})
await arm('an approved scope alias cannot overwrite a previous record-specific alias', () => {
  const identity = createProjectIdentityResolver({ version: 1,
    projects: [{ project_id: 'synthetic-project', workspace_roots: ['/synthetic/approved-alias'] }],
    alias_table: { version: 1, status: 'owner-reviewed', review_id: 'synthetic-record-review',
      entries: [{ legacy_scope: OLD_SCOPE, project_id: 'synthetic-project', record_ids: [oldNotes[0].id] }] } })
  const previous = identity.contextFor({ session: { header: { cwd: '/synthetic/approved-alias' } } })
  assert.throws(() => createApprovedScopeAliasResolver(configOf()).contextFor({ ...previous,
    attachedProjects: [...previous.attachedProjects, TARGET_SCOPE] }), /alias-view-ambiguous/u)
  assert.equal(isProjectScopeAttached(oldNotes[1], previous), false, 'collision failure preserves the older exact-record guard')
})
await arm('read-time aliases do not follow chains or create reverse links', () => {
  const resolver = createApprovedScopeAliasResolver({ ...configOf(),
    entries: [{ from_scope: OLD_SCOPE, to_scope: TARGET_SCOPE }, { from_scope: TARGET_SCOPE, to_scope: OTHER_SCOPE }] })
  const context = governed(resolver.contextFor({ attachedProjects: [OTHER_SCOPE] }))
  refusedByEveryRead(oldNotes[0], context, OTHER_SCOPE)
  assert.equal(resolvedProjectScopeOf(targetNotes[0], context), OTHER_SCOPE, 'only the separately supplied direct edge resolves')
  const reverse = approvedContext([OLD_SCOPE])
  refusedByEveryRead(noteAt(232, OTHER_SCOPE), reverse, OLD_SCOPE)
})
await arm('project selection remains narrow with multiple attached projects', () => {
  const context = approvedContext([TARGET_SCOPE, OTHER_SCOPE]), other = noteAt(233, OTHER_SCOPE)
  assert.equal(filtered([other], context).records.length, 1, 'host still directly attaches its other project')
  assert.equal(visibleRemembered([...oldNotes, other], policy, TARGET_SCOPE, context).length, 46)
  assert.equal(visibleRemembered([...oldNotes, other], policy, OTHER_SCOPE, context).length, 1)
  const recent = projectRecent([...oldNotes, other], policy, TARGET_SCOPE, new Map(), { projectContext: context })
  assert.equal(recent.snippets.length, 3); assert.ok(recent.snippets.every(note => note.scope === OLD_SCOPE))
  assert.equal(projectRecent([other], policy, TARGET_SCOPE, new Map(), { projectContext: context }).snippets.length, 0)
})
await arm('subject privacy state and automatic pre-turn guards remain in force', () => {
  const context = approvedContext()
  for (const [note, reason] of [
    [{ ...oldNotes[0], subject: `aukora:1:${'9e'.repeat(32)}` }, 'subject-out-of-scope'],
    [{ ...oldNotes[0], privacy: 'private' }, 'privacy-out-of-scope'],
    [{ ...oldNotes[0], consent: 'hidden' }, 'hidden'],
  ]) {
    const answer = filtered([note], context)
    assert.equal(answer.records.length, 0); assert.equal(answer.report.reasons[reason], 1)
  }
  const hidden = { ...context, states: new Map([[oldNotes[0].id, 'hidden']]) }
  assert.equal(filtered([oldNotes[0]], hidden).report.reasons.hidden, 1)
  assert.deepEqual(recallFilter(oldNotes[0], hidden), { ok: false, why: 'hidden-not-recallable' })
  assert.deepEqual(preTurnRecallFilter(oldNotes[0], context), { ok: false, why: 'model-authored-never-pre-turn' })
  assert.deepEqual(recallFilter({ ...oldNotes[0], category: 'instruction' }, context), { ok: false, why: 'instruction-never-pre-turn' })
  assert.equal(preTurnRecallFilter(oldNotes[38], context).ok, true, 'owner observations retain normal pre-turn eligibility')
})
await arm('closed review input rejects nonproject wildcard ambiguous and overbroad entries', () => {
  for (const from_scope of ['owner', 'agent', 'project:*', 'project:id:synthetic', OLD_SCOPE.toUpperCase(), `${OLD_SCOPE}/child`])
    assert.throws(() => createApprovedScopeAliasResolver({ ...configOf(), entries: [{ from_scope, to_scope: TARGET_SCOPE }] }), /scope-alias-entry-invalid/u)
  for (const to_scope of ['owner', 'agent', 'project:*', 'project:id:synthetic', OLD_SCOPE])
    assert.throws(() => createApprovedScopeAliasResolver({ ...configOf(), entries: [{ from_scope: OLD_SCOPE, to_scope }] }), /scope-alias-entry-invalid/u)
  assert.throws(() => createApprovedScopeAliasResolver({ ...configOf(), entries: [configOf().entries[0], configOf().entries[0]] }), /scope-alias-source-ambiguous/u)
  assert.throws(() => createApprovedScopeAliasResolver({ ...configOf(), all_projects: true }), /scope-alias-configuration-invalid/u)
  assert.throws(() => createApprovedScopeAliasResolver({ ...configOf(), entries: [{ ...configOf().entries[0], rewrite: true }] }), /scope-alias-entry-invalid/u)
})
if (mutant !== null) assert.equal(mutationApplied, 1, 'actual production module was mutated exactly once')
process.stdout.write(`${passed}/${total} approved scope alias SOURCE groups passed${mutant === null ? '' : `; mutant=${mutant}`}\n`)
