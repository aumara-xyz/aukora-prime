/** Project identity is supplied by the trusted host composition. A directory is
 * an attachment to that identity, never the identity itself. This module does
 * not read Git, project files, memory or owner credentials and performs no writes.
 * Owner review is an input to the host's configuration, not verified here. */
import { isAbsolute, normalize, parse, sep } from 'node:path'

const PROJECT_ID = /^[a-z0-9][a-z0-9._-]{0,79}$/u
const LEGACY_SCOPE = /^project:[0-9a-f]{64}$/u
const RECORD_ID = /^(?:rem|kira):[0-9a-f]{64}$/u
const aliasViews = new WeakMap()
const invalid = code => new Error(`kira.project-identity:${code}`)
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value))
const text = value => typeof value === 'string' && value === value.trim()
  && value.length > 0 && !/[\u0000-\u001f\u007f]/u.test(value)
const pathOf = value => {
  if (!text(value) || !isAbsolute(value)) return null
  let root = normalize(value)
  const minimum = parse(root).root.length
  while (root.length > minimum && root.endsWith(sep)) root = root.slice(0, -1)
  return root
}

export function stableProjectScope(projectId) {
  if (typeof projectId !== 'string' || !PROJECT_ID.test(projectId)) throw invalid('project-id-invalid')
  return `project:id:${projectId}`
}

/** Existing owner/agent/direct attachment stays intact. Record-specific aliases
 * still require the reviewed record ID; separately reviewed scope aliases use
 * an exact source scope. Both require the target to be currently attached.
 * The derived view does not edit the historical note or its ID. */
export function isProjectScopeAttached(note, context) {
  const scope = String(note?.scope ?? 'owner')
  if (scope === 'owner' || scope === 'agent' || (context?.attachedProjects ?? []).includes(scope)) return true
  return resolvedProjectScopeOf(note, context) !== null
}

/** The effective project is a read projection. It never replaces the original
 * scope in the record whose historical ID and bytes were committed. */
export function resolvedProjectScopeOf(note, context) {
  const scope = String(note?.scope ?? 'owner')
  if (scope === 'owner' || scope === 'agent') return null
  if ((context?.attachedProjects ?? []).includes(scope)) return scope
  const alias = aliasViews.get(context?.projectAliases)?.get(scope)
  return alias && (alias.scopeWide === true || alias.recordIds.has(String(note?.id ?? note?.recordId)))
    && (context?.attachedProjects ?? []).includes(alias.canonicalScope) ? alias.canonicalScope : null
}

const aliasViewOf = aliases => {
  const view = Object.freeze([...aliases].map(([legacyScope, alias]) => Object.freeze({
    legacy_scope: legacyScope, canonical_scope: alias.canonicalScope,
    ...(alias.scopeWide === true ? { scope_wide: true } : { record_ids: Object.freeze([...alias.recordIds]) }),
  })))
  aliasViews.set(view, aliases)
  return view
}

/** An explicitly reviewed, one-way alias between existing hashed project
 * scopes. This decorates a trusted host read context; it does not attach a
 * target, read memory, modify records or change project identity configuration.
 * Review is supplied by the host, as with the record-specific alias table. */
export function createApprovedScopeAliasResolver(config = { version: 1, status: 'draft', entries: [] }) {
  if (!plain(config) || config.version !== 1 || !['draft', 'owner-reviewed'].includes(config.status)
    || Object.keys(config).some(key => !['version', 'status', 'review_id', 'entries'].includes(key))
    || !Array.isArray(config.entries) || config.entries.length > 128) throw invalid('scope-alias-configuration-invalid')
  if (config.status === 'owner-reviewed' && (!text(config.review_id) || config.review_id.length > 128))
    throw invalid('alias-review-missing')
  const reviewed = new Map(), entries = [], sources = new Set()
  for (const entry of config.entries) {
    if (!plain(entry) || Object.keys(entry).length !== 2
      || !Object.hasOwn(entry, 'from_scope') || !Object.hasOwn(entry, 'to_scope')
      || typeof entry.from_scope !== 'string' || !LEGACY_SCOPE.test(entry.from_scope)
      || typeof entry.to_scope !== 'string' || !LEGACY_SCOPE.test(entry.to_scope)
      || entry.from_scope === entry.to_scope) throw invalid('scope-alias-entry-invalid')
    if (sources.has(entry.from_scope)) throw invalid('scope-alias-source-ambiguous')
    sources.add(entry.from_scope)
    entries.push(Object.freeze({ from_scope: entry.from_scope, to_scope: entry.to_scope }))
    if (config.status === 'owner-reviewed') reviewed.set(entry.from_scope, {
      canonicalScope: entry.to_scope, scopeWide: true,
    })
  }
  const description = Object.freeze({ version: 1, status: config.status,
    review_id: config.status === 'owner-reviewed' ? config.review_id : null,
    entries: Object.freeze(entries), writes: false, grantsAuthority: false })
  const contextFor = context => {
    if (context !== undefined && !plain(context)) throw invalid('scope-alias-context-invalid')
    const attached = context?.attachedProjects ?? []
    if (!Array.isArray(attached) || attached.length > 128 || !attached.every(value => typeof value === 'string'))
      throw invalid('scope-alias-context-invalid')
    const aliases = new Map(aliasViews.get(context?.projectAliases) ?? [])
    for (const [from, alias] of reviewed) {
      if (aliases.has(from)) throw invalid('alias-view-ambiguous')
      aliases.set(from, alias)
    }
    return Object.freeze({ ...context, attachedProjects: Object.freeze([...attached]), projectAliases: aliasViewOf(aliases) })
  }
  return Object.freeze({ contextFor, description })
}

/** A direct trusted-host read adapter supplies existing attachment and project
 * selection callbacks. Configuration and note/model metadata cannot supply
 * these callbacks. Project context has no subject/privacy fields, so it cannot
 * replace the read owner's policy when composed at the recall boundary.
 * This adapter never changes capture identity or creates an attachment. */
export function createProjectReadContextResolver({ projectIdentity = createProjectIdentityResolver(),
  approvedScopeAliases = createApprovedScopeAliasResolver(), host } = {}) {
  if (host !== undefined && (!plain(host)
    || Reflect.ownKeys(host).length !== 2 || typeof host.contextFor !== 'function'
    || typeof host.scopeFor !== 'function')) throw invalid('project-read-host-invalid')
  const contextFor = host === undefined ? agent => projectIdentity.contextFor(agent) : host.contextFor.bind(host)
  const scopeFor = host === undefined ? agent => projectIdentity.scopeOf(agent) : host.scopeFor.bind(host)
  return Object.freeze({
    scopeOf(agent) {
      const scope = scopeFor(agent)
      if (scope !== null && (typeof scope !== 'string' || !scope.startsWith('project:')))
        throw invalid('project-read-scope-invalid')
      return scope
    },
    contextFor(agent) {
      const context = contextFor(agent)
      if (!plain(context) || Reflect.ownKeys(context).some(key => !['attachedProjects', 'projectAliases'].includes(key)))
        throw invalid('project-read-context-invalid')
      return approvedScopeAliases.contextFor(context)
    },
  })
}

/** Nonsecret configuration suitable for explicit host review. Missing
 * configuration leaves project memory unattached. An unreviewed alias table is
 * retained for preview but cannot attach any historical scope. */
export function createProjectIdentityResolver(config) {
  if (config === undefined || config === null) config = { version: 1, projects: [] }
  if (!plain(config) || config.version !== 1 || !Array.isArray(config.projects)
    || config.projects.length > 128) throw invalid('configuration-invalid')
  const projects = [], projectMap = new Map(), workspaceMap = new Map()
  for (const entry of config.projects) {
    if (!plain(entry) || typeof entry.project_id !== 'string' || !PROJECT_ID.test(entry.project_id)
      || !Array.isArray(entry.workspace_roots) || entry.workspace_roots.length < 1
      || entry.workspace_roots.length > 128) throw invalid('project-invalid')
    if (projectMap.has(entry.project_id)) throw invalid('project-id-ambiguous')
    const roots = []
    for (const value of entry.workspace_roots) {
      const root = pathOf(value)
      if (!root) throw invalid('workspace-root-invalid')
      if (workspaceMap.has(root)) throw invalid('workspace-alias-ambiguous')
      workspaceMap.set(root, entry.project_id)
      roots.push(root)
    }
    const project = Object.freeze({ project_id: entry.project_id, workspace_roots: Object.freeze(roots) })
    projects.push(project); projectMap.set(project.project_id, project)
  }
  const aliases = new Map(), reviewedAliases = new Map(), aliasedRecordIds = new Set()
  const aliasTable = config.alias_table
  let reviewId = null, reviewStatus = 'unavailable'
  if (aliasTable !== undefined) {
    if (!plain(aliasTable) || aliasTable.version !== 1
      || !['draft', 'owner-reviewed'].includes(aliasTable.status)
      || !Array.isArray(aliasTable.entries) || aliasTable.entries.length > 1024) throw invalid('alias-table-invalid')
    if (aliasTable.status === 'owner-reviewed' && (!text(aliasTable.review_id) || aliasTable.review_id.length > 128))
      throw invalid('alias-review-missing')
    reviewStatus = aliasTable.status
    reviewId = aliasTable.status === 'owner-reviewed' ? aliasTable.review_id : null
    for (const entry of aliasTable.entries) {
      if (!plain(entry) || typeof entry.legacy_scope !== 'string' || !LEGACY_SCOPE.test(entry.legacy_scope)
        || !projectMap.has(entry.project_id) || !Array.isArray(entry.record_ids)
        || entry.record_ids.length === 0 || entry.record_ids.length > 100_000) throw invalid('alias-entry-invalid')
      if (aliases.has(entry.legacy_scope)) throw invalid('legacy-alias-ambiguous')
      const recordIds = new Set()
      for (const id of entry.record_ids) {
        if (typeof id !== 'string' || !RECORD_ID.test(id)) throw invalid('alias-record-invalid')
        if (aliasedRecordIds.has(id)) throw invalid('alias-record-ambiguous')
        recordIds.add(id); aliasedRecordIds.add(id)
      }
      const alias = { projectId: entry.project_id, canonicalScope: stableProjectScope(entry.project_id), recordIds }
      aliases.set(entry.legacy_scope, alias)
      if (aliasTable.status === 'owner-reviewed') reviewedAliases.set(entry.legacy_scope, alias)
    }
  }
  const projectAliases = aliasViewOf(reviewedAliases)
  // Snapshot all inputs above. Later caller mutation cannot change attachment.
  const projectIdOf = agent => {
    const root = pathOf(agent?.session?.header?.cwd)
    if (!root || !workspaceMap.has(root)) return null
    return workspaceMap.get(root)
  }
  const scopeOf = agent => {
    const projectId = projectIdOf(agent)
    return projectId === null ? null : stableProjectScope(projectId)
  }
  const contextFor = agent => {
    const projectId = projectIdOf(agent)
    const attachedProjects = projectId === null ? [] : [stableProjectScope(projectId)]
    return Object.freeze({ attachedProjects: Object.freeze(attachedProjects), projectAliases })
  }
  const resolveLegacyScope = (scope, recordId) => {
    const alias = reviewedAliases.get(scope)
    return alias?.recordIds.has(recordId) ? alias.canonicalScope : null
  }
  const previewMigration = (records, { expectedCount } = {}) => {
    if (!Array.isArray(records) || records.length > 100_000
      || (expectedCount !== undefined && (!Number.isSafeInteger(expectedCount) || expectedCount < 0)))
      throw invalid('migration-input-invalid')
    const seen = new Set(), mappings = [], unresolved = []
    for (const note of records) {
      const scope = note?.scope, id = note?.id ?? note?.recordId
      if (typeof scope !== 'string' || !LEGACY_SCOPE.test(scope)) continue
      if (typeof id !== 'string' || !RECORD_ID.test(id) || seen.has(id)) throw invalid('migration-record-invalid')
      seen.add(id)
      const canonical = resolveLegacyScope(scope, id)
      if (canonical === null) { unresolved.push(Object.freeze({ record_id: id, from_scope: scope, reason: 'owner-reviewed-alias-unavailable' })); continue }
      mappings.push(Object.freeze({ record_id: id, from_scope: scope, to_scope: canonical,
        preserve_record_id: true, preserve_canonical_bytes: true }))
    }
    const countMatches = expectedCount === undefined || mappings.length === expectedCount
    return Object.freeze({ status: reviewStatus === 'owner-reviewed' && unresolved.length === 0 && countMatches ? 'ready-for-review' : 'incomplete',
      review_id: reviewId, writes: false, grantsAuthority: false, mappings: Object.freeze(mappings),
      unresolved: Object.freeze(unresolved), ...(expectedCount === undefined ? {} : { expected_count: expectedCount, count_matches: countMatches }) })
  }
  return Object.freeze({ scopeOf, contextFor, resolveLegacyScope, previewMigration,
    description: Object.freeze({ version: 1, projects: Object.freeze(projects), alias_status: reviewStatus,
      review_id: reviewId, grantsAuthority: false }) })
}
