/** Project continuity uses a trusted host identity binding, never a path or ID
 * proposed in recalled text. Historical notes retain their bytes and scopes;
 * only explicitly reviewed record aliases join a canonical attached project. */
import { recallFilter } from './memory-frame.mjs'
import { isAbsolute } from 'node:path'
import { projectMemoryText } from './memory-quality.mjs'
import { createProjectIdentityResolver, isProjectScopeAttached, resolvedProjectScopeOf } from './project-identity.mjs'

const unattachedProjectIdentity = createProjectIdentityResolver()
export function projectScopeOf(agent, identity = unattachedProjectIdentity) {
  return identity.scopeOf(agent)
}

/** A project-shaped capture with no configured identity stays unattached. It
 * cannot become personal owner memory merely because a mapping is pending. */
export function captureScopeOf(agent, identity = unattachedProjectIdentity) {
  const scope = projectScopeOf(agent, identity)
  if (scope !== null) return scope
  const cwd = agent?.session?.header?.cwd
  return typeof cwd === 'string' && isAbsolute(cwd) ? 'project:unresolved' : 'owner'
}

/** The policy is acquired by the composition's read owner. This function only filters. */
export function visibleRemembered(notes, policy, scope, projectContext = { attachedProjects: scope === null ? [] : [scope] }) {
  return (Array.isArray(notes) ? notes : []).filter(note => note?.subject === policy?.subject
    && note.privacy === 'local' && policy?.permittedPrivacy?.includes('local')
    && isProjectScopeAttached(note, projectContext)
    && (['owner', 'agent'].includes(String(note.scope ?? 'owner')) || resolvedProjectScopeOf(note, projectContext) === scope))
}

export function rememberedSnippet(note) {
  return {
    recordId: note.id, ...projectMemoryText(note, String(note.statement ?? note.text ?? '').slice(0, 600), { start: 0 }),
    observedAt: note.observedAt, tier: 'remembered', attributedTo: note.attributedTo,
    source: note.source, scope: note.scope,
    citation: { remembered: true, sessionId: note.source?.sessionId, seq: note.source?.seq,
      sha256: note.source?.sha256, entryHash: note.aura?.entryHash },
  }
}

/** Newest project findings, not oldest ledger entries or personal trivia. The
 * timestamp is observation time; a receipt proves a report existed, not its truth. */
export function projectRecent(notes, policy, scope, states, { unreadable = 0, unchained = 0,
  projectContext = { attachedProjects: scope === null ? [] : [scope] } } = {}) {
  if (scope === null) return { snippets: [], projectState: true, availability: 'undetermined', reason: 'host-project-scope-unavailable' }
  const diagnostics = []
  const complete = unreadable === 0 && unchained === 0
  for (const [reason, count] of [['unreadable', unreadable], ['unchained', unchained]]) if (count > 0) diagnostics.push({ reason, count })
  const recent = visibleRemembered(notes, policy, scope, projectContext)
    .filter(note => String(note.scope ?? '').startsWith('project:') && resolvedProjectScopeOf(note, projectContext) === scope && note.attributedTo === 'agent')
    .filter(note => {
      const verdict = recallFilter(note, { now: new Date().toISOString(), ...projectContext, states })
      if (!verdict.ok) diagnostics.push({ reason: verdict.why })
      return verdict.ok
    })
    .sort((a, b) => String(b.observedAt).localeCompare(String(a.observedAt))
      || Number(b.source?.seq ?? 0) - Number(a.source?.seq ?? 0) || String(a.id).localeCompare(String(b.id)))
  return { snippets: recent.slice(0, 3).map(rememberedSnippet), projectState: true, diagnostics,
    availability: complete ? recent.length ? 'found' : 'empty' : 'undetermined',
    reason: !complete ? 'remembered-store-unavailable' : recent.length ? 'newest-agent-reports-not-live-attestation' : 'no-eligible-captured-project-findings' }
}
