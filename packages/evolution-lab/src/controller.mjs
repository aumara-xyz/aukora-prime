import { EMPTY_MANIFEST_JSON, parseManifest } from './manifest.mjs'

/** The only data ingress is bounded JSON text. There is no transport or effect API. */
export function createEvolutionController(manifestJson = EMPTY_MANIFEST_JSON) {
  let disposed = false
  const listeners = new Set()
  let state
  function publish(jsonText) {
    if (disposed) return false
    try {
      const manifest = parseManifest(jsonText)
      state = Object.freeze({ status: manifest.availability, manifest, error: null })
    } catch {
      // Invalid updates clear previous results. Never retain stale evidence or echo input.
      state = Object.freeze({ status: 'refused', manifest: parseManifest(EMPTY_MANIFEST_JSON),
        error: 'Evidence manifest refused. A bounded, sanitized reference manifest is required.' })
    }
    for (const listener of listeners) listener()
    return state.status !== 'refused'
  }
  publish(manifestJson)
  return Object.freeze({
    getSnapshot: () => state,
    subscribe(listener) {
      if (disposed) return () => {}
      if (typeof listener !== 'function') throw new TypeError('evolution-lab:listener-required')
      listeners.add(listener)
      return () => { listeners.delete(listener) }
    },
    updateManifest: publish,
    dispose() { disposed = true; listeners.clear() },
  })
}
