// The face carries seven words through an available desktop or same-origin browser transport.
export interface AumlokCeremonyResult {
  readonly ok: boolean
  /** The shell's own short machine-readable refusal. Shown verbatim, never replaced. */
  readonly reason?: string
  /** Only a new draw can be submitted after the shell consumes these words. */
  readonly drawSpent?: true
  readonly invalidWord?: string
}

/** What one draw resolves to: the seven words, shown once, or the shell's own refusal. */
export interface AumlokDrawnPhrase {
  readonly ok: boolean
  /** The seven independent words, in order. Present only on a completed draw. */
  readonly words?: readonly string[]
  readonly language?: string
  readonly entropyBits?: 77
  /** The shell's own short machine-readable refusal. Shown verbatim, never replaced. */
  readonly reason?: string
}

/** The preload bridge, narrowed to the verbs this screen may ask for. */
export interface AumlokCeremonyBridge {
  /**
   * Draw seven words in the chosen language.
   * @param intent - which ceremony is being started.
   * @returns whether the words were drawn, and the shell's own reason when they were not.
   */
  draw(intent: AumlokCeremonyIntent, language?: string): Promise<unknown>
  /**
   * Hand the typed words back, and resolve when the ceremony finishes.
   *
   * ONE VERB PER HALF OF THE CROSSING, AND NOTHING BEYOND THEM. A bridge carrying a verb this screen
   * does not name is a shell offering a ceremony this face has not agreed to render.
   * @param intent - which ceremony the words belong to.
   * @param words - the seven typed words, in order, anchor first.
   * @param handle - the person's PUBLIC handle, as typed. X8 salts the key with it, so it is half of
   *   the key rather than a label on it; it is passed through as typed and kept nowhere here.
   * @returns whether the ceremony completed, and the shell's own reason when it did not.
   */
  submit(intent: AumlokCeremonyIntent, words: readonly string[], handle?: string): Promise<unknown>
}

/** Browser transport exposes only first binding and cancellation of its pending draw. */
export interface AumlokBrowserCeremonyBridge extends AumlokCeremonyBridge {
  prepare(handle: string, language?: string): Promise<unknown>
  cancel(): Promise<unknown>
  status(): Promise<unknown>
}

export const AUMLOK_BROWSER_BINDING_ENDPOINT = '/api/aukora/aumlok-binding'

type CeremonyFetch = (input: string, init: RequestInit) => Promise<Response>

/** The browser submits secrets only in a same-origin HTTPS POST body. */
export function createAumlokBrowserCeremonyBridge(
  fetchCeremony: CeremonyFetch = (input, init) => globalThis.fetch(input, init),
  protocol: string = globalThis.location?.protocol ?? '',
): AumlokBrowserCeremonyBridge | undefined {
  if (protocol !== 'https:') return undefined
  let ceremonyId: string | undefined
  let preparedHandle: string | undefined
  let generation = 0
  const refusal = (reason: string) => ({ ok: false, reason })
  async function post(verb: string, body: unknown): Promise<Record<string, unknown>> {
    try {
      const response = await fetchCeremony(`${AUMLOK_BROWSER_BINDING_ENDPOINT}/${verb}`, {
        method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' },
        credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error',
        referrerPolicy: 'no-referrer', body: JSON.stringify(body),
      })
      if (response.headers.get('content-type')?.split(';', 1)[0]?.trim() !== 'application/json')
        return refusal('aumlok:browser-response-invalid')
      const value: unknown = await response.json()
      if (value === null || typeof value !== 'object' || Array.isArray(value))
        return refusal('aumlok:browser-response-invalid')
      const record = value as Record<string, unknown>
      if (response.ok && record['ok'] === true) return record
      const reason = record['reason']
      return refusal(typeof reason === 'string' && /^aumlok:[a-z0-9:_-]{1,112}$/u.test(reason)
        ? reason : 'aumlok:browser-request-refused')
    } catch { return refusal('aumlok:browser-request-failed') }
  }
  async function cancel(): Promise<unknown> {
    generation += 1
    const pending = ceremonyId
    ceremonyId = undefined
    preparedHandle = undefined
    return pending === undefined ? { ok: true } : post('cancel', { ceremonyId: pending })
  }
  return {
    draw: async () => refusal('aumlok:browser-handle-required'),
    async prepare(handle, language = 'en') {
      await cancel()
      const current = generation
      const value = await post('prepare', { handle, language })
      if (value['ok'] !== true) return value
      const draw = value['draw']
      if (draw === null || typeof draw !== 'object' || Array.isArray(draw))
        return refusal('aumlok:browser-response-invalid')
      const id = (draw as Record<string, unknown>)['ceremonyId']
      const phrase = parseAumlokDrawnPhrase({ ok: true, ...draw })
      if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/u.test(id) || !phrase.ok)
        return refusal('aumlok:browser-response-invalid')
      if (current !== generation) {
        await post('cancel', { ceremonyId: id })
        return refusal('aumlok:browser-draw-cancelled')
      }
      ceremonyId = id
      preparedHandle = handle
      return phrase
    },
    async submit(intent, words, handle) {
      if (intent !== 'bind') return refusal('aumlok:browser-first-binding-only')
      if (ceremonyId === undefined) return refusal('aumlok:browser-no-pending-draw')
      if (handle !== preparedHandle) return refusal('aumlok:browser-handle-changed')
      if (!Array.isArray(words) || words.length !== PHRASE_LENGTH
        || !words.every(word => typeof word === 'string' && WORD.test(word)))
        return refusal('aumlok:browser-phrase-shape')
      const pending = ceremonyId
      ceremonyId = undefined
      preparedHandle = undefined
      generation += 1
      const value = await post('bind', { ceremonyId: pending, typedPhrase: words.join(' '), acknowledged: true })
      if (value['ok'] !== true) return { ...value, drawSpent: true }
      if (value['binding'] === null || typeof value['binding'] !== 'object' || Array.isArray(value['binding']))
        return { ...refusal('aumlok:browser-response-invalid'), drawSpent: true }
      return { ok: true, drawSpent: true }
    },
    cancel,
    status: () => post('status', {}),
  }
}

/** Which ceremony the operator asked for. */
export type AumlokCeremonyIntent = 'bind' | 'refresh'

/** Generated words contain only bounded Unicode letters and combining marks. */
const WORD = /^[\p{L}\p{M}]{1,64}$/u

export const AUMLOK_PHRASE_LANGUAGES = Object.freeze([
  { tag: 'en', name: 'English' }, { tag: 'es', name: 'Español' },
  { tag: 'fr', name: 'Français' }, { tag: 'it', name: 'Italiano' },
  { tag: 'pt', name: 'Português' }, { tag: 'cs', name: 'Čeština' },
  { tag: 'ja', name: '日本語' }, { tag: 'ko', name: '한국어' },
  { tag: 'zh-Hans', name: '简体中文' }, { tag: 'zh-Hant', name: '繁體中文' },
])

/** The plan's phrase is seven words, and a draw that is not seven words is not a phrase. */
const PHRASE_LENGTH = 7

function isFunction(value: unknown): value is (...args: never[]) => unknown {
  return typeof value === 'function'
}

/**
 * Read the shell bridge off the page, if this launch has one.
 *
 * `available: true` is required as well as both verbs: the shell's own flag is the shell's statement
 * that a ceremony can actually be run here, and a bridge that declares itself unavailable must not grow
 * a working-looking button. Both verbs are required together, for the same reason.
 * @param page - the object to read the bridge from; the page's own global by default.
 * @returns the bounded bridge, or undefined in a plain browser or a half-mounted shell.
 */
export function readAumlokCeremonyBridge(page?: unknown): AumlokCeremonyBridge | undefined {
  const candidate = page === undefined
    ? (globalThis as { aukoraAumlok?: unknown }).aukoraAumlok
    : page
  if (candidate === null || typeof candidate !== 'object') return undefined
  const record = candidate as Record<string, unknown>
  if (record['available'] !== true) return undefined
  // BOTH, OR NONE. A half-mounted bridge must render no control rather than one that fails at click
  // time, which is the same doctrine as the `available` flag above.
  if (!isFunction(record['draw']) || !isFunction(record['submit'])) return undefined
  return {
    draw: (intent, language) => (record['draw'] as AumlokCeremonyBridge['draw']).call(candidate, intent, language) as Promise<unknown>,
    submit: (intent, words, handle) =>
      (record['submit'] as AumlokCeremonyBridge['submit'])
        .call(candidate, intent, words, handle) as Promise<unknown>,
  }
}

/** The shell's reason, when it gave one this screen may show. */
function readReason(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return undefined
  return value
}

/**
 * Narrow one drawn phrase without inventing words the shell did not draw.
 *
 * Require seven bounded Unicode words and the shared generator's language and strength metadata.
 * Carry the shell's refusal when no phrase was drawn.
 * @param value - the resolved value of a draw call.
 * @returns the seven words, or a failure carrying no words.
 */
export function parseAumlokDrawnPhrase(value: unknown): AumlokDrawnPhrase {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return { ok: false }
  const record = value as Record<string, unknown>
  const reason = readReason(record['reason'])
  if (record['ok'] !== true) return reason === undefined ? { ok: false } : { ok: false, reason }
  const words = record['words']
  if (!Array.isArray(words) || words.length !== PHRASE_LENGTH) return { ok: false }
  if (!words.every(word => typeof word === 'string' && WORD.test(word))) return { ok: false }
  const language = record['language']
  if (!AUMLOK_PHRASE_LANGUAGES.some(item => item.tag === language) || record['entropyBits'] !== 77) return { ok: false }
  return { ok: true, words: words.map(word => String(word)), language: language as string, entropyBits: 77 }
}

/**
 * Narrow one submit result without inventing a claim the shell did not make.
 *
 * A value that is not the contracted shape is reported as a FAILURE with no reason, not as a success:
 * the caller then says only that no result came back, which is the whole of what is known.
 * @param value - the resolved value of a submit call.
 * @returns the contracted result, or a failure carrying no reason.
 */
export function parseAumlokCeremonyResult(value: unknown): AumlokCeremonyResult {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return { ok: false }
  const record = value as Record<string, unknown>
  const ok = record['ok'] === true
  const reason = readReason(record['reason'])
  const spent = record['drawSpent'] === true ? { drawSpent: true as const } : {}
  const invalidWord = typeof record['invalidWord'] === 'string' && record['invalidWord'].length > 0 && record['invalidWord'].length <= 64
    ? { invalidWord: record['invalidWord'] } : {}
  return reason === undefined ? { ok, ...spent, ...invalidWord } : { ok, reason, ...spent, ...invalidWord }
}

/**
 * Draw one phrase and report what the shell said, and nothing more.
 *
 * A rejected promise (the shell died, its window was destroyed, the bridge was replaced) is the same
 * fact as a refusal with no reason: no phrase came back. Neither outcome is turned into a success.
 * @param bridge - the bounded bridge read from the page.
 * @param intent - which ceremony to draw for.
 * @returns the contracted drawn phrase, or a failure carrying no words.
 */
export async function drawAumlokPhrase(
  bridge: AumlokCeremonyBridge,
  intent: AumlokCeremonyIntent,
  language = 'en',
): Promise<AumlokDrawnPhrase> {
  try {
    // A CLOSED SWITCH, AND THE DEFAULT REFUSES. The verbs are named per ceremony, so a third ceremony
    // added to the type would otherwise silently draw for one of the two that exist — a person asking
    // for one thing handed the words of another. An intent this mapper does not know draws NOTHING and
    // refuses by name.
    switch (intent) {
      case 'bind':
      case 'refresh':
        return parseAumlokDrawnPhrase(await bridge.draw(intent, language))
      default: return { ok: false, reason: 'aumlok:ceremony-intent-unknown' }
    }
  } catch {
    return { ok: false }
  }
}

/**
 * Hand the typed words back and report the shell's verdict, and nothing more.
 *
 * THE WORDS GO BACK EXACTLY AS TYPED, and this function keeps no copy of them: the array it is given
 * is passed through and then forgotten, so nothing here can grow a cache of a phrase. THE HANDLE GOES
 * WITH THEM, for the same reason and with the same care — except that it is public, so the only rule
 * it needs is that it is not invented here.
 * @param bridge - the bounded bridge read from the page.
 * @param intent - which ceremony the words belong to.
 * @param words - the seven typed words, in order, anchor first.
 * @param handle - the person's public handle, as typed, or nothing on a ceremony that does not ask.
 * @returns the contracted result, or a failure carrying no reason.
 */
export async function submitAumlokPhrase(
  bridge: AumlokCeremonyBridge,
  intent: AumlokCeremonyIntent,
  words: readonly string[],
  handle?: string,
): Promise<AumlokCeremonyResult> {
  try {
    // THE SAME CLOSED SWITCH, for the same reason: a submit must not be routed to another ceremony's
    // verb, and an intent this mapper does not know submits NOTHING and refuses by name.
    switch (intent) {
      case 'bind':
      case 'refresh':
        return parseAumlokCeremonyResult(await bridge.submit(intent, words, handle))
      default: return { ok: false, reason: 'aumlok:ceremony-intent-unknown' }
    }
  } catch {
    return { ok: false }
  }
}

export function phraseStrengthKey(legacy: unknown): 'phrase.strength.new' | 'phrase.strength.legacy' {
  return legacy === false ? 'phrase.strength.new' : 'phrase.strength.legacy'
}
