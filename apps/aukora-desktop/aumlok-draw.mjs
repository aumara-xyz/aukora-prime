// The release's shared generator draws seven words; one sender owns one consumable type-back.

export const DRAW_REFUSE = Object.freeze({
  /** The caller is not the application window. */
  FORBIDDEN_SENDER: 'aumlok:forbidden-sender',
  /** A ceremony was asked for that this shell does not run. */
  INTENT_UNKNOWN: 'aumlok:ceremony-intent-unknown',
  /** A submit arrived with no draw behind it, or with the draw already answered. */
  NO_PENDING_DRAW: 'aumlok:no-pending-draw',
  /** The words typed back are not the words that were drawn. ONE refusal, nothing written. */
  PHRASE_MISMATCH: 'aumlok:phrase-mismatch',
  /** The type-back is not seven bounded strings and is not compared. */
  PHRASE_SHAPE: 'aumlok:phrase-shape',
  /** The release carries no word lists, so no phrase can be drawn. */
  NO_LISTS: 'aumlok:word-lists-absent',
  /** The phrase was drawn and the words came back exactly as drawn, and the binding was written. */
  VERIFIED: 'aumlok:ceremony-verified',
  /** The words matched but this shell has no bind ceremony to perform, so nothing can be written. */
  CEREMONY_ABSENT: 'aumlok:ceremony-absent',
  /** The binding could not be written; the ceremony's own name carries the errno after it. */
  WRITE_FAILED: 'aumlok:bind-write-failed',
  /** The binding was written but cannot be read back, so it is not a binding. */
  RECORD_UNREADABLE: 'aumlok:bind-record-unreadable',
})

/**
 * THE NAMES THE CEREMONY REFUSES BY, MIRRORED SO THE SCREEN CAN RECOGNISE THEM.
 *
 * `bind-v3.mjs` owns these strings and the shell does not paraphrase them: a refusal crosses to the
 * screen verbatim, which is the point of a named refusal. This list exists only so a court reading the
 * shell's own constants can tell a ceremony refusal from a shell one — it is a copy for comparison, and
 * the ceremony remains the author. It is deliberately NOT used to rewrite what crosses.
 */
export const BIND_REFUSE = Object.freeze({
  DIRECTORY_ABSENT: 'aumlok:bind-directory-absent',
  PHRASE_MALFORMED: 'aumlok:bind-phrase-malformed',
  WRITE_FAILED: 'aumlok:bind-write-failed',
  RECORD_UNREADABLE: 'aumlok:bind-record-unreadable',
  ALREADY_BOUND: 'aumlok:bind-already-bound',
})

const REFUSAL_LIMIT = 128

/**
 * Read a refusal name off a thrown value, or answer `null` so the caller invents nothing.
 *
 * MEASURED, AND THIS IS WHY IT IS NOT `error.code`: a plain `TypeError` in modern Node carries
 * `code === 'ERR_INVALID_ARG_TYPE'`. A shell that passed `error.code` straight through therefore put a
 * raw Node identifier on the screen where the item requires a NAME of the shell's own — and this
 * screen's whole defect was that it said nothing useful. Only a value this product chose counts, and a
 * value the product chose always begins with the `aumlok:` prefix.
 * @param {unknown} cause - whatever was thrown.
 * @returns {string|null} the name, or null when this was not one of ours.
 */
function refusalName(cause) {
  const code = cause?.code
  if (typeof code !== 'string' || !code.startsWith('aumlok:') || code.length > REFUSAL_LIMIT) {
    return null
  }
  return code
}

/**
 * The errno from a failure, as a short suffix for a refusal name, or nothing at all.
 *
 * A REFUSAL NAME THAT SWALLOWED THE ERRNO WOULD BE A WORSE REFUSAL. `aumlok:bind-write-failed` alone
 * says the write failed; `aumlok:bind-write-failed:EACCES` says it was permissions and not a full disk,
 * which is the difference between two different mornings. The suffix is held to the shape of an errno
 * so a long or hostile message cannot ride into the name.
 * @param {unknown} cause - whatever was thrown.
 * @returns {string} the suffix, including its leading colon, or an empty string.
 */
function errnoSuffix(cause) {
  const code = cause?.code
  if (typeof code !== 'string' || !/^[A-Z][A-Z0-9]{1,15}$/u.test(code)) return ''
  return `:${code}`
}

export const PHRASE_LENGTH = 7

export function createAumlokDraw(options = {}) {
  const ceremony = typeof options.ceremony === 'function' ? options.ceremony : undefined
  let pending = null
  return {
    draw(owner, intent, releaseDir, context = {}) {
      if (intent !== 'bind' && intent !== 'refresh') return { ok: false, reason: DRAW_REFUSE.INTENT_UNKNOWN }
      const library = context.library ?? options.library
      if (typeof library?.generatePhrase !== 'function' || typeof library?.validatePhrase !== 'function') {
        return { ok: false, reason: DRAW_REFUSE.NO_LISTS }
      }
      try {
        const drawn = library.generatePhrase({ language: context.language ?? 'en' })
        pending = { owner, intent, words: drawn.words, language: drawn.language, library }
        return { ok: true, words: drawn.words, language: drawn.language, entropyBits: drawn.entropyBits }
      } catch (error) {
        return { ok: false, reason: refusalName(error) ?? DRAW_REFUSE.NO_LISTS }
      }
    },

    async submit(owner, intent, words, context = {}) {
      if (intent !== 'bind' && intent !== 'refresh') return { ok: false, reason: DRAW_REFUSE.INTENT_UNKNOWN }
      if (pending === null) return { ok: false, reason: DRAW_REFUSE.NO_PENDING_DRAW, drawSpent: true }
      if (pending.owner !== owner) return { ok: false, reason: DRAW_REFUSE.FORBIDDEN_SENDER }
      if (pending.intent !== intent) return { ok: false, reason: DRAW_REFUSE.INTENT_UNKNOWN }
      const expected = pending
      // Consume before validation: every attempted type-back spends this draw.
      pending = null
      if (!Array.isArray(words) || words.length !== PHRASE_LENGTH
        || !words.every(word => typeof word === 'string' && word.length > 0 && word.length <= 64)) {
        return { ok: false, reason: DRAW_REFUSE.PHRASE_SHAPE, drawSpent: true }
      }
      let offered
      try {
        offered = expected.library.validatePhrase(words.join(' '), { language: expected.language }).words
      } catch (error) {
        return { ok: false, reason: refusalName(error) ?? DRAW_REFUSE.PHRASE_SHAPE,
          ...(error?.code === 'aumlok:phrase-word-unknown' && typeof error.word === 'string'
            ? { invalidWord: error.word } : {}), drawSpent: true }
      }
      if (offered.some((word, at) => word !== expected.words[at])) {
        return { ok: false, reason: DRAW_REFUSE.PHRASE_MISMATCH, drawSpent: true }
      }
      const bind = ceremony ?? context?.library?.bindV3
      if (typeof bind !== 'function') return { ok: false, reason: DRAW_REFUSE.CEREMONY_ABSENT, drawSpent: true }
      try {
        const bound = await bind({ words: offered, phraseLanguage: expected.language,
          handle: context?.handle, directory: context?.directory,
          boundAt: typeof context?.boundAt === 'string' && context.boundAt.length > 0
            ? context.boundAt : new Date().toISOString() })
        return { ok: true, reason: DRAW_REFUSE.VERIFIED, subject: bound?.projection?.subject ?? null, drawSpent: true }
      } catch (error) {
        return { ok: false, reason: refusalName(error) ?? `${DRAW_REFUSE.WRITE_FAILED}${errnoSuffix(error)}`,
          drawSpent: true }
      }
    },
    forget() { pending = null },
    isPending() { return pending !== null },
  }
}
