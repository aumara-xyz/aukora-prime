/** Explicit byte budgets, not estimates of a model's token count.
 * The shipped local embedder has a 512-token microbatch and a 2048-token
 * context. Keep content documents small without increasing its memory profile.
 * Installed tokenizer/embedding acceptance still requires an operator check. */
export const MAX_EMBEDDING_CONTENT_BYTES = 384
export const MAX_REMEMBER_INPUT_BYTES = 4 * MAX_EMBEDDING_CONTENT_BYTES

/** Split only index transport bytes. Authoritative stored notes are unchanged.
 * Offsets are UTF-8 bytes; each part ends on a complete Unicode code point. */
export function embeddingParts(text) {
  const parts = []
  let content = '', size = 0, start = 0
  for (const point of text) {
    const bytes = Buffer.byteLength(point, 'utf8')
    if (size + bytes > MAX_EMBEDDING_CONTENT_BYTES) {
      parts.push({ content, start, end: start + size })
      start += size; content = ''; size = 0
    }
    content += point; size += bytes
  }
  if (content !== '' || parts.length === 0) parts.push({ content, start, end: start + size })
  return parts
}
