// SPDX-License-Identifier: AGPL-3.0-or-later
// Preserve the existing UTF-16-unit limit without splitting a valid surrogate pair.
// This diagnostic helper does not repair malformed text or normalize stored bytes.
export function truncateUtf16(value, maxUnits) {
  if (typeof value !== 'string' || !Number.isSafeInteger(maxUnits) || maxUnits < 0) {
    throw new TypeError('memory:text-prefix-invalid')
  }
  if (value.length <= maxUnits) return value
  const last = value.charCodeAt(maxUnits - 1), next = value.charCodeAt(maxUnits)
  const end = last >= 0xD800 && last <= 0xDBFF && next >= 0xDC00 && next <= 0xDFFF
    ? maxUnits - 1 : maxUnits
  return value.slice(0, end)
}
