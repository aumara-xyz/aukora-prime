// Displays the shown digest; stale or malformed inputs leave no picture. Grants no authority.
import { PENTORA, pentoraDigits } from './pentora.mjs'

const sha256 = bytes => globalThis.crypto.subtle.digest('SHA-256', bytes)
const colors = ['rgb(86,190,255)', 'rgb(236,232,245)', 'rgb(255,184,92)']

export function watchPentora(document, Observer, hash = sha256) {
  const source = document.getElementById('f-digest')
  const target = document.getElementById('pentora')
  let revision = 0
  function element(name, attributes) {
    const node = document.createElementNS('http://www.w3.org/2000/svg', name)
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value))
    return node
  }
  async function refresh() {
    const current = ++revision
    const head = source.textContent
    target.replaceChildren()
    target.hidden = true
    if (!/^[0-9a-fA-F]{64}$/.test(head)) return 'pentora:head-invalid'
    let digits
    try {
      digits = await pentoraDigits(Uint8Array.from(head.match(/../g), b => parseInt(b, 16)), hash)
    } catch {
      return 'pentora:hash-unavailable'
    }
    if (current !== revision || source.textContent !== head) return 'pentora:stale'
    const svg = element('svg', { viewBox: '-1.2 -1.2 2.4 2.4', role: 'img', 'aria-label': 'Pentora of displayed digest' })
    const project = ([x, y, z]) => [0.86 * x + 0.5 * z, 0.25 * x - 0.86 * y - 0.43 * z]
    const points = PENTORA.points.map(project)
    for (const [a, b] of PENTORA.edges) {
      svg.appendChild(element('line', { x1: points[a][0], y1: points[a][1], x2: points[b][0], y2: points[b][1],
        stroke: 'currentColor', 'stroke-width': 0.008, opacity: 0.25 }))
    }
    for (const [i, index] of PENTORA.mutable.entries()) {
      const [cx, cy] = points[index], digit = digits[i]
      svg.appendChild(element('circle', { cx, cy, r: 0.024, 'data-cell': index, 'data-digit': digit,
        fill: colors[digit],
        stroke: 'currentColor', 'stroke-width': 0.008 }))
    }
    svg.appendChild(element('circle', { cx: 0, cy: 0, r: 0.03, fill: colors[1] }))
    const label = document.createElement('p')
    label.textContent = 'Pentora · comparison of the displayed digest only. Matching pictures do not identify a person or approve an operation.'
    target.replaceChildren(svg, label)
    target.hidden = false
    return 'pentora:displayed'
  }
  const observer = new Observer(() => { void refresh() })
  observer.observe(source, { childList: true, characterData: true, subtree: true })
  void refresh()
  return refresh
}
