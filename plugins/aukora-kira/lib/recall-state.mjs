/** Presentation state is normalized after the last policy pass. Historical
 * read outcomes and partial-failure decisions remain separate evidence. */
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0
const returnedRecords = answer => {
  const records = Array.isArray(answer?.snippets) ? answer.snippets : Array.isArray(answer?.notes) ? answer.notes : []
  return new Set(records.filter(record => String(record?.text ?? record?.statement ?? '').trim() !== '')
    .map((record, index) => String(record.recordId ?? record.id ?? `anonymous:${index}`))).size
}

export function normalizeRecallState(answer, facts = {}) {
  if (!answer) return answer
  const returned = returnedRecords(answer)
  const readable = facts.readable === true || (facts.readable === undefined && ['found', 'empty'].includes(answer.availability))
  const eligible = facts.eligibleRecords === undefined ? count(answer.eligibleRecords) : count(facts.eligibleRecords)
  const withheld = facts.policyWithheldCount === undefined ? count(answer.policyWithheldCount) : count(facts.policyWithheldCount)
  const recallState = returned > 0 ? 'returned' : withheld > 0 ? 'withheld'
    : !readable ? 'unavailable' : eligible > 0 || answer.availability === 'found' ? 'query-miss' : 'empty'
  // A returned verified record establishes a positive result even when another
  // read was unavailable. Never erase that sibling failure or its action policy.
  const availability = returned > 0 || recallState === 'query-miss' ? 'found'
    : readable ? 'empty' : 'undetermined'
  const status = recallState === 'returned' ? 'match' : recallState === 'withheld' ? 'withheld'
    : recallState === 'query-miss' ? 'insufficient' : recallState === 'empty' ? 'empty' : 'undetermined'
  return { ...answer, availability, status, recallState, returnedRecords: returned,
    eligibleRecords: eligible, policyWithheldCount: withheld }
}
