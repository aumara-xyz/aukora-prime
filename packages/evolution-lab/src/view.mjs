const REPO_ORIGIN = 'https://github.com/aumara-xyz/aukora-prime/blob/'

/** Paths and revisions are already recognized by parseManifest; no request is made. */
export function receiptHref(receipt) {
  return `${REPO_ORIGIN}${receipt.revision}/${receipt.path}`
}

/** React supplies HTML/attribute escaping. Evidence is always a text child. */
export function createEvolutionComponents(React, { ActionButton, Card, SectionHeader, PortalButton }) {
  const h = React.createElement
  const label = (value, key) => h('span', { className: 'evolution-lab-label', key }, value)
  const list = (values, absent) => values.length
    ? h('ul', null, values.map((text, i) => h('li', { key: i }, text))) : h('p', null, absent)
  const fact = (name, value, evidenceClass) => h('div', { key: name },
    h('dt', null, name, ' ', label(evidenceClass)), h('dd', null, value ?? 'Unavailable / unmeasured'))
  const receipt = (value) => value ? h('a', { href: receiptHref(value), rel: 'noreferrer',
    className: 'evolution-lab-receipt' }, `Repository receipt: ${value.path} @ ${value.revision}`)
    : h('p', null, 'No sanitized repository receipt supplied.')

  function Entry({ entry }) {
    const prediction = entry.prediction
    const outcome = entry.outcome
    return h(PortalButton, { title: entry.title,
      subtitle: `${entry.kind} · ${entry.evidenceClass} · ${entry.execution}`,
      variant: entry.evidenceClass === 'synthetic' ? 'purple' : 'blue',
      containerProps: { 'data-evidence-class': entry.evidenceClass, 'data-entry-id': entry.id } },
      h('p', null, 'Entry lineage: ', entry.id, ' ← ', entry.parentIds.join(', ') || 'No parent supplied'),
      h('p', null, 'The labels beside each field describe its evidence source; execution is ', entry.execution, '.'),
      h('dl', { className: 'evolution-lab-facts' },
        fact('Source pin', entry.sourcePin, entry.evidenceClass),
        fact('Recorded command (inert text)', entry.command, entry.evidenceClass),
        fact('Cost (USD)', entry.costUsd === null ? null : String(entry.costUsd), entry.evidenceClass),
        fact('Wall time (seconds)', entry.wallTimeSeconds === null ? null : String(entry.wallTimeSeconds), entry.evidenceClass)),
      h('h3', null, 'Prediction and outcome'),
      prediction ? h('div', null, label(prediction.evidenceClass),
        h('p', null, 'Prediction: ', prediction.statement),
        h('p', null, 'Preregistered at: ', prediction.preregisteredAt ?? 'Unestablished'),
        h('p', null, 'Prediction source pin: ', prediction.sourcePin ?? 'Unavailable'),
        h('p', null, prediction.preregisteredAt && prediction.sourcePin && prediction.receipt
          ? 'Preregistration is reported in the supplied reference; it has not been independently verified here.'
          : 'Preregistration unestablished: timestamp, pinned source and retained receipt are required.'),
        receipt(prediction.receipt)) : h('p', null, 'No prediction supplied. Preregistration unestablished.'),
      outcome ? h('div', null, label(outcome.evidenceClass),
        h('p', null, 'Outcome: ', outcome.summary),
        h('p', null, 'Observed at: ', outcome.observedAt ?? 'Unavailable'))
        : h('p', null, 'No outcome supplied / unmeasured.'),
      h('h3', null, 'Artifacts and lineage'),
      entry.artifacts.length ? h('ul', { className: 'evolution-lab-artifacts' }, entry.artifacts.map(artifact =>
        h('li', { key: artifact.id }, h('strong', null, artifact.title), ' ', label(artifact.evidenceClass),
          h('p', null, artifact.id, ' ← ', artifact.parentIds.join(', ') || 'No parent supplied'),
          h('p', null, 'SHA-256: ', artifact.sha256 ?? 'Unavailable'), receipt(artifact.receipt))))
        : h('p', null, 'No artifact lineage supplied.'),
      h('h3', null, 'Model and registration provenance'),
      entry.modelProvenance ? h('div', null, label(entry.modelProvenance.evidenceClass),
        h('p', null, 'Model: ', entry.modelProvenance.model), h('p', null, entry.modelProvenance.registration))
        : h('p', null, 'No model or registration provenance supplied.'),
      h('h3', null, 'Failures reported'), list(entry.failures, 'No failure report supplied; this does not establish zero failures.'),
      h('h3', null, 'Limits'), list(entry.limits, 'No entry-specific limits supplied.'))
  }

  function EvolutionSurface({ activeSurface, controller }) {
    const state = React.useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot)
    const manifest = state.manifest
    return h('section', { className: 'evolution-lab-surface', hidden: activeSurface !== 'evolution-lab',
      'data-evolution-lab': '', 'data-evidence-status': state.status },
      h('div', { className: 'evolution-lab-scroll' },
        h(SectionHeader, { className: 'evolution-lab-header' }, h('h1', null, 'Evolution Lab'),
          h('p', null, 'Read-only generations, artifact lineage and evidence.')),
        h(Card, { className: 'evolution-lab-card' }, h('h2', null, manifest.title),
          h('p', null, 'Registration and model provenance are not safety certification.'),
          h('p', null, 'Displaying references does not repeat an experiment or qualify the current product.'),
          manifest.mode === 'synthetic-fixture' && manifest.availability === 'available'
            ? h('p', { role: 'status', 'data-synthetic-fixture': '' }, 'SYNTHETIC FIXTURE — invented values for viewer checks; no demo results.') : null,
          state.error ? h('p', { role: 'alert' }, state.error) : null,
          manifest.reason ? h('p', null, manifest.reason) : null,
          list(manifest.limits, 'No dataset-specific limits supplied.')),
        manifest.entries.length ? h('div', { className: 'evolution-lab-entries' }, manifest.entries.map(entry => h(Entry, { key: entry.id, entry })))
          : h(Card, { className: 'evolution-lab-card' }, h('h2', null, manifest.availability === 'empty' ? 'Empty evidence ledger' : 'Evidence unavailable'),
            h('p', null, manifest.availability === 'empty' ? 'The supplied ledger contains no evidence entries.'
              : 'No approved generation metrics, predictions or artifact lineage are loaded.'))))
  }

  function EvolutionMenu({ activeSurface, openSurface }) {
    return h(ActionButton, { className: 'evolution-lab-menu', variant: 'purple',
      'aria-current': activeSurface === 'evolution-lab' ? 'page' : undefined,
      'data-evolution-lab-launcher': '', onClick: () => openSurface('evolution-lab', undefined, 'contained') }, 'Evolution Lab')
  }
  return { EvolutionSurface, EvolutionMenu }
}
