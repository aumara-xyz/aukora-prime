// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/** Render recorded heads; only head changes drive a marked transition. */
import { useEffect, useId, useRef, useState, type CSSProperties } from 'react'
import type { PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { PENTORA } from '../aura/pentora.mjs'
import { createPentoraMotion, pentoraMotionFrame, type PentoraMotion } from '../aura/pentora-motion.mjs'
import { parseAuraSnapshot, advanceSourceEntries, observeSourceAdvances,
  type AuraSnapshot, type AuraSourceAdvance } from './aura-snapshot.ts'
import { isEditableTarget } from './escape.ts'
import css from './AuraCoherenceSurface.module.css'

export type AuraCoherenceSurfaceComponentProps = PropsRuntime<'shell.surface'> & PropsLocale<'settings'>
const POLL_MS = 2000
const READ_TIMEOUT_MS = 5000

/** Rotate only the presentation camera; head-derived cells stay unchanged. */
function projectedPoints(elapsedMs: number) {
  const yaw = 0.52 + elapsedMs * 0.00011
  const pitch = 0.38 + 0.045 * Math.sin(elapsedMs * 0.00006)
  return PENTORA.points.map(([x, y, z]) => {
    const xx = x * Math.cos(yaw) + z * Math.sin(yaw)
    const zz = -x * Math.sin(yaw) + z * Math.cos(yaw)
    const yy = y * Math.cos(pitch) - zz * Math.sin(pitch)
    const depth = y * Math.sin(pitch) + zz * Math.cos(pitch)
    const scale = 1 / (1 - 0.18 * depth)
    return [220 + xx * 168 * scale, 220 + yy * 168 * scale, depth] as const
  })
}
const CELL_INDEX = new Map(PENTORA.mutable.map((point, cell) => [point, cell]))

function reducedMotionMedia(): MediaQueryList | undefined {
  return typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-reduced-motion: reduce)') : undefined
}
function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => reducedMotionMedia()?.matches ?? false)
  useEffect(() => {
    const media = reducedMotionMedia()
    if (media === undefined) return
    const update = () => { setReduced(media.matches) }
    update()
    media.addEventListener('change', update)
    return () => { media.removeEventListener('change', update) }
  }, [])
  return reduced
}
function useDocumentVisible(): boolean {
  const [visible, setVisible] = useState(() => document.visibilityState !== 'hidden')
  useEffect(() => {
    const update = () => { setVisible(document.visibilityState !== 'hidden') }
    document.addEventListener('visibilitychange', update)
    return () => { document.removeEventListener('visibilitychange', update) }
  }, [])
  return visible
}
interface Observation { snapshot: AuraSnapshot; motion: PentoraMotion; since: number }

function recordTime(value: number): string {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function AuraCoherenceSurface({ activeSurface, closeSurface, t }: AuraCoherenceSurfaceComponentProps) {
  const active = activeSurface === 'aura-coherence'
  const visible = useDocumentVisible()
  const reducedMotion = useReducedMotion()
  const svgPrefix = useId().replace(/:/g, '')
  const [observation, setObservation] = useState<Observation | null>(null)
  const observed = useRef<Observation | null>(null)
  const [clock, setClock] = useState<{ motion: PentoraMotion; elapsed: number; presentation: number } | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [entriesMoved, setEntriesMoved] = useState(0)
  const [activity, setActivity] = useState<AuraSourceAdvance[]>([])
  const [advancedSources, setAdvancedSources] = useState<ReadonlySet<string>>(new Set())
  const counters = useRef(new Map<string, number>())
  const sourceHeads = useRef(new Map<string, string | null>())

  useEffect(() => {
    if (!active) return
    observed.current = null
    counters.current = new Map()
    sourceHeads.current = new Map()
    setObservation(null)
    setEntriesMoved(0)
    setActivity([])
    setAdvancedSources(new Set())
    setProblem(null)
  }, [active])
  useEffect(() => {
    if (!active || !visible) return
    let disposed = false
    let timer: ReturnType<typeof setTimeout> | undefined
    let controller: AbortController | undefined
    const read = async () => {
      controller = new AbortController()
      const timeout = setTimeout(() => { controller?.abort() }, READ_TIMEOUT_MS)
      try {
        const response = await fetch('/api/aukora/aura-snapshot', {
          credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        })
        if (!response.ok) throw new Error(`aura-snapshot:http-${response.status}`)
        const snapshot = parseAuraSnapshot(await response.json())
        const prior = observed.current
        const motion = prior?.snapshot.head === snapshot.head ? prior.motion
          : await createPentoraMotion(prior?.snapshot.head ?? snapshot.head, snapshot.head)
        if (disposed) return
        const advance = advanceSourceEntries(counters.current, snapshot.sources)
        counters.current = advance.counters
        setEntriesMoved(value => value + advance.entries)
        const sourceAdvance = observeSourceAdvances(sourceHeads.current, snapshot.sources, Date.now())
        sourceHeads.current = sourceAdvance.heads
        const next = { snapshot, motion, since: prior?.snapshot.head === snapshot.head ? prior.since : performance.now() }
        observed.current = next
        setObservation(next)
        if (prior?.snapshot.head !== snapshot.head) setClock({ motion, elapsed: 0, presentation: performance.now() })
        setAdvancedSources(new Set(sourceAdvance.advances.map(item => item.source)))
        if (sourceAdvance.advances.length > 0) {
          setActivity(value => [...sourceAdvance.advances, ...value].slice(0, 4))
        }
        setProblem(null)
      } catch (error) {
        if (!disposed) setProblem(error instanceof Error ? error.message : 'aura-snapshot:read-failed')
      } finally {
        clearTimeout(timeout)
        if (!disposed) timer = setTimeout(() => { void read() }, POLL_MS)
      }
    }
    void read()
    return () => { disposed = true; clearTimeout(timer); controller?.abort() }
  }, [active, visible])
  useEffect(() => {
    if (observation === null || !active || !visible) return
    let request = 0
    const draw = () => {
      const now = performance.now()
      const age = Math.max(0, now - observation.since)
      setClock({ motion: observation.motion, elapsed: age, presentation: reducedMotion ? 0 : now })
      if (!reducedMotion || pentoraMotionFrame(observation.motion, age, reducedMotion).status === 'in-motion') {
        request = window.requestAnimationFrame(draw)
      }
    }
    draw()
    return () => { window.cancelAnimationFrame(request) }
  }, [observation?.motion, active, visible, reducedMotion])
  useEffect(() => {
    if (!active) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !event.defaultPrevented && !isEditableTarget(event.target)) {
        event.preventDefault()
        closeSurface()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => { window.removeEventListener('keydown', onKey) }
  }, [active, closeSurface])

  const frame = observation === null ? null : pentoraMotionFrame(observation.motion, clock?.motion === observation.motion ? clock.elapsed : 0, reducedMotion)
  // Digests appear only once the picture has settled: between two heads nothing a person could read out or
  // compare is on the page.
  const digestsWithheld = frame !== null && frame.status !== 'solid'
  const snapshot = observation?.snapshot
  const present = snapshot?.sources.filter(source => source.head !== null).length ?? 0
  const points = projectedPoints(reducedMotion ? 0 : clock?.presentation ?? 0)
  const drawOrder = points.map((_, index) => index).sort((a, b) => points[a]![2] - points[b]![2] || a - b)
  return <section className={css.root} hidden={!active} aria-label={t('aura.trigger')}>
    <div className={css.content}>
      <header className={css.heading}>
        <div><h2>{t('aura.trigger')}</h2><p>{t('aura.subtitle')}</p></div>
        <button type="button" onClick={closeSurface}>{t('aura.close')}</button>
      </header>
      {frame !== null && <div className={css.figureStage} data-pentora-state={frame.status}
        data-pentora-pulse={frame.status === 'in-motion' ? 'active' : undefined}>
        <div className={css.figureHalo} aria-hidden="true" />
        <svg className={css.pentora} viewBox="0 0 440 440" role="img" aria-labelledby={`${svgPrefix}-title ${svgPrefix}-description`}>
          <title id={`${svgPrefix}-title`}>{t('aura.figure.title')}</title>
          <desc id={`${svgPrefix}-description`}>{t('aura.figure.description')}</desc>
          <g className={css.edges}>{PENTORA.edges.map(([from, to], index) => {
            const a = points[from]!, b = points[to]!
            return <line key={index} x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} />
          })}</g>
          {drawOrder.map(point => {
            const cell = CELL_INDEX.get(point), position = points[point]!
            const trit = cell === undefined ? 1 : frame.cells[cell]
            return <circle key={point} cx={position[0]} cy={position[1]} r={cell === undefined ? 6 : 3.8}
              className={css.cell} data-pentora-cell={cell} data-trit={trit}
              data-changed={cell === undefined ? undefined : frame.changedCells[cell] || undefined}
              style={{ '--cell-order': cell ?? 55 } as CSSProperties} />
          })}
        </svg>
        <p className={css.state} role="status">{t(frame.status === 'solid' ? 'aura.status.rest' : 'aura.status.moving')}</p>
      </div>}
      {!digestsWithheld && activity.length > 0 && <section className={css.activityStrip} aria-label={t('aura.activity.title')}>
        <h3>{t('aura.activity.title')}</h3>
        <ol>{activity.map(item => <li key={`${item.source}:${item.head}:${item.observedAt}`} data-aura-activity={item.source}>
          <strong>{item.source}</strong><code title={item.head}>{item.head.slice(0, 12)}</code>
          <time dateTime={new Date(item.observedAt).toISOString()}>{recordTime(item.observedAt)}</time>
        </li>)}</ol>
      </section>}
      {problem !== null && <p className={css.problem} role="status">{t('aura.snapshot.stale')} · {problem}</p>}
      {snapshot === undefined ? <p>{t('aura.snapshot.waiting')}</p> : digestsWithheld ? <p className={css.state}>{t('aura.status.moving')}</p> : <>
        <div className={css.readout}>
          <p>{t('aura.snapshot.head')} <code title={snapshot.head}>{snapshot.head.slice(0, 16)}</code></p>
          <p>{t('aura.snapshot.entries', { count: entriesMoved })}</p>
          <p>{t('aura.snapshot.present', { count: present })}</p>
        </div>
        <dl className={css.sources}>{snapshot.sources.map(source => <div key={source.name}
          data-source={source.name} data-source-advanced={advancedSources.has(source.name) || undefined}>
          <dt>{source.name}</dt>
          <dd>{source.head === null ? <><span className={`${css.stateChip} ${css.absent}`}>{t('aura.snapshot.absent')}</span><span>{source.absence}</span></>
            : <><span className={css.stateChip}>{t('aura.snapshot.available')}</span><code title={source.head}>{source.head.slice(0, 16)}</code>
              <span key={`${source.name}:${source.entries}`} className={css.entryCount}>{source.entries} {t('aura.snapshot.records')}</span></>}</dd>
        </div>)}</dl>
        <details className={css.details}><summary>{t('aura.snapshot.details')}</summary><pre>{JSON.stringify(snapshot, null, 2)}</pre></details>
      </>}
      <p className={css.note}>{t('aura.snapshot.meaning')}</p>
      <p className={css.note}>{t('aura.snapshot.limit')}</p>
      <p className={css.note}>{t('aura.snapshot.polling')}</p>
    </div>
  </section>
}
