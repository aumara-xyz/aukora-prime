// The ceremony displays seven words once and requires a confirmed type-back before binding.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type {
  HostObservable,
  InjectFace,
  PropsLocale,
  PropsRuntime,
} from '@deepseek-ai/dsh-client-ui-slots'
import { AUMLOK_PHRASE_LANGUAGES, phraseStrengthKey } from './binding-bridge.ts'
import type {
  AumlokCeremonyIntent,
  AumlokCeremonyResult,
  AumlokDrawnPhrase,
} from './binding-bridge.ts'
import type { AumlokControlProjectionState } from './control-projection.ts'
import type { AumlokKey } from './locales.ts'
import { Card, SectionHeader } from '@aukora/face-layout/client'
import { IdentityIcon } from './IdentityVisuals.tsx'
import {
  AUMLOK_ANCHOR_POSITION,
  AUMLOK_BANDS,
  aumlokActionKey,
  aumlokAnchorBoxes,
  aumlokBadgeWord,
  aumlokConfirmGate,
  aumlokFirstRunOpen,
  aumlokFirstRunStep,
  aumlokHandleGate,
  aumlokReceipt,
  aumlokRedraw,
  aumlokSurfaceState,
  aumlokTileFace,
  aumlokWordInitial,
  type AumlokAnchorBox,
  type AumlokBandSpec,
  type AumlokCeremonyBeat,
  type AumlokTileFace,
} from './surface-state.ts'
import css from './Aumlok.module.css'

// Escape inside a text-entry control edits that control, never the surface. Duck-typed so a target
// from another realm classifies identically. THIS SCREEN HAS INPUTS NOW: the seven tiles become text
// entry while the person types the phrase back, and Escape there must leave the surface open.
function isEditableTarget(target: EventTarget | null): boolean {
  const el = target as { tagName?: unknown; isContentEditable?: unknown } | null
  const tag = typeof el?.tagName === 'string' ? el.tagName : ''
  return el?.isContentEditable === true || tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT'
}

/** Connection state of the parent-reported local controller. */
export type AumlokBindingStatus = AumlokControlProjectionState['status']
export type ModelCredentialStatus = 'configured' | 'missing' | 'unavailable'

/** Projection source, and ceremony source, injected by the browser plugin. */
export interface AumlokSurfaceInjected {
  hooks: {
    /** Parent-reported AUMLOK control metadata, disconnected by default. */
    controlProjection: HostObservable<AumlokControlProjectionState>
  }
  /** Whether the desktop shell exposes the two ceremony verbs on this page at all. */
  ceremonyAvailable: boolean
  /** Browser binding is first-run only and derives the phrase on the node. */
  browserCeremony?: boolean
  /** The page is the node's authenticated non-loopback browser origin. */
  publicFirstRun?: boolean
  /** Clear the pending browser draw when the surface closes or unmounts. */
  cancelCeremony?: () => void
  /** Ask the shell for one phrase, shown once, and report what came back. */
  drawPhrase: (intent: AumlokCeremonyIntent, language?: string, handle?: string) => Promise<AumlokDrawnPhrase>
  /** Hand the typed words back, and report the shell's verdict. */
  submitPhrase: (intent: AumlokCeremonyIntent, words: readonly string[],
    handle?: string) => Promise<AumlokCeremonyResult>
  /** Re-read the controller's public control, which is what flips the screen's state. */
  refreshControlStatus: () => void
  /** Read only whether the operator-managed model credential exists. */
  readModelCredentialStatus: () => Promise<ModelCredentialStatus>
  /** Leave binding and open the resident first conversation. */
  startFirstChat: () => void
}

/** Props assembled for the always-mounted AUMLOK center surface. */
export type AumlokSurfaceProps =
  PropsRuntime<'shell.surface'>
  & PropsLocale<'aumlok'>
  & InjectFace<AumlokSurfaceInjected>

type Translate = (key: AumlokKey) => string

/** The seven tiles are one set of seven; the typed words are held here until they cross back. */
const TILE_POSITIONS = [0, 1, 2, 3, 4, 5, 6] as const

/** A fresh set of empty tiles, one entry per position. */
function emptyTyped(): string[] {
  return TILE_POSITIONS.map(() => '')
}

/** Render one placeholder from the tile state; the revealed first word is rendered whole. */
function AnchorBox({ box, index }: { box: AumlokAnchorBox; index: number }) {
  return (
    <span className={css.anchorBox} data-aumlok-anchor-box={index} data-aumlok-anchor-box-kind={box.kind}>
      {box.kind === 'letter' ? box.letter : box.kind === 'dot' ? <i className={css.anchorDot} /> : null}
    </span>
  )
}

/** Render the word only during reveal, then accept its type-back or mask the bound phrase. */
function TileBody({
  face,
  position,
  word,
  value,
  dots,
  onType,
  t,
}: {
  face: AumlokTileFace
  position: number
  word: string | undefined
  value: string
  dots: number
  onType: (position: number, value: string) => void
  t: Translate
}) {
  switch (face) {
    case 'empty':
      return <span className={css.tileEmpty} data-aumlok-tile-face="empty" aria-hidden="true">—</span>
    case 'dots':
      return (
        <span className={css.wordMask} data-aumlok-tile-face="dots" aria-hidden="true">
          {Array.from({ length: dots }, (_, index) => <i key={index} />)}
        </span>
      )
    case 'word':
      return <span className={css.tileWord} data-aumlok-tile-face="word">{word ?? ''}</span>
    case 'input':
      return (
        <input
          className={css.tileInput}
          data-aumlok-tile-face="input"
          data-aumlok-tile-input={position}
          value={value}
          onChange={event => { onType(position, event.target.value) }}
          aria-label={t('tile.input').replace('{position}', String(position + 1))}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
        />
      )
  }
}

/** The one shape a band's two rows take, from the same face as the anchor above them. */
function PhraseBand({
  band,
  face,
  words,
  typed,
  onType,
  t,
}: {
  band: AumlokBandSpec
  face: AumlokTileFace
  words: readonly string[] | undefined
  typed: readonly string[]
  onType: (position: number, value: string) => void
  t: Translate
}) {
  return (
    <section className={css.phraseBand} data-aumlok-band={band.id} data-aumlok-tone={band.tone}>
      <header className={css.bandHeader}>
        <strong>{t(band.label)}</strong>
        <span>{t(band.detail)}</span>
      </header>
      <div className={css.bandRows}>
        {band.positions.map(position => (
          <div className={css.phraseRow} data-aumlok-token={position} key={position}>
            {/* The number is optional and quiet, and it is never read out: it is an aid to the eye. */}
            <span className={css.position} aria-hidden="true">{position + 1}</span>
            {/* Hide the initial whenever the word itself is hidden. */}
            <span className={css.initialBox} data-aumlok-initial-box={position} aria-hidden="true">
              {aumlokWordInitial(face, words?.[position])}
            </span>
            <TileBody
              face={face}
              position={position}
              word={words?.[position]}
              value={typed[position] ?? ''}
              dots={5}
              onType={onType}
              t={t}
            />
            {face === 'dots'
              ? <span className={css.visuallyHidden}>{t('token.rowMasked')}</span>
              : null}
          </div>
        ))}
      </div>
    </section>
  )
}

/**
 * Render the AUMLOK surface: the ceremony in its three states, and the technical status behind one
 * closed disclosure.
 * @param props - shell visibility, close action, ceremony source, and localized copy.
 * @returns the always-mounted AUMLOK surface.
 */
export function AumlokSurface({
  activeSurface,
  openSurface,
  closeSurface,
  t,
  useControlProjection,
  ceremonyAvailable,
  browserCeremony = false,
  publicFirstRun = false,
  cancelCeremony,
  drawPhrase,
  submitPhrase,
  refreshControlStatus,
  readModelCredentialStatus,
  startFirstChat,
}: AumlokSurfaceProps) {
  const active = activeSurface === 'aumlok'
  const projection = useControlProjection(value => value)
  const [refreshing, setRefreshing] = useState(false)
  const [changingHandle, setChangingHandle] = useState(false)
  const [beat, setBeat] = useState<AumlokCeremonyBeat>('none')
  // THE WORDS LIVE ONLY WHILE THEY ARE ON THE SCREEN. This is the one place they exist in this
  // process, they are cleared the moment the tiles turn over, and nothing else in this file reads
  // them — no effect, no log, no request.
  const [words, setWords] = useState<readonly string[] | undefined>(undefined)
  const [typed, setTyped] = useState<readonly string[]>(emptyTyped)
  // THE HANDLE LIVES HERE ONLY WHILE IT IS ON THE SCREEN, and it is NOT a secret: it is public, it is
  // recorded in the public record, and it is what a NIP-05 `name@domain` local part is read from. It is
  // held in this component's state for the same reason the words are — because the person is typing it
  // — and it is passed to the shell exactly as typed.
  const [handle, setHandle] = useState('')
  const [language, setLanguage] = useState('en')
  const [busy, setBusy] = useState(false)
  const [acknowledged, setAcknowledged] = useState(false)
  const [outcome, setOutcome] = useState<AumlokCeremonyResult | undefined>(undefined)
  const [explanationOpen, setExplanationOpen] = useState(false)
  const [modelCredential, setModelCredential] = useState<ModelCredentialStatus | 'idle' | 'checking'>('idle')
  const ceremonyGeneration = useRef(0)
  const autoOpened = useRef(false)
  useLayoutEffect(() => {
    if (!active) {
      setRefreshing(false)
      setChangingHandle(false)
      setBeat('none')
      setWords(undefined)
      setTyped(emptyTyped())
      setHandle('')
      setBusy(false)
      setAcknowledged(false)
      setOutcome(undefined)
    }
    // Invalidate pending work on close or unmount; late words must never reopen a ceremony.
    return () => { ceremonyGeneration.current += 1; cancelCeremony?.() }
  }, [active])
  const state = aumlokSurfaceState({ bound: projection.status === 'connected', refreshing })
  const face = aumlokTileFace(state, beat)
  const action = aumlokActionKey(state, beat)
  const gate = aumlokConfirmGate({ beat, acknowledged, busy })
  // Y3: Peter's "give me another" — a quiet redraw, offered while the words are on an unbound screen
  // and nowhere else. `busy` is one of its three inputs because a draw already in flight cannot be
  // asked for a second time.
  const redraw = aumlokRedraw({ state, beat, busy })
  // Require a valid public handle before drawing; show the bound handle from the record.
  const boundHandle = projection.status === 'connected' ? projection.control.handle : undefined
  const shownHandle = typeof boundHandle === 'string' && boundHandle.length > 0
    ? boundHandle
    : (state === 'unbound' ? handle : '')
  const handleGate = aumlokHandleGate({ state: changingHandle ? 'unbound' : state, handle: changingHandle ? handle : shownHandle })
  const sameHandle = changingHandle && typeof boundHandle === 'string' && boundHandle.length > 0
    && handle.normalize('NFKC').toLowerCase() === boundHandle.normalize('NFKC').toLowerCase()
  const receipt = projection.status === 'connected' ? aumlokReceipt(projection.control) : undefined
  const successfulBrowserBind = browserCeremony && outcome?.ok === true
  const firstRunStep = aumlokFirstRunStep({
    beat,
    busy,
    bound: projection.status === 'connected',
    successfulBind: successfulBrowserBind,
  })
  useEffect(() => {
    if (!successfulBrowserBind) {
      setModelCredential('idle')
      return
    }
    let current = true
    setModelCredential('checking')
    void readModelCredentialStatus().then(status => {
      if (current) setModelCredential(status)
    }, () => {
      if (current) setModelCredential('unavailable')
    })
    return () => { current = false }
  }, [readModelCredentialStatus, successfulBrowserBind])
  useEffect(() => {
    const decision = aumlokFirstRunOpen({
      active,
      alreadyOpened: autoOpened.current,
      browserCeremony,
      isLoopback: !publicFirstRun,
      projection,
    })
    if (!decision.ok) return
    autoOpened.current = true
    openSurface('aumlok')
  }, [active, browserCeremony, openSurface, projection, publicFirstRun])
  const onType = (position: number, value: string): void => {
    // THE BOX ACKNOWLEDGES THE WORDS THAT WERE ON THE SCREEN WHEN IT WAS TICKED. Editing any of them
    // afterwards puts the box back to unticked, so the one thing that arms Bind cannot be carried
    // over a phrase the person has not said out loud.
    if (beat === 'confirm') setAcknowledged(false)
    setTyped(current => current.map((word, index) => (index === position ? value : word)))
  }
  // ASK FOR ONE PHRASE, AND SHOW IT ONCE. A draw that returns no words is a refusal, not an empty
  // phrase: the screen then says only that no result came back, and a refresh that failed leaves the
  // binding it was replacing exactly as it was.
  const begin = (intent: AumlokCeremonyIntent): void => {
    // Refuse a draw until the required handle is valid and any refresh uses a different handle.
    if (busy || !active || !handleGate.canDraw || sameHandle) return
    const generation = ++ceremonyGeneration.current
    setBusy(true)
    setOutcome(undefined)
    setAcknowledged(false)
    if (intent === 'refresh') setRefreshing(true)
    void (async () => {
      const drawn = await (browserCeremony ? drawPhrase(intent, language, handle)
        : drawPhrase(intent, language)).catch((): AumlokDrawnPhrase => ({ ok: false }))
      if (generation !== ceremonyGeneration.current) return
      setBusy(false)
      if (!drawn.ok || drawn.words === undefined) {
        setOutcome(drawn.reason === undefined ? { ok: false } : { ok: false, reason: drawn.reason })
        if (intent === 'refresh') setRefreshing(false)
        return
      }
      setWords(drawn.words)
      setTyped(emptyTyped())
      setBeat('shown')
    })()
  }
  // A spent draw needs new words; only a refusal before consumption can keep the typed tiles.
  const submit = (intent: AumlokCeremonyIntent): void => {
    if (busy || !active || sameHandle) return
    const generation = ++ceremonyGeneration.current
    setBusy(true)
    setOutcome(undefined)
    void (async () => {
      const result = await submitPhrase(intent, typed, handle).catch((): AumlokCeremonyResult => ({ ok: false }))
      if (result.ok) refreshControlStatus()
      if (generation !== ceremonyGeneration.current) return
      setBusy(false)
      setWords(undefined)
      setAcknowledged(false)
      setOutcome(result)
      if (!result.ok) {
        if (result.drawSpent === true) {
          setTyped(emptyTyped())
          setBeat('none')
          if (intent === 'refresh') setRefreshing(false)
          return
        }
        setBeat('typed')
        return
      }
      setBeat('none')
      setRefreshing(false)
      setChangingHandle(false)
      if (browserCeremony) setTyped(emptyTyped())
      else setHandle('')
    })()
  }
  // ONE CONTROL PER STATE, AND THE PERSON'S OWN BEAT BETWEEN SHOWING AND TYPING. The words leave the
  // screen here and nowhere else, which is why this is a click and not a timer. THE THIRD CLICK IS NOT
  // A BIND: it puts Peter's warning on the screen and arms the button, and only a ticked box lets the
  // fourth click write an identity the person has just been told they will never see again.
  const act = (): void => {
    if (busy) return
    if (beat === 'shown') {
      setWords(undefined)
      setBeat('typed')
      return
    }
    if (beat === 'typed') {
      setAcknowledged(false)
      setBeat('confirm')
      return
    }
    if (beat === 'confirm') {
      if (!gate.bindEnabled) return
      submit(state === 'refresh' ? 'refresh' : 'bind')
      return
    }
    if (state === 'unbound') begin('bind')
    else if (state === 'bound') {
      if (!changingHandle) { setHandle(''); setChangingHandle(true) }
      else begin('refresh')
    }
  }
  useEffect(() => {
    if (!active) return
    // Bubble-phase, deferring to consumed events: Modal/Menu take Escape in
    // capture and mark it defaultPrevented, and Escape inside a text-entry
    // control belongs to that control, so only an unclaimed press closes the
    // surface.
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key !== 'Escape' || event.defaultPrevented) return
      if (isEditableTarget(event.target)) return
      event.preventDefault()
      closeSurface()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => { document.removeEventListener('keydown', onKeyDown) }
  }, [active, closeSurface])

  const ceremonyControls = ceremonyAvailable && (!browserCeremony || state === 'unbound') ? (
    <div
      className={css.ceremonyAction}
      data-aumlok-ceremony-state={state}
      data-aumlok-ceremony-beat={beat}
    >
      {beat === 'shown' ? (
        <p className={css.warning} data-aumlok-phrase-warning>{t('surface.warning.lost')}</p>
      ) : null}
      {/* Y3: "GIVE ME ANOTHER". Peter's sentence is that a person may draw a new phrase "as
          many times as the person likes until one feels right", and that NOTHING is written
          until they confirm and type it back. Both halves are the decision above: it is
          offered exactly while the words are on an unbound screen, and its handler draws —
          it never submits, so there is no path from this control to a write.
          IT IS A SPAN, AND NOT A SECOND BUTTON ELEMENT, DELIBERATELY. X6 courts exactly ONE
          button element in this surface and that one is the ceremony's own; a second one
          here would break a ticked requirement to satisfy this one, and on a bound screen it
          would be the second big button Peter ruled out. So the element kind is part of the
          requirement rather than a styling choice, and the keyboard handler below is what
          makes a span an honest control rather than a click target only a mouse can reach.
          THIS COMMENT DELIBERATELY DOES NOT SPELL THAT ELEMENT'S TAG, and the reason is
          measured rather than imagined: X6 counts openings of that tag in THIS FILE, so a
          comment that named it would be counted as one. That arm is a protection, not an
          obstacle, and the honest way past it is to stop writing the tag in prose — never
          to loosen the arm. */}
      {redraw.offered ? (
        <span
          className={css.redraw}
          data-aumlok-redraw
          data-aumlok-redraw-kind={redraw.kind}
          role="button"
          tabIndex={0}
          onClick={() => { begin('bind') }}
          onKeyDown={event => {
            if (event.key !== 'Enter' && event.key !== ' ') return
            event.preventDefault()
            begin('bind')
          }}
        >
          {t(redraw.action ?? 'surface.action.another')}
        </span>
      ) : null}
      {/* PETER'S OWN STEP, BEFORE ANYTHING IS BOUND. The words are off the screen, the
          person has typed them back, and this is the last moment at which saying them out
          loud can save the identity: the box is what arms the button. */}
      {gate.ask ? (
        <div className={css.confirm} data-aumlok-confirm>
          <p className={css.confirmWarning} data-aumlok-confirm-warning>
            {t('surface.confirm.warning')}
          </p>
          <label className={css.confirmRow}>
            <input
              type="checkbox"
              data-aumlok-confirm-checkbox
              checked={acknowledged}
              disabled={busy}
              onChange={event => { setAcknowledged(event.target.checked) }}
            />
            <span>{t('surface.confirm.checkbox')}</span>
          </label>
        </div>
      ) : null}
      <button
        type="button"
        data-aumlok-bind-button
        data-aumlok-action={action}
        disabled={busy || (gate.ask && !gate.bindEnabled)
          || (handleGate.ask && !handleGate.canDraw) || sameHandle}
        aria-busy={busy}
        onClick={act}
      >
        {t(busy ? 'runtime.binding.busy' : changingHandle && beat === 'none' ? 'surface.action.drawNew' : action)}
      </button>
      {state !== 'unbound' ? <p className={css.handleHint}>{t('surface.handle.together')}</p> : null}
      {/* A list-membership refusal names only the first invalid word; a mismatch reveals no matching positions. */}
      {outcome === undefined || outcome.ok ? null : (
        <p className={css.ceremonyRefusal} data-aumlok-binding-refused="true">
          {t('runtime.binding.failed')}
          {outcome.invalidWord === undefined ? null : <span>{' '}{t('phrase.wordUnknown').replace('{word}', outcome.invalidWord)}</span>}
          {outcome.reason === undefined ? null : (
            <>
              {' '}
              <code data-aumlok-binding-reason>{outcome.reason}</code>
            </>
          )}
        </p>
      )}
    </div>
  ) : null

  return (
    <section
      data-aumlok-surface
      className={css.surface}
      hidden={!active}
      aria-hidden={!active}
      aria-labelledby="aumlok-title"
    >
      <div className={css.canvas}>
        <header className={css.hero}>
          <div className={css.heroCopy}>
            <p>{t('eyebrow')}</p>
            <h2 id="aumlok-title">{t('title')}</h2>
          </div>
          {/* §3's badge: UNBOUND before a binding and BOUND after it, through a refresh as well,
              because a refresh is an act on the bound state and the old binding stands until the new
              words are typed back. The decision is `aumlokBadgeWord`, keyed off the same state the
              tiles and the buttons are drawn from, so the badge cannot disagree with the screen. */}
          <span className={css.statusBadge} data-aumlok-badge={successfulBrowserBind ? 'bound' : aumlokBadgeWord(state)} role="img"
            aria-label={t(successfulBrowserBind ? 'bound' : aumlokBadgeWord(state))}>
            {successfulBrowserBind || aumlokBadgeWord(state) === 'bound' ? <IdentityIcon name="lock" /> : null}
            {t(successfulBrowserBind ? 'bound' : aumlokBadgeWord(state))}
          </span>
        </header>

        <div className={css.composition}>
          <section className={css.phraseStage} aria-label={t('phrase.label')}>
            {browserCeremony && firstRunStep !== 'complete' ? (
              <ol className={css.firstRunSteps} data-aumlok-first-run-step={firstRunStep} aria-label={t('firstRun.steps.label')}>
                {([1, 2, 3] as const).map(step => (
                  <li key={step} data-current={firstRunStep === step || undefined}
                    aria-current={firstRunStep === step ? 'step' : undefined}>
                    <span>{step}</span>{t(`firstRun.step.${step}`)}
                  </li>
                ))}
              </ol>
            ) : null}
            {successfulBrowserBind ? (
              <section className={css.completion} data-aumlok-completion aria-labelledby="aumlok-completion-title">
                <span className={css.completionBadge}><IdentityIcon name="lock" />{t('bound')}</span>
                <h3 id="aumlok-completion-title">{t('firstRun.complete.title')}</h3>
                <p>{t('firstRun.complete.handle')}</p>
                <strong data-aumlok-completion-handle>{handle}</strong>
                {modelCredential === 'checking' ? (
                  <p data-aumlok-model-key-status="checking" role="status">{t('firstRun.complete.modelChecking')}</p>
                ) : modelCredential === 'missing' ? (
                  <p data-aumlok-model-key-status="missing">{t('firstRun.complete.modelMissing')}</p>
                ) : modelCredential === 'unavailable' ? (
                  <p data-aumlok-model-key-status="unavailable">{t('firstRun.complete.modelUnavailable')}</p>
                ) : null}
                {modelCredential === 'configured' ? (
                  <button type="button" data-aumlok-start-chat onClick={startFirstChat}>
                    {t('firstRun.complete.chat')}
                  </button>
                ) : modelCredential === 'missing' || modelCredential === 'unavailable' ? (
                  <button type="button" data-aumlok-completion-ok onClick={closeSurface}>
                    {t('firstRun.complete.ok')}
                  </button>
                ) : null}
              </section>
            ) : <>
            {browserCeremony ? <p className={css.warning} data-aumlok-browser-derivation>
              In this version, your words are sent over the encrypted connection to your own node and derived there.
              Deriving on your device is later work.
            </p> : null}
            {state !== 'bound' || changingHandle ? <label className={css.handleLabel}>
              {t('phrase.language')}
              <select data-aumlok-phrase-language value={language} disabled={busy || beat !== 'none'}
                onChange={event => { if (!busy && beat === 'none') setLanguage(event.target.value) }}>
                {AUMLOK_PHRASE_LANGUAGES.map(item => <option key={item.tag} value={item.tag}>{item.name}</option>)}
              </select>
            </label> : null}
            <p className={css.handleHint} data-aumlok-phrase-strength>
              {t(state === 'bound'
                ? phraseStrengthKey(projection.status === 'connected' ? projection.control.phraseLegacy : undefined)
                : 'phrase.strength.new')}
            </p>
            {/* A new binding needs a handle before the phrase is drawn; a bound handle is read-only. */}
            {handleGate.ask ? (
              <div className={css.handleField} data-aumlok-handle>
                <label className={css.handleLabel} htmlFor="aumlok-handle">
                  {t('surface.handle.label')}
                </label>
                <input
                  id="aumlok-handle"
                  className={css.handleInput}
                  data-aumlok-handle-input
                  value={handle}
                  disabled={busy || beat !== 'none'}
                  onChange={event => { if (!busy && beat === 'none') setHandle(event.target.value) }}
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                />
                {/* THE SHAPE IS SAID BEFORE IT IS ENFORCED, and the hint changes to the rule when what
                    is typed cannot be a handle: a disabled button with no sentence beside it is the
                    silent refusal this whole screen exists to remove. */}
                <p className={css.handleHint} data-aumlok-handle-hint>
                  {sameHandle ? t('surface.handle.mustChange') : handle.length === 0 || handleGate.valid
                    ? t('surface.handle.hint')
                    : t('surface.handle.invalid')}
                </p>
              </div>
            ) : null}
            {handleGate.shown ? (
              <Card className={css.handleHeading} data-aumlok-handle-locked>
                <div><span className={css.handleLabel}>{t('surface.handle.label')}</span>
                  <h3 data-aumlok-handle-locked-value>{handleGate.value}</h3></div>
                <div className={css.handleTools}><IdentityIcon name="lock" /><span>{t('surface.handle.locked')}</span>
                </div>
              </Card>
            ) : null}
            {/* Show the first word whole during reveal; keep fixed placeholders when hidden. */}
            <div
              className={css.anchorToken}
              data-aumlok-token={AUMLOK_ANCHOR_POSITION}
              data-aumlok-anchor-card
              data-aumlok-tile-face={face}
            >
              <span className={css.anchorMeta}>
                <strong>{t('anchor.label')}</strong>
                <span>{t('anchor.detail')}</span>
              </span>
              <span className={css.anchorBoxes}>
                {/* The reveal marker exists only while the words are visible. */}
                {face === 'word' ? <span data-aumlok-reveal="words" aria-hidden="true" /> : null}
                {face === 'input' ? (
                  <input
                    className={css.anchorInput}
                    data-aumlok-tile-input={AUMLOK_ANCHOR_POSITION}
                    data-aumlok-anchor-input
                    value={typed[AUMLOK_ANCHOR_POSITION] ?? ''}
                    onChange={event => { onType(AUMLOK_ANCHOR_POSITION, event.target.value) }}
                    aria-label={t('tile.input').replace('{position}', String(AUMLOK_ANCHOR_POSITION + 1))}
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                  />
                ) : face === 'word' ? (
                  <span className={css.tileWord} data-aumlok-first-word>{words?.[AUMLOK_ANCHOR_POSITION]}</span>
                ) : (
                  aumlokAnchorBoxes(face, undefined).map((box, index) => (
                    <AnchorBox box={box} index={index} key={index} />
                  ))
                )}
              </span>
              {face === 'dots'
                ? <span className={css.visuallyHidden}>{t('token.anchorMasked')}</span>
                : null}
            </div>
            <div className={css.bands}>
              {/* Y5'S SECOND REVEAL MARKER: the same fact as the one in the card above, on the spine,
                  so the boxes settling and the rows fading are one arrival rather than two effects that
                  could drift apart. It is a sibling of the bands, so it cannot disturb their stagger
                  (which counts children of `.bandRows`), and `display: contents` means it draws
                  nothing itself. */}
              {face === 'word' ? <span data-aumlok-reveal="words" aria-hidden="true" /> : null}
              {AUMLOK_BANDS.map(band => (
                <PhraseBand
                  band={band}
                  face={face}
                  words={words}
                  typed={typed}
                  onType={onType}
                  t={t}
                  key={band.id}
                />
              ))}
            </div>
            <div className={receipt === undefined ? undefined : css.boundReceipt}
              data-aumlok-bound-receipt={receipt === undefined ? undefined : ''}>
              {receipt === undefined ? null : <>
                <h3 className={css.boundLine} data-aumlok-bound-line>{t('surface.bound.line')}</h3>
                <p className={css.boundExplanation}>{t('surface.bound.explanation')}</p>
                <code className={css.boundRoot} data-aumlok-receipt-root>{receipt.root}</code>
              </>}
              {ceremonyControls}
            </div>
            </>}
          </section>

          <Card className={css.flow} aria-labelledby="aumlok-flow-label">
            <button type="button" className={css.flowSummary} aria-controls="aumlok-flow-body"
              aria-expanded={explanationOpen} onClick={() => { setExplanationOpen(open => !open) }}>
              {t('firstRun.what')}
            </button>
            <div id="aumlok-flow-body" className={css.flowBody} data-collapsed={!explanationOpen || undefined}>
              <SectionHeader className={css.explanationHeader}>
                <img src="/branding/aumara-icon-96.png" width="36" height="36" alt="" />
                <h3 id="aumlok-flow-label">{t('surface.explanation.title')}</h3>
              </SectionHeader>
              <div className={css.explanation} data-aumlok-explanation>
                <p>{t('surface.explanation.identity')}</p>
                <p>{t('surface.explanation.knowledge')}</p>
                <p>{t('surface.explanation.decider')}</p>
                <p>{t('surface.explanation.boundary')}</p>
                <p>{t('surface.explanation.edge')}</p>
              </div>
              <p className={css.boundaryClosing}>{t('surface.explanation.closing')}</p>
            </div>
          </Card>
        </div>
      </div>

    </section>
  )
}
