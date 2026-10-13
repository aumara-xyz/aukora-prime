/** Standalone AUMLOK browser plugin. */
import type { Context as ClientContext } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import type {} from '@deepseek-ai/dsh-client-ui-session/client'
import type { ConnectionHandle } from '@deepseek-ai/dsh-api-remotes/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@aukora/face-layout/client'
import { AumlokMenu } from './AumlokMenu.tsx'
import { AumlokSurface, type AumlokSurfaceInjected } from './AumlokSurface.tsx'
import { IdentityMenu, IdentitySurface, type IdentitySurfaceInjected } from './IdentitySurface.tsx'
import { AumlokControlProjectionService } from './control-projection.ts'
import { AumlokControlStatusLoader } from './control-status-loader.ts'
import { createAumlokBrowserCeremonyBridge, parseAumlokDrawnPhrase, readAumlokCeremonyBridge } from './binding-bridge.ts'
import { en, zh, type AumlokKey } from './locales.ts'
import { AUMLOK_IDENTITY_ENDPOINT, type AumlokContactIdentity } from '../identity.ts'
import type { ReadIdentity } from './IdentityCard.tsx'

export {
  AUMLOK_CONTROL_NOT_CONNECTED,
  AumlokControlProjectionService,
  parseAumlokControlProjection,
  readAumlokCeremonyBridge,
} from './control-projection.ts'
export type {
  AumlokControlProjection,
  AumlokControlProjectionState,
} from './control-projection.ts'

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** AUMLOK launcher and local-binding preview. */
    aumlok: AumlokKey
  }
}

const NS = 'aumlok'

/** Services required by the AUMLOK browser plugin. */
export const inject = ['slots', 'locale', 'connection']

/**
 * Register the AUMLOK dictionaries, System launcher, and center surface.
 * @param ctx - Client root context.
 */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'ui-aumlok: dictionaries')
  const projection = new AumlokControlProjectionService(ctx)
  const desktopCeremony = readAumlokCeremonyBridge()
  const browserCeremony = desktopCeremony === undefined ? createAumlokBrowserCeremonyBridge() : undefined
  projection.attachCeremony(desktopCeremony ?? browserCeremony)
  const connection = ctx.get('connection') as ConnectionHandle
  const readIdentity: ReadIdentity = async signal => {
    const response = await fetch(AUMLOK_IDENTITY_ENDPOINT, { method: 'GET', signal,
      headers: { accept: 'application/json' }, credentials: 'same-origin', cache: 'no-store' })
    if (!response.ok) throw new Error('aumlok:identity-unavailable')
    return await response.json() as AumlokContactIdentity
  }
  const loader = new AumlokControlStatusLoader(projection, connection)
  const refreshControlStatus = (): void => { void loader.refresh() }
  ctx.effect(() => {
    const disposeReset = ctx.on('connection/reset', () => { void loader.refresh() })
    void loader.refresh()
    return () => {
      disposeReset()
      loader.dispose()
    }
  }, 'ui-aumlok: control status refresh')
  ctx.slots.inject('shell.menu.system', () => ctx.slots.register({
    name: 'shell.menu.system',
    id: 'aumlok',
    order: -30,
    locale: NS,
  }, AumlokMenu))
  ctx.slots.inject('shell.menu.system', () => ctx.slots.register({
    name: 'shell.menu.system', id: 'identity', order: -20, locale: NS,
  }, IdentityMenu))
  ctx.inject(['slots', 'aumlokControlProjection', 'layout'], (scope: ClientContext) => {
    scope.slots.inject('shell.surface', () => scope.slots.register({
      name: 'shell.surface',
      id: 'aumlok',
      order: 20,
      locale: NS,
      inject: (): AumlokSurfaceInjected => ({
        hooks: { controlProjection: scope.aumlokControlProjection.store },
        ceremonyAvailable: scope.aumlokControlProjection.ceremonyAvailable,
        browserCeremony: browserCeremony !== undefined,
        publicFirstRun: browserCeremony !== undefined && !connection.isLoopback,
        ...(browserCeremony === undefined ? {} : { cancelCeremony: () => { void browserCeremony.cancel() } }),
        // THE TWO HALVES OF ONE CROSSING, AND THE HANDLE THAT SALTS THE KEY CROSSES WITH THEM (X8):
        // the shell draws the words, the screen shows them once, and the typed words — and the public
        // handle — go back the same way. None of it is kept here.
        drawPhrase: (intent, language, handle) => browserCeremony === undefined
          ? scope.aumlokControlProjection.drawPhrase(intent, language)
          : intent !== 'bind' ? Promise.resolve({ ok: false, reason: 'aumlok:browser-first-binding-only' })
            : browserCeremony.prepare(handle ?? '', language).then(parseAumlokDrawnPhrase),
        submitPhrase: (intent, words, handle) =>
          scope.aumlokControlProjection.submitPhrase(intent, words, handle),
        // WHAT FLIPS THE SCREEN. After a ceremony completes, the same loader that serves
        // every other status read re-reads the controller, so a newly bound subject
        // becomes the seven public fields without a page reload, and a changed phrase
        // moves the record to its new epoch. A refusal never reaches this.
        refreshControlStatus,
        startFirstChat: () => {
          scope.layout.closeSurface()
          scope.layout.openConversation()
        },
      }),
    }, AumlokSurface))
    scope.slots.inject('shell.surface', () => scope.slots.register({
      name: 'shell.surface', id: 'identity', order: 21, locale: NS,
      inject: (): IdentitySurfaceInjected => ({
        hooks: { controlProjection: scope.aumlokControlProjection.store },
        readIdentity,
        refreshControlStatus,
      }),
    }, IdentitySurface))
  })
}
