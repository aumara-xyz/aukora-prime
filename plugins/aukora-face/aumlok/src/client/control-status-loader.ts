/** Same-origin reader for the parent-supplied AUMLOK control projection. */
import type { ConnectionHandle } from '@deepseek-ai/dsh-api-remotes/client'
import {
  AUMLOK_CONTROL_STATUS_ENDPOINT,
  parseAumlokNotConnectedBody,
} from '../control-projection.ts'
import type { AumlokControlProjectionService } from './control-projection.ts'

type StatusFetch = (
  input: string,
  init: RequestInit,
) => Promise<Response>

/**
 * Refreshes one generation-scoped AUMLOK status projection from the local page origin.
 * Every refresh disconnects first; aborted or superseded reads cannot restore stale status.
 */
export class AumlokControlStatusLoader {
  private controller: AbortController | undefined
  private disposed = false
  private readonly publicOrigin: boolean

  /**
   * @param projection - browser-owned validated projection service.
   * @param connection - page connection facts; the authenticated host validates its configured origin.
   * @param fetchStatus - same-origin HTTP reader; defaults to the browser fetch implementation.
   */
  constructor(
    private readonly projection: AumlokControlProjectionService,
    connection: Pick<ConnectionHandle, 'isLoopback'>,
    private readonly fetchStatus: StatusFetch = (input, init) => globalThis.fetch(input, init),
  ) {
    this.publicOrigin = !connection.isLoopback
  }

  private stale(controller: AbortController): boolean {
    return controller.signal.aborted
  }

  /**
   * Drop the current projection and attempt one fresh authenticated same-origin read.
   * Network, HTTP, media-type, and validation failures leave the service disconnected.
   * @returns after the current generation either connects or remains disconnected.
   */
  async refresh(): Promise<void> {
    this.controller?.abort()
    this.projection.disconnect()
    if (this.disposed) return
    const controller = new AbortController()
    this.controller = controller
    try {
      const response = await this.fetchStatus(AUMLOK_CONTROL_STATUS_ENDPOINT, {
        method: 'GET',
        headers: { accept: 'application/json' },
        cache: 'no-store',
        credentials: 'same-origin',
        signal: controller.signal,
      })
      if (this.stale(controller)) return
      const mediaType = response.headers.get('content-type')?.split(';', 1)[0]?.trim()
      if (response.status === 404) {
        // Older public releases used 404 for the explicit unbound state. Preserve its
        // body when present; a public 404 without one is the same first-run signal.
        const body = mediaType === 'application/json'
          ? parseAumlokNotConnectedBody(await response.json())
          : undefined
        if (!this.stale(controller)) {
          if (body !== undefined) this.projection.disconnect(body.reason, body.code, body.detail)
          else if (this.publicOrigin) this.projection.disconnect('controller-absent')
        }
        return
      }
      if (response.status !== 200 || mediaType !== 'application/json') return
      const value: unknown = await response.json()
      if (this.stale(controller)) return
      const body = parseAumlokNotConnectedBody(value)
      if (body !== undefined) {
        this.projection.disconnect(body.reason, body.code, body.detail)
        return
      }
      this.projection.connect(value)
    } catch {
      // Absence, transport failure, and invalid JSON all mean disconnected.
    }
  }

  /** Permanently stop reads and remove any visible status. */
  dispose(): void {
    this.disposed = true
    this.controller?.abort()
    this.controller = undefined
    this.projection.disconnect()
  }
}
