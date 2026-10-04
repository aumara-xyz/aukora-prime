// SPDX-License-Identifier: AGPL-3.0-or-later
// The default composition supplies trusted host bindings as E's third argument.
// Ordinary Kira configuration stays data; it cannot supply a verifier or pins.
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash, createPublicKey } from 'node:crypto'

export const name = 'aukora-kira'
export const inject = Object.freeze(['tools', 'sessions'])
export const PROPOSE_SOCKET = '/run/aukora-gate/gate.sock'
export const AURA_CONFIGURATION = '/etc/aukora-boundary-gate/aura-context.json'
export const AURA_MODULE = '/opt/aukora-aura/packages/boundary-gate/host/aura/context.mjs'
export const AURA_JSON_MODULE = '/opt/aukora-aura/packages/contracts/src/json.mjs'
export const AURA_READ_LIFECYCLE = '/etc/aukora-boundary-gate/aura-read-lifecycle.json'
export const CAPTURE_MODULE = '/opt/aukora-boundary-gate/src/ledger.mjs'
export const captureUnavailable = Object.freeze({ status: 'unavailable',
  reason: 'kira-aura-capture:host-unavailable', grantsAuthority: false })

const execute = promisify(execFile)
async function checkRuntimeAura() {
  // A fixed, no-dispatch public preflight runs before either installed module.
  // Python isolation and an empty environment exclude caller-selected loaders.
  const { stdout } = await execute('/usr/bin/python3', ['-I', '-S',
    '/usr/local/lib/aukora-boundary/gate-bootstrap', 'check-runtime-aura'],
  { env: {}, timeout: 10_000, maxBuffer: 65_536 })
  if (stdout.trim() !== 'RUNTIME_AURA_VERIFIED') throw new Error(captureUnavailable.reason)
  return true
}

function publicCapturePins(configuration) {
  const source = configuration?.source
  if (!source || source.source_id !== 'aukora-gate-pilot'
    || typeof source.public_key_pem !== 'string' || Buffer.byteLength(source.public_key_pem) > 1024
    || typeof source.key_sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(source.key_sha256))
    throw new Error(captureUnavailable.reason)
  const key = createPublicKey(source.public_key_pem)
  if (key.asymmetricKeyType !== 'ed25519'
    || createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex') !== source.key_sha256)
    throw new Error(captureUnavailable.reason)
  return Object.freeze({ journal_id: source.source_id, gate_public_key_pem: source.public_key_pem,
    gate_pubkey_sha256: source.key_sha256 })
}

const unavailable = () => { throw new Error(captureUnavailable.reason) }
const sha256 = value => createHash('sha256').update(value, 'utf8').digest('hex')
const hex64 = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const proposalId = value => typeof value === 'string'
  && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)

// Own the exact data/property order before verification and canonical hashing.
// A later raw result or JSON hook cannot substitute different receipt bytes.
function snapshotData(value, depth = 0, ancestors = new Set(), configuration = false) {
  if (configuration && value === undefined) return value
  if (value === null || typeof value === 'boolean') return value
  if (typeof value === 'string' && value.length <= 65_536) return value
  if (typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)) return value
  const array = Array.isArray(value)
  if (!value || typeof value !== 'object' || (array && !configuration) || depth > 12 || ancestors.has(value)
    || !(array ? Object.getPrototypeOf(value) === Array.prototype
      : [Object.prototype, null].includes(Object.getPrototypeOf(value)))) unavailable()
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors)
  if (keys.length > 64) unavailable()
  ancestors.add(value)
  if (array) {
    if (!Number.isSafeInteger(value.length) || value.length > 63 || keys.length !== value.length + 1) unavailable()
    const entries = Array.from({ length: value.length }, (_, index) => {
      const descriptor = descriptors[String(index)]
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) unavailable()
      return snapshotData(descriptor.value, depth + 1, ancestors, configuration)
    })
    ancestors.delete(value)
    return Object.freeze(entries)
  }
  const entries = keys.map(key => {
    const descriptor = descriptors[key]
    if (typeof key !== 'string' || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) unavailable()
    return [key, snapshotData(descriptor.value, depth + 1, ancestors, configuration)]
  })
  ancestors.delete(value)
  return Object.freeze(Object.fromEntries(entries))
}

function configurationFingerprint(value) {
  const encode = node => node === undefined ? ['undefined'] : node === null ? ['null']
    : typeof node !== 'object' ? [typeof node, node] : Array.isArray(node) ? ['array', node.map(encode)]
      : ['record', Object.entries(node).map(([key, child]) => [key, encode(child)])]
  return JSON.stringify(encode(value))
}

function readLifecycle(aura, contextSha256) {
  const value = snapshotData(aura.parseStrictJson(aura.readProtectedAuraData(AURA_READ_LIFECYCLE, { maximum: 4096 })))
  const fields = ['version', 'kind', 'context_sha256', 'release_sha', 'genesis_instance_id']
  if (!value || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))
    || value.version !== 1 || value.kind !== 'aukora-aura-read-lifecycle/v1'
    || !hex64(value.context_sha256) || value.context_sha256 !== contextSha256
    || typeof value.release_sha !== 'string' || !/^[0-9a-f]{40}$/u.test(value.release_sha)
    || typeof value.genesis_instance_id !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value.genesis_instance_id)) unavailable()
  return value
}

/** Trusted host construction seam for disposable dependency fixtures. These
 * functions are never read from Cordis config, model input or reflected services. */
export function createGateCaptureHostPlugin({ platform, preflight, loadKira, loadAura, loadCapture, gateCall } = {}) {
  if (typeof platform !== 'string' || [preflight, loadKira, loadAura, loadCapture, gateCall]
    .some(value => typeof value !== 'function')) throw new Error(captureUnavailable.reason)
  return Object.freeze({ name, inject,
    async apply(ctx, existingConfig) {
      let trustedThirdArg, setup, effectiveConfig = existingConfig, origin, disposeOwned = () => {}
      const warnUnavailable = () => ctx.logger?.warn?.(`aukora-kira: gate capture unavailable (${captureUnavailable.reason})`)
      if (platform === 'linux') {
        try {
          if (await preflight() !== true) throw new Error(captureUnavailable.reason)
          const aura = await loadAura()
          const capture = await loadCapture()
          if (['readProtectedAuraData', 'loadAuraPublicConfiguration', 'auraConfigurationSha256',
            'createProtectedAuraProposalReadScope', 'validateAuraPublicProposalReadScope', 'canonicalJson', 'parseStrictJson']
            .some(method => typeof aura?.[method] !== 'function') || typeof capture?.verifyCompletedGateCapture !== 'function') unavailable()
          // This public role parses the protected JSON only. It never loads a
          // private context, reads scoped author material, or invents a grant.
          const configuration = aura.loadAuraPublicConfiguration()
          const capturePins = publicCapturePins(configuration)
          const contextSha256 = aura.auraConfigurationSha256(configuration)
          if (!hex64(contextSha256)) unavailable()
          setup = { aura, capture, configuration, capturePins, contextSha256 }
        } catch {
          // Keep reader/private paths and errors out of the ordinary host log.
          warnUnavailable()
        }
      }
      const kira = await loadKira()
      if (typeof kira?.apply !== 'function') throw new Error('aukora-kira: host entry unavailable')
      if (setup) {
        try {
          const detached = snapshotData(existingConfig, 0, new Set(), true)
          const ownerDescriptor = Object.getOwnPropertyDescriptor(existingConfig, 'memoryOwner')
          if (!ownerDescriptor || !Object.hasOwn(ownerDescriptor, 'value')) unavailable()
          origin = { memoryOwner: ownerDescriptor.value, fingerprint: configurationFingerprint(detached) }
          // The operator explicitly authorizes this sole INTERIM alias mapping
          // from the branded protected D configuration. No other alias is inferred.
          if (detached.memoryOwner?.subject === 'aumlok:subject:owner') {
            effectiveConfig = Object.freeze({ ...detached,
              memoryOwner: Object.freeze({ ...detached.memoryOwner, subject: setup.configuration.owner_subject }) })
          }
        } catch {
          setup = undefined
          effectiveConfig = existingConfig
          warnUnavailable()
        }
      }
      // E's selected normalizer reads existing public owner configuration only.
      // Ordinary configuration failures propagate through the same mount.
      const normalized = setup && typeof kira.readConfig === 'function' ? kira.readConfig(effectiveConfig) : undefined
      if (setup) {
        let releaseScope
        try {
          const { aura, capture, configuration, capturePins, contextSha256 } = setup
          const memoryOwner = normalized?.memoryOwner
          if (typeof ctx.effect !== 'function' || !memoryOwner || memoryOwner.subject !== configuration.owner_subject
            || typeof memoryOwner.subject !== 'string' || !/^aukora:1:[0-9a-f]{64}$/u.test(memoryOwner.subject)
            || typeof memoryOwner.stateDir !== 'string' || memoryOwner.stateDir.length < 1) unavailable()
          const identity = Object.freeze({ subject: memoryOwner.subject, stateDir: memoryOwner.stateDir })
          const lifecycle = readLifecycle(aura, contextSha256), scopes = new Map()
          let hostLive = true
          const ownerIsLive = () => {
            if (!hostLive) return false
            try {
              const ownerDescriptor = Object.getOwnPropertyDescriptor(existingConfig, 'memoryOwner')
              if (!ownerDescriptor || !Object.hasOwn(ownerDescriptor, 'value') || ownerDescriptor.value !== origin.memoryOwner
                || configurationFingerprint(snapshotData(existingConfig, 0, new Set(), true)) !== origin.fingerprint) return false
              const current = kira.readConfig(effectiveConfig)?.memoryOwner
              return hostLive && current?.subject === identity.subject && current?.stateDir === identity.stateDir
            } catch { return false }
          }
          releaseScope = () => {
            if (!hostLive) return
            hostLive = false
            for (const { scope } of scopes.values()) { try { scope.dispose() } catch {} }
          }
          const bindVerified = (value, id) => {
            if (!ownerIsLive()) unavailable()
            const dto = snapshotData(value)
            const verified = capture.verifyCompletedGateCapture(dto, capturePins)
            if (!proposalId(dto.receipt.proposal) || (id !== undefined && dto.receipt.proposal !== id)) unavailable()
            const binding = Object.freeze({ owner_subject: identity.subject, proposal_id: dto.receipt.proposal,
              source: Object.freeze({ journal_id: verified.source.journal_id, position: verified.source.position,
                hash: verified.source.hash, key_sha256: capturePins.gate_pubkey_sha256 }),
              receipt_sha256: sha256(aura.canonicalJson(dto.receipt)), context_sha256: contextSha256,
              release_sha: lifecycle.release_sha, genesis_instance_id: lifecycle.genesis_instance_id })
            return { dto, verified, binding, fingerprint: aura.canonicalJson(binding) }
          }
          const validate = (bound, retained) => {
            if (!retained || retained.fingerprint !== bound.fingerprint || !ownerIsLive()
              || aura.validateAuraPublicProposalReadScope(configuration, retained.scope) !== true || !ownerIsLive()) unavailable()
          }
          trustedThirdArg = Object.freeze({ capturePins,
            proposalFromToolResult: (value, execution) => {
              if (!ownerIsLive() || execution?.name !== 'aukora_gate_propose') unavailable()
              // E passes the parsed lossless result.value, never model arguments.
              // Bind the full ID to the exact proposeTheme return shape.
              const result = snapshotData(value)
              const fields = ['ok', 'state', 'proposal', 'proposal_id', 'target', 'accent', 'expires', 'message']
              if (!result || Object.keys(result).length !== fields.length || fields.some(field => !Object.hasOwn(result, field))
                || result.ok !== true || result.state !== 'PENDING_OWNER' || !proposalId(result.proposal_id)
                || result.proposal !== result.proposal_id.slice(0, 8) || result.target !== 'plugins/auma-theme/theme.json'
                || typeof result.accent !== 'string' || !/^(default|#[0-9A-F]{6})$/u.test(result.accent)
                || result.message !== 'Proposed. An approval popup is now on the owner\'s screen; only the owner can Approve or Refuse. You cannot approve it.'
                || typeof result.expires !== 'string') unavailable()
              const expires = Date.parse(result.expires)
              if (!Number.isSafeInteger(expires) || expires <= Date.now()
                || new Date(expires).toISOString() !== result.expires || !ownerIsLive()) unavailable()
              return Object.freeze({ id: result.proposal_id, expires })
            },
            // E invokes this synchronously after its policy await, immediately
            // before persistence. It validates only an already retained scope.
            isCaptureScopeLive: value => {
              try {
                const bound = bindVerified(value)
                validate(bound, scopes.get(bound.binding.proposal_id))
                return true
              } catch { return false }
            },
            verifyCompletedGateCapture: (value, pins) => {
              try {
                if (pins !== capturePins) unavailable()
                const bound = bindVerified(value)
                validate(bound, scopes.get(bound.binding.proposal_id))
                return bound.verified
              } catch { unavailable() }
            },
            stateForProposal: async id => {
              try {
                if (!proposalId(id) || !ownerIsLive()) unavailable()
                const dto = snapshotData(await gateCall(PROPOSE_SOCKET, 'state', { id }))
                if (!ownerIsLive()) unavailable()
                if (dto?.state !== 'applied') return dto
                const bound = bindVerified(dto, id)
                let retained = scopes.get(id)
                if (!retained) {
                  // Keep revocation permanent for this mount; never replace a
                  // retained grant or grow state without a finite bound.
                  if (scopes.size >= 128) unavailable()
                  const scope = aura.createProtectedAuraProposalReadScope(configuration, bound.binding, { isLive: ownerIsLive })
                  if (!scope || typeof scope.dispose !== 'function') unavailable()
                  retained = { scope, fingerprint: bound.fingerprint }
                  scopes.set(id, retained)
                }
                validate(bound, retained)
                return bound.dto
              } catch { unavailable() }
            },
          })
          ctx.effect(() => releaseScope, 'aukora-kira: protected proposal read scopes')
          disposeOwned = releaseScope
        } catch {
          releaseScope?.()
          trustedThirdArg = undefined
          warnUnavailable()
        }
      }
      try { return await kira.apply(ctx, effectiveConfig, trustedThirdArg) }
      catch (error) { disposeOwned(); throw error }
    },
  })
}

const production = createGateCaptureHostPlugin({ platform: process.platform, preflight: checkRuntimeAura,
  loadKira: () => import('./index.js'), loadAura: async () => {
    const aura = await import(AURA_MODULE), json = await import(AURA_JSON_MODULE)
    return Object.freeze({ ...aura, canonicalJson: json.canonicalJson, parseStrictJson: json.parseStrictJson })
  },
  loadCapture: () => import(CAPTURE_MODULE),
  gateCall: async (...args) => (await import('../../aukora-auma-theme/lib/propose.mjs')).gateCall(...args),
})

export const apply = production.apply
