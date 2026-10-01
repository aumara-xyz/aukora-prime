import { canonical, hash, id, integer, refuse } from './policy.mjs';
import { fromPrimeRoute, usdMicros } from './prime-contracts.mjs';
import { openPrivateDatabase, transaction } from './private-db.mjs';

export const PROVIDER_DIRECTORY = Object.freeze({ provider: 'externalDeepSeek', displayName: 'DeepSeek',
  settingsNs: 'prime-inference', settingsPath: Object.freeze(['providers','externalDeepSeek']), declared: false });
export function mountDshCatalog(ctx) { return ctx.llm.registerConfigurableProviders([PROVIDER_DIRECTORY]); }

/** Official documentation metadata, not a paid-route qualification or an API availability test. */
export const DEEPSEEK_FLASH_MODEL = Object.freeze({ id: 'deepseek-flash', name: 'DeepSeek V4.1 Flash',
  status: 'unavailable', qualification: 'documentation_only',
  source: 'https://api-docs.deepseek.com/updates/', documented_release: '2026-09-10' });

export function providerCatalog() {
  return { version: 1, providers: [{ ...PROVIDER_DIRECTORY, active: false, endpoint: 'https://api.deepseek.com',
    credential_entry: 'separated_owner_handoff', paid_requests_enabled: false, models: [{ ...DEEPSEEK_FLASH_MODEL }],
    credential_status: 'unknown', pending: ['owner_auth_join','secure_credential_service','approved_numeric_spend_cap','qualified_route'] }],
    namespace: providerNamespace() };
}

/** Public/owner read view only. B owns conversion into the pinned settings schema protocol. */
export function providerNamespace({ profile = null, credential = { configured: false }, paid_requests_enabled = false } = {}) {
  const route = profile?.route;
  return { namespace: 'prime-inference', section: { providers: { externalDeepSeek: {
    endpoint: 'https://api.deepseek.com', model: route?.model ?? '', region: route?.region ?? '',
    allowedDataClasses: route?.allowed_data_classes ?? [], maxInputTokens: route?.max_input_tokens ?? 0,
    maxOutputTokens: route?.max_output_tokens ?? 0, maxRequests: route?.max_requests ?? 0,
    enabled: paid_requests_enabled === true, credentialConfigured: credential.configured === true,
    taskSpendCeiling: route?.task_spend_ceiling ?? null,
  } } } };
}

function configPayload(input, validateContract) {
  if (!input || Object.keys(input).sort().join(',') !== 'pricing,route' || typeof validateContract !== 'function') refuse('INVALID_PROVIDER_CONFIG');
  validateContract('ModelRoute',input.route);
  const { route, pricing } = input;
  // UI cannot elevate status. Exact approved configuration is a separate C-backed operation.
  if (route.status !== 'unavailable' || route.provider !== 'deepseek' || route.route_id !== 'externalDeepSeek'
      || route.endpoint !== 'https://api.deepseek.com' || !route.model || !route.region
      || !pricing || Object.keys(pricing).sort().join(',') !== 'input_microusd_per_token,max_request_ms,output_microusd_per_token,pricing_evidence_id,served_version,terms_evidence_id'
      || !integer(pricing.input_microusd_per_token,1) || !integer(pricing.output_microusd_per_token,1)
      || ![pricing.pricing_evidence_id,pricing.terms_evidence_id,pricing.served_version].every(id)
      || usdMicros(route.task_spend_ceiling) <= 0) refuse('INVALID_PROVIDER_CONFIG');
  // Validates endpoint, class list, empty tool list and ceilings without claiming a live paid route.
  fromPrimeRoute(route,{ ...pricing, mode: 'unavailable' });
  return structuredClone(input);
}

/** Owned app API has no method accepting a secret. C and private transport hooks are required for writes. */
export class OwnerProviderSettings {
  constructor({ path, validateContract, authenticateOwner, approveConfiguration, credentials, qualifiedDispatchStatus }) {
    this.db = openPrivateDatabase(path);
    this.db.exec('CREATE TABLE IF NOT EXISTS provider_configs(owner_id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL, operation_id TEXT NOT NULL);');
    this.validateContract = validateContract;
    this.authenticateOwner = authenticateOwner;
    this.approveConfiguration = approveConfiguration;
    this.credentials = credentials;
    this.qualifiedDispatchStatus = qualifiedDispatchStatus;
  }
  close() { this.db.close(); }
  catalog() { return providerCatalog(); }
  async owner(context) {
    if (typeof this.authenticateOwner !== 'function') refuse('OWNER_AUTH_UNAVAILABLE');
    let actor; try { actor = await this.authenticateOwner(context); } catch { refuse('OWNER_AUTH_REQUIRED'); }
    if (!actor || !id(actor.owner_id)) refuse('OWNER_AUTH_REQUIRED');
    return actor.owner_id;
  }
  async status(context) {
    const owner = await this.owner(context);
    const row = this.db.prepare('SELECT digest,payload FROM provider_configs WHERE owner_id=?').get(owner);
    let credential = { configured: false, generation: null };
    if (this.credentials?.status) credential = await this.credentials.status(owner,context);
    let ready = false;
    if (row && credential.configured === true && integer(credential.generation,1) && typeof this.qualifiedDispatchStatus === 'function') {
      const observed = await this.qualifiedDispatchStatus(owner,row.digest,credential.generation);
      ready = observed?.config_digest === row.digest && observed.credential_generation === credential.generation && observed.ready === true;
    }
    const status = { version: 1, provider: 'externalDeepSeek', configured: !!row,
      config_digest: row?.digest ?? null, profile: row ? JSON.parse(row.payload) : null,
      credential: { configured: credential.configured === true, generation: integer(credential.generation,1) ? credential.generation : null },
      paid_requests_enabled: ready, pending: ready ? [] : ['qualified_separated_dispatch_join'] };
    return { ...status, namespace: providerNamespace(status) };
  }
  async configure(context, input, approval_proof) {
    const owner = await this.owner(context), payload = configPayload(input,this.validateContract);
    const digest = 'sha256:' + hash('aukora-prime.inference-config.v1\0' + canonical(payload));
    if (typeof this.approveConfiguration !== 'function') refuse('OWNER_APPROVAL_UNAVAILABLE');
    let approved;
    try { approved = await this.approveConfiguration({ owner_id: owner, config_digest: digest,
      payload, approval_proof, context }); } catch { refuse('OWNER_APPROVAL_REQUIRED'); }
    if (approved?.owner_id !== owner || approved.config_digest !== digest || !id(approved.operation_id)) refuse('OWNER_APPROVAL_REQUIRED');
    transaction(this.db,() => this.db.prepare('INSERT INTO provider_configs VALUES(?,?,?,?) ON CONFLICT(owner_id) DO UPDATE SET digest=excluded.digest,payload=excluded.payload,operation_id=excluded.operation_id').run(owner,digest,canonical(payload),approved.operation_id));
    return { configured: true, config_digest: digest, paid_requests_enabled: false };
  }
  async credentialHandoff(context, { expected_generation, approval_proof }) {
    const owner = await this.owner(context);
    if (!integer(expected_generation) || typeof this.credentials?.createHandoff !== 'function') refuse('CREDENTIAL_SERVICE_UNAVAILABLE');
    // The worker authenticates/approves this owner action independently before issuing a one-use ticket.
    const value = await this.credentials.createHandoff({ owner_id: owner, expected_generation, approval_proof, context });
    if (!value || Object.keys(value).sort().join(',') !== 'expires_at,method,path,provider,ticket'
        || value.provider !== 'externalDeepSeek' || value.method !== 'POST' || value.path !== '/api/prime/inference/credential-entry'
        || typeof value.ticket !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.ticket)
        || typeof value.expires_at !== 'string' || !Number.isFinite(Date.parse(value.expires_at))) refuse('CREDENTIAL_SERVICE_UNAVAILABLE');
    return { provider: value.provider, method: value.method, path: value.path, ticket: value.ticket, expires_at: value.expires_at };
  }
  // Explicit application-layer refusal, including accidental generic credential bridges.
  setCredential() { refuse('SECRET_REQUIRES_SEPARATED_OWNER_ENTRY'); }
}
