// Disposable presentation fixture only. Never imported by the native production client.
export function createOwnerUiFixture(contracts, { now = Date.now, outcome = 'approved', loginGate, approvalGate } = {}) {
  const counts = { login: 0, review: 0, approve: 0, decline: 0 }
  const expiry = new Date(now() + 300000).toISOString()
  const operation = Object.freeze({ version: 1, operation_id: 'ui-fixture-operation', task_id: 'ui-fixture-task', owner_id: 'ui-fixture-owner',
    agent_id: 'ui-fixture-agent', audience: 'prime:fixture', action_type: 'fixture.review',
    target_identity: { scope: 'disposable', record: '<exact public fixture>' },
    canonical_parameters: { text: '<script>must remain literal text</script>', lines: 'one\ntwo', count: 3 },
    data_scope: ['public-fixture'], expected_state_version: 'fixture-v1', provider_and_region: { provider: 'none', region: 'none' },
    maximum_cost: { currency: 'USD', amount: '0.00' }, expiry, nonce: 'fixture-original-operation-nonce', policy_version: 'fixture-v1', authorization_epoch: 1 })
  const authority = {
    async loginChallenge({owner_id,kind}) {
      if (kind !== 'passkey') return {ok:false,error_code:'UNAVAILABLE',reason:'No owner-key fallback in this fixture.'}
      return {ok:true,challenge:{version:1,owner_id,audience:'prime:login',challenge:'fixture-login',issued_at:new Date(now()).toISOString(),expiry,authorization_epoch:1}}
    },
    async loginComplete({challenge}) { counts.login++; await loginGate; return {ok:true,owner_id:challenge.owner_id,session_token:'synthetic-in-memory-only',expiry} },
    async approvalChallenge({operation}) {
      counts.review++
      const operation_digest = await contracts.operationDigest(operation)
      const issuedAt = Math.floor(now()/1000), expiresAt = Math.min(issuedAt + 120,Math.floor(Date.parse(operation.expiry)/1000))
      const approval_request = {domain:'aukora:owner-approval-request:v1',subject:'aukora:1:'+'1'.repeat(64),activeControlDigest:'2'.repeat(64),
        operationDigest:operation_digest.slice(7),challenge:counts.review.toString(16).padStart(64,'0'),issuedAt,expiresAt}
      return {ok:true,operation,operation_digest,approval_request,proof_template:{version:1,operation_id:operation.operation_id,operation_digest,
        owner_id:operation.owner_id,audience:operation.audience,authorization_epoch:operation.authorization_epoch,
        expiry:new Date(expiresAt*1000).toISOString(),nonce:approval_request.challenge,material:{kind:'passkey'}}}
    },
    async approvalComplete({proof}) { counts.approve++; await approvalGate; if(outcome==='unknown') throw new Error('Disposable lost reply');
      return {ok:true,status:'APPROVED',approval_proof:proof} },
    async declineApproval() { counts.decline++; return {ok:true,status:'DENIED'} },
  }
  return {authority,contracts,owner_id:operation.owner_id,operation,fixture:true,counts,
    passkeySigner:async()=>({kind:'passkey',credential_id:'Zml4dHVyZQ',client_data_json:'Zml4dHVyZQ',authenticator_data:'Zml4dHVyZQ',signature:'Zml4dHVyZQ',user_handle:null})}
}
