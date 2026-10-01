// SPDX-License-Identifier: AGPL-3.0-or-later
// H injects the Prime-contained, pinned pg 8.16.3 Pool. No discovery or fallback.
const refuse = () => { throw Object.assign(new Error('PRIME_PEER_PG_POOL_REFUSED'), {code:'UNAVAILABLE'}) }

/** Only the assigned memory UID may use this exact synthetic Unix peer target. */
export function createPeerPgPool({Pool,memoryUid}={}) {
  if(typeof Pool!=='function' || !Number.isSafeInteger(memoryUid) || memoryUid<=0
      || typeof process.getuid!=='function' || process.getuid()!==memoryUid
      || Object.keys(process.env).some(name=>name.startsWith('PG'))) refuse()
  return new Pool({host:'/run/aukora-prime/postgres',port:55434,
    database:'aukora_prime_synthetic',user:'prime_memory',ssl:false,
    client_encoding:'UTF8',options:'-c search_path=public',replication:'false',
    // Truthy callback suppresses pg's inherited PGPASSWORD default; a password
    // challenge is a refusal. Correct peer authentication never calls it.
    password:refuse,max:6,min:0,connectionTimeoutMillis:3000,idleTimeoutMillis:10000,
    statement_timeout:10000,query_timeout:10000,
    application_name:'aukora-prime-memory-synthetic'})
}
