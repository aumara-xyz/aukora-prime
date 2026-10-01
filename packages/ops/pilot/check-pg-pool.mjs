import assert from 'node:assert/strict'
import {createPeerPgPool} from './pg-pool.mjs'
let constructed=0
class SyntheticPool { constructor(options) { constructed++;this.options=options } }
const saved=Object.fromEntries(Object.entries(process.env).filter(([k])=>k.startsWith('PG')))
for(const key of Object.keys(saved))delete process.env[key]
try {
  const memoryUid=process.getuid()
  assert.throws(()=>createPeerPgPool({Pool:SyntheticPool,memoryUid:memoryUid+1}),/PRIME_PEER_PG_POOL_REFUSED/)
  const pool=createPeerPgPool({Pool:SyntheticPool,memoryUid})
  assert.equal(pool.options.host,'/run/aukora-prime/postgres')
  assert.equal(pool.options.database,'aukora_prime_synthetic')
  assert.equal(pool.options.user,'prime_memory')
  assert.equal(pool.options.port,55434)
  assert.equal(pool.options.ssl,false)
  assert.equal(pool.options.max,6)
  assert.equal(pool.options.connectionTimeoutMillis,3000)
  assert.equal(pool.options.query_timeout,10000)
  assert.throws(()=>pool.options.password(),/PRIME_PEER_PG_POOL_REFUSED/)
  for(const key of ['PGHOST','PGOPTIONS','PGPASSWORD']) {
    process.env[key]='synthetic-not-used'
    assert.throws(()=>createPeerPgPool({Pool:SyntheticPool,memoryUid}),/PRIME_PEER_PG_POOL_REFUSED/)
    delete process.env[key]
  }
  assert.equal(constructed,1)
  console.log(JSON.stringify({status:'SOURCE_CHECK_PASS',checks:5,actual_pg:'NOT_RUN',cross_uid:'PENDING'}))
} finally {Object.assign(process.env,saved)}
