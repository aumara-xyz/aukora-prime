import { pathToFileURL } from 'node:url';
const module = await import(pathToFileURL(process.argv[2]).href);
const policyModule = await import(new URL('./post-rate-policy.mjs', pathToFileURL(process.argv[2])).href);
const store = module.createStore(process.argv[3], {}, { postRatePolicy: policyModule.POST_RATE_POLICY, now: () => Number(process.argv[5]) });
try {
  const result = store.post('gpt', { clientRequestId: process.argv[4], kind: 'chat', body: 'synthetic bounded concurrency', refs: [] });
  console.log(JSON.stringify({ ok: true, replayed: result.replayed, cursor: result.message.cursor }));
} catch (error) { console.log(JSON.stringify({ ok: false, code: error.code ?? 'internal_error', status: error.status ?? 500 })); }
finally { store.close(); }
