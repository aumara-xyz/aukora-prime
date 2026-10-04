// Cold verify: fresh context + fresh snapshot, no collector state reused beyond the store bytes.
const REL = process.env.AUKORA_RELEASE_DIR
const { verifyCollectorStore } = await import(`${REL}/scripts/aura/verify-collected.mjs`)
const { collectorContext } = await import('/etc/aukora-aura/context.mjs')
const c = await collectorContext()
const r = await verifyCollectorStore(c)
const line = `AURA COLD VERIFY ${r.ok ? 'PASS' : 'FAIL'} coverage=${r.coverage?.position ?? '-'} anchor=${r.anchor_status ?? '-'}(${r.anchors_checked ?? 0}) reason=${r.reason ?? '-'}`
console.log(line); console.log(JSON.stringify(r).slice(0, 1500)); process.exitCode = r.ok ? 0 : 2
