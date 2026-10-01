// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { requireMemory, parseOriginal, MAX_BYTES } from './codecs.mjs'

/** Offline evidence integrity, never an authorization or presence check. Anchor is supplied separately. */
export async function verifyDiamondEvidence({ recordBytes, receiptBytes, logBytes, issuerAnchor, python = 'python3' }) {
  requireMemory(typeof issuerAnchor === 'string' && issuerAnchor.length > 0, 'memory:diamond-anchor-required')
  const values = [recordBytes,receiptBytes,logBytes,Buffer.from(issuerAnchor)]
  requireMemory(values.every(v => v && Buffer.byteLength(v) <= MAX_BYTES), 'memory:diamond-evidence-limit')
  const directory = await mkdtemp(join(tmpdir(),'prime-diamond-cold-'))
  try {
    const files = ['record.json','receipt.json','aura.jsonl','issuer.pub'].map(f => join(directory,f))
    for (let i=0;i<files.length;i++) await writeFile(files[i],values[i],{mode:0o600})
    const { stdout } = await promisify(execFile)(python,[fileURLToPath(new URL('../bin/diamond-verify.py',import.meta.url)),...files],
      { cwd:directory,timeout:30000,maxBuffer:2*1024*1024,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'} })
    const report = parseOriginal(Buffer.from(stdout))
    return { verdict:report.verified === true ? 'VERIFIED' : 'UNVERIFIED', reason:report.refusal?.code ?? null,
      report, grants_authority:false }
  } catch {
    return {verdict:'UNVERIFIED',reason:'memory:diamond-process-unavailable',grants_authority:false}
  } finally { await rm(directory,{recursive:true,force:true}) }
}
