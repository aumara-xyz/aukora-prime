// SPDX-License-Identifier: AGPL-3.0-or-later
import { lstatSync, realpathSync } from 'node:fs'
import { resolve, relative, isAbsolute, join } from 'node:path'
import { readBytesStrict } from '../genesis/plugins/aukora-kira/lib/strict-read.mjs'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { parseOriginal, requireMemory, verifyChain, validateOriginal, MAX_BYTES } from './codecs.mjs'
import { makeSnapshot } from './snapshot.mjs'

/** Explicit source-file inventory only: no store discovery, writes, salting, or note rebuilding. */
export function snapshotReadOnlyKiraFiles({ directory, manifestBytes, owner_subject }) {
  requireMemory(typeof directory === 'string' && isAbsolute(directory) && !lstatSync(directory).isSymbolicLink()
    && lstatSync(directory).isDirectory(), 'memory:snapshot-directory-invalid')
  directory = realpathSync(directory)
  const manifest = parseOriginal(manifestBytes)
  requireMemory(manifest.owner_subject === owner_subject && Array.isArray(manifest.files)
    && manifest.files.length <= 10000, 'memory:source-manifest-invalid')
  const files = [{ path:'source-inventory.json',role:'original',bytes:Buffer.from(manifestBytes) }],heads = {},chains = new Map()
  let total = files[0].bytes.length
  for (const item of manifest.files) {
    requireMemory(typeof item.path === 'string' && !isAbsolute(item.path) && !item.path.split('/').includes('..'), 'memory:source-file-path-invalid')
    const path = join(directory,item.path),inside = relative(directory,path)
    requireMemory(inside && !inside.startsWith('..') && !isAbsolute(inside), 'memory:source-file-path-invalid')
    // Every parent must be a real directory; O_NOFOLLOW on the donor strict reader protects the leaf.
    let parent = directory
    for (const part of item.path.split('/').slice(0,-1)) {
      parent = join(parent,part)
      requireMemory(lstatSync(parent).isDirectory() && !lstatSync(parent).isSymbolicLink(), 'memory:source-file-symlink')
    }
    const { bytes } = readBytesStrict(path,{maxBytes:MAX_BYTES})
    total += bytes.length; requireMemory(total <= MAX_BYTES,'memory:snapshot-bytes-limit')
    const { object_value, event_line, include_line_terminator, ...metadata } = item
    if (object_value === true) {
      // Genesis memoryEffectBody's canonical wrapper is retained whole, and its literal inner bytes are selected.
      const wrapper = parseOriginal(bytes),text = bytes.toString('utf8')
      requireMemory(wrapper.key === wrapper.value?.recordId && text === canonicalJSON(wrapper)+'\n', 'memory:source-object-wrapper-invalid')
      const prefix = '{"key":'+JSON.stringify(wrapper.key)+',"value":'
      requireMemory(text.startsWith(prefix) && text.endsWith('}\n'), 'memory:source-object-wrapper-invalid')
      files.push({path:'original-objects/'+item.path,role:'original',bytes})
      files.push({...metadata,bytes:Buffer.from(text.slice(prefix.length,-2))})
    } else if (event_line !== undefined) {
      requireMemory(item.role === 'event' && Number.isSafeInteger(event_line) && event_line >= 0, 'memory:source-event-line-invalid')
      const text=bytes.toString('utf8'),lines=text.split('\n')
      requireMemory(event_line < lines.length && lines[event_line] !== '', 'memory:source-event-line-missing')
      files.push({path:'original-events/'+item.path,role:'original',bytes})
      files.push({...metadata,path:'selected-events/'+item.path+'/'+event_line+'.json',bytes:Buffer.from(lines[event_line]+(include_line_terminator===true?'\n':''))})
    } else files.push({...metadata,bytes})
  }
  for (const file of files.filter(f=>f.role==='chain')) {
    const checked=verifyChain(file.bytes,manifest.heads?.[file.chain_domain])
    requireMemory(!chains.has(file.chain_domain),'memory:source-chain-duplicate')
    chains.set(file.chain_domain,checked);heads[file.chain_domain]=checked.head
  }
  for (const file of files.filter(f=>f.role==='record')) {
    // No invalid historical record is rebuilt. It remains literal input for import quarantine.
    try {
      const meta=validateOriginal(file.bytes,owner_subject)
      file.record_id ??= meta.id;file.revision ??= 1
      const chain=chains.get(file.chain_domain)
      file.chain_sequence ??= (chain?.entries.findIndex(e => (e.id===meta.id || e.key===meta.id || e.recordId===meta.id)
        && (meta.tier!=='remembered' || e.entryHash===meta.record.aura?.entryHash)) ?? -1)+1
    } catch { /* importSnapshot retains bytes and records a named quarantine reason */ }
  }
  return makeSnapshot(owner_subject,files,heads)
}
