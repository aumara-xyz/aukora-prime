import { createHash } from 'node:crypto';
import { validateContract, canonicalJson } from './shared.mjs';
export * from './shared.mjs';
export function operationBytes(proposal) { validateContract('OperationProposal',proposal); return Buffer.from('aukora-prime.operation.v1\0'+canonicalJson(proposal),'utf8'); }
export function operationDigest(proposal) {return 'sha256:'+createHash('sha256').update(operationBytes(proposal)).digest('hex');}


