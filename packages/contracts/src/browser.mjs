import {validateContract,canonicalJson} from './shared.mjs';
export * from './shared.mjs';
export function operationBytes(p){validateContract('OperationProposal',p);return new TextEncoder().encode('aukora-prime.operation.v1\0'+canonicalJson(p));}
export async function operationDigest(p){const b=await globalThis.crypto.subtle.digest('SHA-256',operationBytes(p));return 'sha256:'+Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');}
