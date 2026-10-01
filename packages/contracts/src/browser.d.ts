export * from './index.js';
import type {Digest, OperationProposal} from './index.js';
export function operationDigest(proposal: OperationProposal): Promise<Digest>;
