import type {CaptureDraft} from './capture-review.mjs'
/** Equality against retained NEW review; original donor bytes are never rewritten. */
export function validateSavedCaptureContent<T>(record:T, memoryDraft:CaptureDraft):T
export function validateSaveRecovery<T>(result:T, context:{presentation:unknown;approved:boolean;proofNonce:string;contracts:any}):Promise<T>
