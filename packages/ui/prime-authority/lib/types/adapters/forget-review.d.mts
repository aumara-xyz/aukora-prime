export interface ForgetRecordSummary {readonly record_id:string;readonly revision:string;readonly statement:string;readonly attributed_to:string|null}
export const FORGET_PROFILE:'prime-logical-forget/v1'
export const FORGET_STATEMENT_MAX_BYTES:16384
export const FORGET_REFERENCE_MAX_BYTES:1024
export const FORGET_SUMMARY_FIELDS:readonly string[]
export const FORGET_PARAMETER_FIELDS:readonly string[]
export function validateForgetReview(operation:unknown,independentlyRetainedRecordSummary:unknown):Readonly<ForgetRecordSummary>
