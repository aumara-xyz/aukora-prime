export interface CaptureDraft {readonly statement:string;readonly attributed_to:string}
export const CAPTURE_STATEMENT_MAX:4096
export const CAPTURE_ATTRIBUTIONS:readonly string[]
export const CAPTURE_PARAMETER_FIELDS:readonly string[]
export function validateCaptureDraft(draft:unknown):Readonly<CaptureDraft>
export function validateCaptureReview(parameters:unknown,immutableDraft:unknown):Readonly<CaptureDraft>
