export interface CaptureMetadata {readonly profile:'prime-pilot-memory-capture/v1';readonly category:'fact';readonly valid_from:string;readonly observed_at:string;readonly confidence_percent:70;readonly sensitivity:'none'}
export interface CaptureLiterals {readonly statement:string;readonly attributed_to:string}
export interface CaptureDraft extends CaptureLiterals {readonly capture_metadata:CaptureMetadata;readonly evidence_quote:string}
export const CAPTURE_STATEMENT_MAX:4096
export const CAPTURE_EVIDENCE_QUOTE_MAX:4096
export const CAPTURE_ATTRIBUTIONS:readonly string[]
export const CAPTURE_METADATA_FIELDS:readonly (keyof CaptureMetadata)[]
export const CAPTURE_DRAFT_FIELDS:readonly (keyof CaptureDraft)[]
export const CAPTURE_PARAMETER_FIELDS:readonly string[]
export const CAPTURE_TEXT_POLICY:Readonly<{scope:'new-capture-only';normal_form:'NFC-required-never-normalized';allowed_controls:readonly string[];allowed_format_controls:readonly string[];refused_fillers:readonly string[];refused_line_separators:readonly string[]}>
export function validateCaptureLiterals(draft:unknown):Readonly<CaptureLiterals>
export function validateCaptureMetadata(metadata:unknown):Readonly<CaptureMetadata>
export function validateCaptureDraft(draft:unknown):Readonly<CaptureDraft>
export function validateCaptureReview(parameters:unknown,immutableDraft:unknown):Readonly<CaptureDraft>
