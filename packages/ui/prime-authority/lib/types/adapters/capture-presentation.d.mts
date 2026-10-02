export interface FormatControlExample {readonly index:number;readonly code_point:string}
export interface LookalikeExample extends FormatControlExample {readonly resembles:string;readonly script:string|null}
export interface MixedScriptExample {readonly index:number;readonly length:number;readonly scripts:readonly string[]}
export type CapturePresentationExample=FormatControlExample|LookalikeExample|MixedScriptExample
export interface CapturePresentationWarning {readonly code:'format-controls'|'ascii-lookalikes'|'mixed-scripts';readonly count:number;readonly examples:readonly CapturePresentationExample[];readonly text:string}
export function capturePresentationWarnings(statement:string):readonly CapturePresentationWarning[]
