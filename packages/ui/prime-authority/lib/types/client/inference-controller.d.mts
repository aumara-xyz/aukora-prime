import type { Binding, Controller } from './controller.mjs'
import type { PilotInferenceResult } from './AumaReplyView'
export interface PilotInferenceContext {
  readonly owner_id:string
  readonly task_id:string
  readonly conversation_id:string
}
export type PilotInferenceAvailability =
  {readonly state:'unavailable';readonly mode:null;readonly reason:string}
  | {readonly state:'ready';readonly mode:'mock'|'production';readonly reason:string}
/** Presentation adapter for H's existing trusted native composition. This is
 * not an authentication, authorization, IPC or provider contract. */
export interface InferencePilotBinding {
  readonly ownerController:Controller
  readonly client:{
    readonly binding:Binding
    readonly context:PilotInferenceContext
    readonly availability:{
      getSnapshot():PilotInferenceAvailability
      subscribe(listener:()=>void):()=>void
    }
    requestOne(draft:Readonly<{request_uuid:string;text:string}>,options:{signal:AbortSignal}):Promise<PilotInferenceResult>
  }
}
export interface PilotInferenceSnapshot {
  readonly phase:'unavailable'|'idle'|'pending'|'completed'|'outcome_unknown'
  readonly generation:number
  readonly available:boolean
  readonly mode:'mock'|'production'|null
  readonly reason:string
  readonly context:PilotInferenceContext|null
  readonly request_uuid:string|null
  readonly result:PilotInferenceResult|null
}
export interface PilotInferenceController {
  getSnapshot():PilotInferenceSnapshot
  subscribe(listener:()=>void):()=>void
  connect(binding:InferencePilotBinding):()=>void
  disconnect():void
  request(text:string):Promise<PilotInferenceResult|null>
  dispose():void
}
export function createPilotInferenceController(options:{ownerController:Controller;isConnected:(binding:Binding)=>boolean;
  now?:()=>number;requestId?:()=>string}):PilotInferenceController
