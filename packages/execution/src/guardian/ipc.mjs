// SPDX-License-Identifier: AGPL-3.0-or-later
import { connect } from 'node:net'
import { randomUUID } from 'node:crypto'
import { canonicalJson,parseStrictJson } from '../../../contracts/src/runtime.mjs'
import { closed } from './registration.mjs'
import { refused } from '../policy.mjs'
export const MAX_MESSAGE_BYTES=8*1024*1024
export function decodeMessage(bytes) {
  if(bytes.length>MAX_MESSAGE_BYTES)throw refused('guardian message bound exceeded','INVALID')
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)
  if(text.startsWith('\uFEFF'))throw refused('guardian BOM refused','INVALID')
  return parseStrictJson(text,{maxBytes:MAX_MESSAGE_BYTES})
}
/** Private Unix IPC only. Socket permissions are a same-UID mechanism, not
 * authenticated cross-UID control or proof of an independent host principal. */
export async function guardianCall(socketPath,method,payload,{timeoutMs=1000}={}) {
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>120000)throw refused('bounded guardian call required','INVALID')
  const request={version:1,call_id:randomUUID(),method,payload}
  return new Promise((resolve,reject)=>{
    const socket=connect(socketPath);let chunks=[],size=0,done=false
    const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);socket.destroy();error?reject(error):resolve(value)}
    const timer=setTimeout(()=>finish(refused('guardian reply uncertain; registration must not authorize launch','RECONCILIATION_REQUIRED')),timeoutMs)
    socket.on('connect',()=>socket.end(canonicalJson(request)+'\n'))
    socket.on('error',error=>finish(error))
    socket.on('data',chunk=>{size+=chunk.length;if(size>MAX_MESSAGE_BYTES+1)finish(refused('guardian reply bound exceeded','INVALID'));else chunks.push(chunk)})
    socket.on('end',()=>{
      try {
        const bytes=Buffer.concat(chunks);if(bytes.at(-1)!==10)throw refused('guardian reply incomplete','INVALID')
        const reply=decodeMessage(bytes.subarray(0,-1))
        closed(reply,reply.ok?['version','call_id','ok','value']:['version','call_id','ok','error_code','reason'])
        if(reply.version!==1||reply.call_id!==request.call_id||typeof reply.ok!=='boolean')throw refused('guardian reply binding differs','INVALID')
        if(!reply.ok)throw refused(reply.reason,reply.error_code)
        finish(null,reply.value)
      } catch(error){finish(error)}
    })
    socket.on('close',()=>{if(!done)finish(refused('guardian reply lost','RECONCILIATION_REQUIRED'))})
  })
}
