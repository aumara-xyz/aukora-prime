// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable fixture protocol over owned anonymous child stdio. No socket,
// identity, credentials, signing or process launch belongs to this module.
import {Readable,Writable} from 'node:stream'
import {canonicalJson,parseStrictJson} from '../../contracts/src/runtime.mjs'

const refusal=reason=>Object.assign(new Error(reason),{code:'FIXTURE_PIPE_REFUSED',reason})
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value))
function safePayload(value) {
  if(!object(value))throw refusal('PIPE_PAYLOAD_OBJECT_REQUIRED')
  const walk=node=>{
    if(typeof node==='string'&&/[\u0000-\u0008\u000b-\u001f\u007f]/u.test(node))throw refusal('PIPE_CONTROL_REFUSED')
    if(node&&typeof node==='object')for(const [key,child] of Object.entries(node)) {
      if(['__proto__','prototype','constructor'].includes(key))throw refusal('PIPE_PROTOTYPE_REFUSED')
      walk(child)
    }
  }
  walk(value)
}

/** JSON line body is bounded by maxBytes, excluding LF. Both wire directions
 * have at most maxFrames frames and sequence range 1..maxFrames (never >32).
 * read() returns {sequence,payload}; request() returns the matching payload.
 * close() owns/destroys both supplied streams. Failure is terminal, no resend.
 */
export function createFixturePipe(options) {
  if(!object(options)||Reflect.ownKeys(options).some(key=>typeof key!=='string'||!['readable','writable','timeoutMs','maxFrames','maxBytes'].includes(key)))throw refusal('PIPE_OPTIONS_INVALID')
  const {readable,writable,timeoutMs=30_000,maxFrames=32,maxBytes=65_536}=options
  if(!(readable instanceof Readable)||!(writable instanceof Writable)||readable.readableEncoding||
    !Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>30_000||
    !Number.isSafeInteger(maxFrames)||maxFrames<1||maxFrames>32||
    !Number.isSafeInteger(maxBytes)||maxBytes<64||maxBytes>65_536)throw refusal('PIPE_OPTIONS_INVALID')
  let failed=null,buffer=Buffer.alloc(0),partialTimer=null,inputFrames=0,outputFrames=0
  let sentSequence=0,receivedSequence=0,pending=null,reader=null,incoming=null
  const writes=new Set(),decoder=new TextDecoder('utf-8',{fatal:true})
  function stop(reason='PIPE_CLOSED') {
    if(failed)return
    failed=refusal(reason);clearTimeout(partialTimer);partialTimer=null;buffer=Buffer.alloc(0)
    for(const value of [pending,reader,incoming])if(value)clearTimeout(value.timer)
    pending?.reject(failed);reader?.reject(failed);pending=null;reader=null;incoming=null
    for(const value of writes){clearTimeout(value.timer);value.reject(failed)}writes.clear()
    readable.removeListener('data',data)
    readable.destroy();if(writable!==readable)writable.destroy()
  }
  const deadline=(reason)=>setTimeout(()=>stop(reason),timeoutMs)
  function encode(type,sequence,payload) {
    // Canonicalization checks descriptors before any payload traversal.
    const text=canonicalJson({version:1,sequence,type,payload})
    if(Buffer.byteLength(text)>maxBytes)throw refusal('PIPE_FRAME_BOUND')
    const detached=parseStrictJson(text,{maxBytes,maxDepth:32});safePayload(detached.payload)
    return Buffer.from(text+'\n')
  }
  function write(type,sequence,payload) {
    return new Promise((resolve,reject)=>{
      if(failed){reject(failed);return}
      let bytes
      try {bytes=encode(type,sequence,payload);if(++outputFrames>maxFrames)throw refusal('PIPE_FRAME_COUNT')}
      catch(error){stop(error.reason??'PIPE_FRAME_INVALID');reject(failed);return}
      const value={reject,timer:deadline('PIPE_WRITE_TIMEOUT')};writes.add(value)
      try {writable.write(bytes,error=>{
        if(!writes.delete(value))return
        clearTimeout(value.timer)
        if(error){stop('PIPE_WRITE_FAILED');reject(failed)}else resolve()
      })} catch {writes.delete(value);clearTimeout(value.timer);stop('PIPE_WRITE_FAILED');reject(failed)}
    })
  }
  function deliver() {
    if(reader&&incoming&&!incoming.delivered) {
      const waiting=reader;reader=null;clearTimeout(waiting.timer);incoming.delivered=true
      waiting.resolve({sequence:incoming.sequence,payload:incoming.payload})
    }
  }
  function frame(bytes) {
    if(++inputFrames>maxFrames)throw refusal('PIPE_FRAME_COUNT')
    const text=decoder.decode(bytes)
    if(!text.length||/[\u0000-\u001f\u007f]/u.test(text))throw refusal('PIPE_CONTROL_REFUSED')
    const value=parseStrictJson(text,{maxBytes,maxDepth:32})
    if(!object(value)||Reflect.ownKeys(value).length!==4||!['version','sequence','type','payload'].every(key=>Object.hasOwn(value,key))||value.version!==1||
      !Number.isSafeInteger(value.sequence)||value.sequence<1||value.sequence>maxFrames||!['request','response'].includes(value.type))throw refusal('PIPE_FRAME_INVALID')
    safePayload(value.payload)
    if(value.type==='response') {
      if(!pending||value.sequence!==pending.sequence)throw refusal('PIPE_RESPONSE_UNEXPECTED')
      const waiting=pending;pending=null;clearTimeout(waiting.timer);waiting.resolve(value.payload)
    } else {
      if(pending||incoming)throw refusal('PIPE_EXCHANGE_BUSY')
      if(value.sequence!==receivedSequence+1)throw refusal('PIPE_REQUEST_SEQUENCE')
      receivedSequence=value.sequence
      incoming={sequence:value.sequence,payload:value.payload,delivered:false,timer:deadline('PIPE_RESPONSE_TIMEOUT')}
      deliver()
    }
  }
  function data(chunk) {
    if(failed)return
    if(!Buffer.isBuffer(chunk)&&!(chunk instanceof Uint8Array)){stop('PIPE_RAW_BYTES_REQUIRED');return}
    const bytes=Buffer.from(chunk.buffer,chunk.byteOffset,chunk.byteLength)
    let offset=0
    try {
      while(offset<bytes.length&&!failed) {
        const lf=bytes.indexOf(10,offset),end=lf<0?bytes.length:lf,part=bytes.subarray(offset,end)
        if(buffer.length+part.length>maxBytes)throw refusal('PIPE_FRAME_BOUND')
        if(part.length&&!buffer.length&&!partialTimer)partialTimer=deadline('PIPE_PARTIAL_TIMEOUT')
        if(part.length)buffer=buffer.length?Buffer.concat([buffer,part]):Buffer.from(part)
        if(lf<0)break
        clearTimeout(partialTimer);partialTimer=null
        const complete=buffer;buffer=Buffer.alloc(0);frame(complete);offset=lf+1
      }
    } catch(error){stop(error.reason??'PIPE_FRAME_INVALID')}
  }
  readable.on('data',data)
  readable.on('end',()=>stop('PIPE_EOF'))
  readable.on('close',()=>stop('PIPE_EOF'))
  readable.on('error',()=>stop('PIPE_READ_FAILED'))
  if(writable!==readable) {
    writable.on('error',()=>stop('PIPE_WRITE_FAILED'))
    writable.on('close',()=>stop('PIPE_EOF'))
  }
  return Object.freeze({
    request(payload) {
      if(failed)return Promise.reject(failed)
      if(pending||incoming||reader)return Promise.reject(refusal('PIPE_EXCHANGE_BUSY'))
      if(sentSequence>=maxFrames){stop('PIPE_FRAME_COUNT');return Promise.reject(failed)}
      const sequence=++sentSequence
      const promise=new Promise((resolve,reject)=>{pending={sequence,resolve,reject,timer:deadline('PIPE_REQUEST_TIMEOUT')}})
      write('request',sequence,payload).catch(()=>{})
      return promise
    },
    read() {
      if(failed)return Promise.reject(failed)
      if(reader||pending||incoming?.delivered)return Promise.reject(refusal('PIPE_EXCHANGE_BUSY'))
      const promise=new Promise((resolve,reject)=>{reader={resolve,reject,timer:deadline('PIPE_READ_TIMEOUT')}})
      deliver();return promise
    },
    respond(sequence,payload) {
      if(failed)return Promise.reject(failed)
      if(!incoming?.delivered||incoming.sequence!==sequence){stop('PIPE_RESPONSE_UNEXPECTED');return Promise.reject(failed)}
      const waiting=incoming;incoming=null;clearTimeout(waiting.timer)
      return write('response',sequence,payload)
    },
    close(){stop()},
  })
}
