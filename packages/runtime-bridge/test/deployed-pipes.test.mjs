// SPDX-License-Identifier: AGPL-3.0-or-later
// Stream framing checks only; no authentication, process UID or PG proof.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {PassThrough,Writable} from 'node:stream'
import {createFixturePipe} from './deployed-pipes.mjs'

const observe=promise=>promise.then(value=>({value}),error=>({error}))
const failed=async(promise,reason)=>{const result=await observe(promise);assert.equal(result.error?.code,'FIXTURE_PIPE_REFUSED');if(reason)assert.equal(result.error.reason,reason)}
const line=(type,sequence,payload={})=>Buffer.from(JSON.stringify({version:1,sequence,type,payload})+'\n')
function one(t,options={}) {
  const readable=new PassThrough(),writable=new PassThrough(),output=[]
  writable.on('data',bytes=>output.push(Buffer.from(bytes)))
  const pipe=createFixturePipe({readable,writable,timeoutMs:100,...options});t.after(()=>pipe.close())
  return {pipe,readable,writable,output}
}
function pair(t,options={}) {
  const aToB=new PassThrough(),bToA=new PassThrough()
  const a=createFixturePipe({readable:bToA,writable:aToB,timeoutMs:100,...options})
  const b=createFixturePipe({readable:aToB,writable:bToA,timeoutMs:100,...options})
  t.after(()=>{a.close();b.close()});return {a,b}
}

test('strict LF peer exchanges detached object payloads and consecutive sequences',async t=>{
  const {a,b}=pair(t)
  const payload={kind:'login',nested:{nonce:'fixture'},text:'line one\nline two\ttab'}
  const answer=a.request(payload);payload.nested.nonce='changed'
  const first=await b.read();assert.equal(first.sequence,1);assert.equal(first.payload.nested.nonce,'fixture')
  await b.respond(first.sequence,{ok:true});assert.deepEqual(await answer,{ok:true})
  const second=a.request({kind:'approval'}),request=await b.read();assert.equal(request.sequence,2)
  await b.respond(request.sequence,{ok:true,material:{kind:'passkey'}})
  assert.deepEqual(await second,{ok:true,material:{kind:'passkey'}})
})

test('closed frames reject duplicate fields, trailing garbage, pollution keys, controls and invalid UTF-8',async t=>{
  const invalid=[
    '{"version":1,"sequence":1,"sequence":1,"type":"request","payload":{}}\n',
    '{"version":1,"sequence":1,"type":"request","payload":{}}x\n',
    '{"version":1,"sequence":1,"type":"request","payload":{"__proto__":{}}}\n',
    '{"version":1,"sequence":1,"type":"request","payload":{"x":"\\u0000"}}\n',
    '{"version":1,"sequence":1,"type":"request","payload":{},"extra":1}\n',
    '{"version":1,"sequence":1,"type":"report","payload":{}}\n',
    '{"version":1,"sequence":1,"type":"request","payload":[]}\n',
    '{"version":1,"sequence":1,"type":"request","payload":{}}\r\n',
    Buffer.from([0xff,10]),
  ]
  for(const bytes of invalid) {
    const f=one(t),pending=f.pipe.read();f.readable.write(bytes)
    await failed(pending);await failed(f.pipe.read());assert.equal(f.output.length,0)
  }
})

test('oversize partial input and encoded output are refused before further allocation or output',async t=>{
  const f=one(t,{maxBytes:128}),pending=f.pipe.read()
  f.readable.write(Buffer.alloc(129,32));await failed(pending,'PIPE_FRAME_BOUND')
  assert.equal(f.output.length,0)
  const out=one(t,{maxBytes:128})
  await failed(out.pipe.request({text:'x'.repeat(200)}),'PIPE_FRAME_BOUND');assert.equal(out.output.length,0)
})

test('request replay, skipped sequence, overlapping requests and wrong respond sequence close the peer',async t=>{
  for(const sequence of [0,2,33]) {
    const f=one(t),pending=f.pipe.read();f.readable.write(line('request',sequence));await failed(pending)
  }
  const replay=one(t);replay.readable.write(line('request',1));const first=await replay.pipe.read()
  await replay.pipe.respond(first.sequence,{});const pending=replay.pipe.read()
  replay.readable.write(line('request',1));await failed(pending,'PIPE_REQUEST_SEQUENCE')
  const overlap=one(t);overlap.readable.write(line('request',1));await overlap.pipe.read()
  overlap.readable.write(line('request',2));await failed(overlap.pipe.respond(1,{}),'PIPE_EXCHANGE_BUSY')
  const wrong=one(t);wrong.readable.write(line('request',1));await wrong.pipe.read()
  await failed(wrong.pipe.respond(2,{}),'PIPE_RESPONSE_UNEXPECTED')
})

test('responses require one matching pending request; local concurrent calls never resend',async t=>{
  const unsolicited=one(t),waiting=unsolicited.pipe.read()
  unsolicited.readable.write(line('response',1));await failed(waiting,'PIPE_RESPONSE_UNEXPECTED')
  const f=one(t),first=f.pipe.request({kind:'login'})
  await failed(f.pipe.request({kind:'approval'}),'PIPE_EXCHANGE_BUSY')
  assert.equal(f.output.length,1)
  f.readable.write(line('response',2));await failed(first,'PIPE_RESPONSE_UNEXPECTED')
  assert.equal(f.output.length,1)
  const duplicate=one(t),answer=duplicate.pipe.request({kind:'login'})
  duplicate.readable.write(line('response',1,{ok:true}));assert.deepEqual(await answer,{ok:true})
  duplicate.readable.write(line('response',1,{ok:true}));await failed(duplicate.pipe.read(),'PIPE_RESPONSE_UNEXPECTED')
})

test('read, request, partial frame and delivered-request deadlines are absolute; EOF never resends',async t=>{
  const idle=one(t,{timeoutMs:20});await failed(idle.pipe.read(),'PIPE_READ_TIMEOUT')
  const request=one(t,{timeoutMs:20});await failed(request.pipe.request({kind:'login'}),'PIPE_REQUEST_TIMEOUT')
  assert.equal(request.output.length,1);await failed(request.pipe.request({kind:'login'}),'PIPE_REQUEST_TIMEOUT');assert.equal(request.output.length,1)
  const partial=one(t,{timeoutMs:25});partial.readable.write('{')
  const trickle=setInterval(()=>{if(!partial.readable.destroyed)partial.readable.write(' ')},5);t.after(()=>clearInterval(trickle))
  await new Promise(resolve=>setTimeout(resolve,45));clearInterval(trickle)
  await failed(partial.pipe.read(),'PIPE_PARTIAL_TIMEOUT')
  const delivered=one(t,{timeoutMs:20});delivered.readable.write(line('request',1));await delivered.pipe.read()
  await new Promise(resolve=>setTimeout(resolve,35));await failed(delivered.pipe.respond(1,{}),'PIPE_RESPONSE_TIMEOUT')
  const eof=one(t),pending=eof.pipe.request({kind:'login'});eof.readable.end()
  await failed(pending,'PIPE_EOF');assert.equal(eof.output.length,1)
  await failed(eof.pipe.request({kind:'login'}),'PIPE_EOF');assert.equal(eof.output.length,1)
})

test('bounded frame count, simultaneous reads and stalled response writes cannot retain resources forever',async t=>{
  const {a,b}=pair(t,{maxFrames:1})
  const answer=a.request({}),request=await b.read();await b.respond(request.sequence,{});await answer
  await failed(a.request({}),'PIPE_FRAME_COUNT')
  const read=one(t),pending=read.pipe.read();await failed(read.pipe.read(),'PIPE_EXCHANGE_BUSY')
  read.pipe.close();await failed(pending,'PIPE_CLOSED')
  const input=new PassThrough(),blocked=new Writable({write(_chunk,_encoding,_callback){}})
  const stalled=createFixturePipe({readable:input,writable:blocked,timeoutMs:20});t.after(()=>stalled.close())
  input.write(line('request',1));const incoming=await stalled.read()
  await failed(stalled.respond(incoming.sequence,{ok:true}),'PIPE_WRITE_TIMEOUT')
})
