import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {once} from 'node:events';
import {decodeStrictUtf8,parseIngressBytes,installStrictGatewayWebSocketIngress} from './ingress.mjs';
import {parseStrictJson} from '../packages/contracts/src/runtime.mjs';
const require=createRequire(new URL('../vendor/dsh/packages/api/gateway/package.json',import.meta.url));
const {WebSocket,WebSocketServer}=require('ws');
assert.deepEqual(parseIngressBytes(Buffer.from('{"literal":"✓"}'),parseStrictJson),{literal:'✓'});
for(const bytes of [Buffer.from([0xef,0xbb,0xbf,0x7b,0x7d]),Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xc0,0xaf,0x22,0x7d])])assert.throws(()=>decodeStrictUtf8(bytes));
assert.throws(()=>parseIngressBytes(Buffer.from('{"payload":{"owner":"a","owner":"b"}}'),parseStrictJson),/duplicate/i);
assert.throws(()=>parseIngressBytes(Buffer.from('{"a":1,"\\u0061":2}'),parseStrictJson),/duplicate/i);
installStrictGatewayWebSocketIngress(WebSocketServer,parseStrictJson);
const server=createServer();const acceptor=new WebSocketServer({noServer:true});let dispatches=0;
server.on('upgrade',(request,socket,head)=>acceptor.handleUpgrade(request,socket,head,client=>{client.on('error',()=>{});client.on('message',()=>{dispatches++;client.send('accepted');});}));
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
const url='ws://127.0.0.1:'+server.address().port+'/api/remote.mux';
try {
 const valid=new WebSocket(url);valid.on('error',()=>{});await once(valid,'open');
 const message=once(valid,'message');valid.send('{"type":"open","streamId":"fixture","endpoint":"session/control","payload":{"args":{}}}');await message;
 assert.equal(dispatches,1);valid.close();await once(valid,'close');
 for(const [bytes,code] of [
  [Buffer.from('{"type":"open","type":"cancel","streamId":"fixture"}'),1008],
  [Buffer.from('{"payload":{"owner":"a","owner":"b"}}'),1008],
  [Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from('{}')]),1008],
  [Buffer.from([0xc0,0xaf]),1007],
 ]) {
  const client=new WebSocket(url);client.on('error',()=>{});await once(client,'open');
  const closed=once(client,'close');client.send(bytes,{binary:false});const [actual]=await closed;assert.equal(actual,code);assert.equal(dispatches,1);
 }
 assert.equal(acceptor.options.maxPayload,8388608);
 console.log(JSON.stringify({status:'PASS',checks:10,scope:'fatal UTF8, BOM and duplicate-key guards before actual pinned ws dispatch',runtime_qualification:'UNPERFORMED'}));
} finally {for(const client of acceptor.clients)client.terminate();await new Promise(resolve=>acceptor.close(resolve));await new Promise(resolve=>server.close(resolve));}
