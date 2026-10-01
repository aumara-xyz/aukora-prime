// Reject invalid bytes before any JSON parser can replace or reinterpret them.
export function decodeStrictUtf8(input,{maxBytes=8388608}={}) {
 const bytes=input instanceof Uint8Array?input:new Uint8Array(input);
 if(bytes.byteLength>maxBytes || (bytes[0]===0xef&&bytes[1]===0xbb&&bytes[2]===0xbf))throw new TypeError('INVALID_UTF8');
 return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
}
export function parseIngressBytes(bytes,parser,{maxBytes=8388608,maxDepth=32}={}) {
 return parser(decodeStrictUtf8(bytes,{maxBytes}),{maxBytes,maxDepth});
}
const installed=new WeakSet();
export function installStrictGatewayWebSocketIngress(WebSocketServer,parser) {
 if(installed.has(WebSocketServer))return;
 installed.add(WebSocketServer);
 const original=WebSocketServer.prototype.handleUpgrade;
 WebSocketServer.prototype.handleUpgrade=function(request,socket,head,callback) {
  if(new URL(request.url,'http://prime.invalid').pathname!=='/api/remote.mux')return original.call(this,request,socket,head,callback);
  this.options.maxPayload=Math.min(this.options.maxPayload,8388608);
  return original.call(this,request,socket,head,websocket=>{
   const emit=websocket.emit;
   websocket.emit=function(event,...args) {
    if(event==='message') {
     try {
      if(args[1]!==false)throw new TypeError('TEXT_FRAME_REQUIRED');
      const raw=args[0];const bytes=Array.isArray(raw)?Buffer.concat(raw):raw;
      parseIngressBytes(bytes,parser);
     } catch {this.close(1008,'invalid JSON ingress');return false;}
    }
    return emit.call(this,event,...args);
   };
   callback(websocket);
  });
 };
}
