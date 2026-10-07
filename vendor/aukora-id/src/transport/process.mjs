import { Socket } from 'node:net';
import { createFrameDecoder, encodeFrame } from './framing.mjs';
import { createEvidenceReceiver, diagnosticCode } from './receiver.mjs';

// Trusted transport process. Inherited fd3/fd4 are the only peer data channels;
// no bind/listen/connect, keys, journal, aperture or plugin loader is used here.
let inbound, outbound, decoder, receiver, deadline, closing = false, writing = false;
let frames = 0;
const send = message => { if (process.connected) process.send(message, error => { if (error) close(); }); };
function close() {
  if (closing) return;
  closing = true; clearTimeout(deadline); decoder?.close(); inbound?.destroy(); outbound?.destroy();
  if (process.connected) process.disconnect();
}
function refuse(error) { send({ type: 'transport_error', code: diagnosticCode(error) }); close(); }
process.on('message', message => {
  if (closing) return;
  try {
    if (message?.command === 'start' && !receiver) {
      receiver = createEvidenceReceiver(message.contexts);
      inbound = new Socket({ fd: 3, readable: true, writable: false });
      outbound = new Socket({ fd: 4, readable: false, writable: true });
      decoder = createFrameDecoder((event, evidence) => {
        if (++frames > 128) throw Object.assign(new Error(), { code: 'LIMIT_EXCEEDED' });
        const result = receiver.receive(event, evidence);
        send({ type: 'delivery', receiver_pid: process.pid, result });
      });
      inbound.on('data', chunk => {
        try {
          // A partial frame has a fixed deadline; later fragments cannot extend it.
          decoder.push(chunk);
          if (!decoder.partial) { clearTimeout(deadline); deadline = null; }
          else if (!deadline) deadline = setTimeout(() => refuse({ code: 'LIMIT_EXCEEDED' }), 5000);
        } catch (error) { refuse(error); }
      });
      inbound.on('end', () => { try { decoder.end(); close(); } catch (error) { refuse(error); } });
      inbound.on('error', refuse); outbound.on('error', refuse);
      send({ type: 'ready', pid: process.pid });
    } else if (message?.command === 'publish' && receiver) {
      // Controller publishes already signed bytes. We never create a signature.
      if (writing) throw Object.assign(new Error(), { code: 'LIMIT_EXCEEDED' });
      const frame = encodeFrame(message.event, message.evidence); writing = true;
      outbound.write(frame, error => { writing = false; frame.fill(0); if (error) refuse(error); });
    } else if (message?.command === 'close') close();
    else throw Object.assign(new Error(), { code: 'WRONG_AUTHORITY' });
  } catch (error) { refuse(error); }
});
process.on('disconnect', close);
process.on('SIGTERM', close);
process.on('SIGINT', close);
