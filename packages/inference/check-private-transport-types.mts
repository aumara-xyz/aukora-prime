// SPDX-License-Identifier: AGPL-3.0-or-later
// Compile-only consumer; never execute these declared inputs or mount a transport.
import { RemoteDeepSeekProvider, type ProviderReply, type ProviderRequest } from '@aukora-prime/inference';
import type { SeparatedCredentialService } from '@aukora-prime/inference/credential-service';
import {
  createPrivateInferenceDispatch, createPrivateInferenceReceiver,
  type PrivateInferenceDispatch,
} from '@aukora-prime/inference/private-transport';

declare const send: PrivateInferenceDispatch;
declare const service: SeparatedCredentialService;
declare const envelope: Omit<ProviderRequest, 'signal'>;
declare const signal: AbortSignal;

const dispatch: PrivateInferenceDispatch = createPrivateInferenceDispatch({
  send, max_request_ms: 1000, max_request_bytes: 65536,
});
const provider = new RemoteDeepSeekProvider({ dispatch });
const generated: Promise<ProviderReply> = provider.generate({ ...envelope, signal });
const receive: PrivateInferenceDispatch = createPrivateInferenceReceiver({
  service, max_request_bytes: 65536,
});
const received: Promise<ProviderReply> = receive(envelope, { signal });
const existingServiceDispatch: PrivateInferenceDispatch = (input, options) => service.dispatch(input, options);
const receiverWithBoundCallback = createPrivateInferenceReceiver({
  service: { dispatch: existingServiceDispatch }, max_request_bytes: 65536,
});

// @ts-expect-error Transport submission must return the existing provider reply, not authorization.
const booleanSend: PrivateInferenceDispatch = async () => true;
// @ts-expect-error A boolean cannot replace the protected submission callback.
createPrivateInferenceDispatch({ send: true, max_request_ms: 1000, max_request_bytes: 65536 });
// @ts-expect-error A receiver requires the existing service dispatch callback.
createPrivateInferenceReceiver({ service: { dispatch: true }, max_request_bytes: 65536 });
// @ts-expect-error Every application submission needs an explicit local cancellation scope.
dispatch(envelope);
// @ts-expect-error Empty options do not provide an AbortSignal.
dispatch(envelope, {});
// @ts-expect-error Receiver cancellation must be a real host-provided signal, not a wire boolean.
receive(envelope, { signal: true });
// @ts-expect-error Receiver calls also require their host cancellation scope.
receive(envelope);
