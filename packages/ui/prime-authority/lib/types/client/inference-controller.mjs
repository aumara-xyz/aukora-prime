// SPDX-License-Identifier: AGPL-3.0-or-later
// Transient native UI state only. H supplies the existing owner/task-bound
// client and its approval flow; this module has no transport or signing code.
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const id = value => typeof value === 'string' && value.length > 0;
const keyOf = context => JSON.stringify([context.owner_id,context.task_id,context.conversation_id]);
const freeze = value => {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
};
const initial = () => Object.freeze({phase:'unavailable',available:false,mode:null,generation:0,
  reason:'The host has not supplied an owner-bound reply client.',context:null,request_uuid:null,result:null});

// Display compatibility checks are not authority or provider verification.
function displayResult(value,flight) {
  const {request_uuid,context,mode} = flight;
  if (!value || value.request_uuid !== request_uuid || value.receipt?.request_uuid !== request_uuid
      || value.receipt.sessionId !== context.conversation_id
      || value.receipt.source_citation?.sessionId !== context.conversation_id) return false;
  if (value.outcome === 'outcome_unknown') return value.reservation_retained === true && typeof value.error === 'string';
  return value.outcome === 'completed' && value.mode === mode && value.route_id === 'externalDeepSeek'
    && typeof value.proposal?.text === 'string' && value.proposal.grantsAuthority === false
    && Array.isArray(value.proposal.source_ids) && value.proposal.source_ids.every(id)
    && [value.usage?.input_tokens,value.usage?.output_tokens,value.usage?.cost_microusd]
      .every(number => Number.isSafeInteger(number) && number >= 0)
    && Array.isArray(value.omitted);
}

export function createPilotInferenceController({ownerController,isConnected,now=Date.now,
  requestId=() => globalThis.crypto?.randomUUID()}={}) {
  if (!ownerController || typeof ownerController.getSnapshot !== 'function'
      || typeof ownerController.subscribe !== 'function' || typeof isConnected !== 'function') {
    throw new TypeError('An existing native owner controller and connection predicate are required.');
  }
  let state = initial(), frame, flight, disposed = false, generation = 0;
  const listeners = new Set();
  const usedRequests = new Set();
  // Retain only request identity, never prompt/result/session material. Removing
  // a UI lifetime is not evidence that an entered provider request did not run.
  const unresolved = new Map();
  const emit = next => {state=Object.freeze({...next,generation});for (const listener of [...listeners]) listener();};
  const currentOwner = selected => {
    try {
      const value = ownerController.getSnapshot(), owner = value.owner;
      if (disposed || frame !== selected || selected.binding.ownerController !== ownerController
          || selected.client.binding !== selected.authority || !isConnected(selected.authority)
          || !owner || owner.owner_id !== selected.context.owner_id || value.owner_id !== selected.context.owner_id
          || !value.authority_available || value.expired || value.logout_status === 'pending'
          || !Number.isFinite(Date.parse(owner.expiry)) || Date.parse(owner.expiry) <= now()
          || selected.client.context?.owner_id !== selected.context.owner_id
          || selected.client.context?.task_id !== selected.context.task_id
          || selected.client.context?.conversation_id !== selected.context.conversation_id
          || selected.client.availability !== selected.store || selected.client.requestOne !== selected.method) return null;
      return owner;
    } catch {return null;}
  };
  const availability = selected => {
    try {
      const value = selected.store.getSnapshot();
      return value && typeof value.reason === 'string'
        && ((value.state === 'ready' && ['mock','production'].includes(value.mode))
          || (value.state === 'unavailable' && value.mode === null)) ? value : null;
    } catch {return null;}
  };
  const invalidate = () => {
    const previous = flight;
    if (!previous) return;
    flight = undefined;
    if (previous.entered) unresolved.set(keyOf(previous.context),previous.request_uuid);
    previous.abort.abort();previous.resolve(null);
  };
  const live = candidate => !disposed && flight === candidate && frame === candidate.frame
    && currentOwner(candidate.frame) === candidate.owner
    && availability(candidate.frame) === candidate.availability && !candidate.abort.signal.aborted;
  function refresh() {
    const selected = frame;
    const owner = selected && currentOwner(selected);
    const ready = owner && availability(selected);
    if (flight && (flight.frame !== selected || flight.owner !== owner || flight.availability !== ready)) {
      invalidate();refresh();return;
    }
    if (frame !== selected || disposed) return;
    if (!selected || !owner) {
      if (selected?.owner) {selected.owner = null;generation++;}
      emit({...initial(),reason:selected ? 'Sign in with the current configured owner and native connection before requesting a reply.' : initial().reason});
      return;
    }
    if (selected.owner !== owner) {
      generation++;
      selected.owner = owner;
      state = initial();
    }
    const blocked = unresolved.get(keyOf(selected.context));
    if (blocked) {
      emit({phase:'outcome_unknown',available:false,mode:ready?.mode ?? null,context:selected.context,
        request_uuid:blocked,result:state.result?.request_uuid === blocked ? state.result : null,
        reason:'The previous request is unconfirmed. Do not retry it; the host must reconcile its existing request.'});
      return;
    }
    if (flight) return;
    if (!ready || ready.state !== 'ready') {
      emit({phase:'unavailable',available:false,mode:null,context:selected.context,request_uuid:null,result:null,
        reason:ready?.reason || 'The host has not made the owner-bound provider and approval flow available.'});
      return;
    }
    const ownerState = ownerController.getSnapshot();
    const ownerBusy = ownerState.approval_action_pending || ownerState.phase?.endsWith('_pending')
      || ownerState.phase === 'outcome_unknown';
    emit({phase:state.result?.outcome === 'completed' ? 'completed' : ownerBusy ? 'unavailable' : 'idle',available:!ownerBusy,mode:ready.mode,
      context:selected.context,request_uuid:state.result?.request_uuid ?? null,result:state.result,
      reason:ownerBusy ? 'Complete or reconcile the current owner operation before requesting another reply.' : ready.reason});
  }
  const offOwner = ownerController.subscribe(refresh);
  const detach = () => {
    const old = frame;frame=undefined;
    const detachedGeneration = ++generation;
    invalidate();
    old?.off?.();
    return detachedGeneration;
  };
  return Object.freeze({
    getSnapshot:() => state,
    subscribe(listener) {listeners.add(listener);return () => listeners.delete(listener);},
    connect(binding) {
      if (disposed) return () => {};
      const detachedGeneration = detach();
      if (disposed || generation !== detachedGeneration) return () => {};
      const client = binding?.client, context = client?.context;
      if (binding?.ownerController !== ownerController || !client?.binding
          || ![context?.owner_id,context?.task_id,context?.conversation_id].every(id)
          || client.binding.owner_id !== context.owner_id || typeof client.requestOne !== 'function'
          || typeof client.availability?.getSnapshot !== 'function' || typeof client.availability?.subscribe !== 'function') {
        emit({...initial(),reason:'The supplied reply client does not match this native owner and task context.'});
        return () => {};
      }
      const selected = {binding,client,authority:client.binding,context:Object.freeze({owner_id:context.owner_id,
        task_id:context.task_id,conversation_id:context.conversation_id}),
        store:client.availability,method:client.requestOne,owner:null,off:null};
      frame=selected;state=initial();
      try {
        const off = selected.store.subscribe(refresh);
        if (typeof off !== 'function') throw new TypeError('Availability subscription is unavailable.');
        if (frame !== selected || disposed) {off();return () => {};}
        selected.off=off;refresh();
      } catch {
        if (frame === selected) {
          const detachedGeneration = detach();
          if (generation === detachedGeneration && !disposed) emit({...initial(),reason:'The host reply availability could not be observed.'});
        }
      }
      return () => {
        if (frame === selected) {
          const detachedGeneration = detach();
          if (generation === detachedGeneration && !disposed) emit(initial());
        }
      };
    },
    disconnect() {
      if (disposed) return;
      const detachedGeneration = detach();
      if (generation === detachedGeneration) emit(initial());
    },
    request(text) {
      if (flight) return flight.promise;
      refresh();
      const selected = frame, owner = selected && currentOwner(selected), ready = owner && availability(selected);
      if (!selected || !owner || !state.available || ready?.state !== 'ready'
          || typeof text !== 'string' || !text.trim()) return Promise.resolve(null);
      let request_uuid;
      try {request_uuid=requestId();} catch {request_uuid=null;}
      if (!uuid(request_uuid) || usedRequests.has(request_uuid)) {
        emit({...state,reason:'A fresh request identity could not be created. No request was sent.'});
        return Promise.resolve(null);
      }
      usedRequests.add(request_uuid);
      let resolve;
      const promise = new Promise(done => {resolve=done;});
      const draft = Object.freeze({request_uuid,text});
      const attempt = {frame:selected,owner,availability:ready,context:selected.context,mode:ready.mode,
        request_uuid,draft,abort:new AbortController(),entered:false,promise,resolve};
      flight=attempt;
      emit({phase:'pending',available:false,mode:ready.mode,context:selected.context,request_uuid,result:null,
        reason:'One request is pending. Complete its existing exact-operation review when the host presents it.'});
      void Promise.resolve().then(async () => {
        if (!live(attempt)) {if (flight === attempt) {invalidate();refresh();}return;}
        attempt.entered=true;
        try {
          const reply = await selected.method.call(selected.client,draft,{signal:attempt.abort.signal});
          if (!live(attempt)) {if (flight === attempt) {invalidate();refresh();}return;}
          const result = structuredClone(reply);
          if (!displayResult(result,attempt)) throw new TypeError('Unconfirmed reply projection.');
          freeze(result);flight=undefined;
          if (result.outcome === 'outcome_unknown') unresolved.set(keyOf(attempt.context),request_uuid);
          emit({phase:result.outcome === 'completed' ? 'completed' : 'outcome_unknown',
            available:result.outcome === 'completed',mode:attempt.mode,context:attempt.context,request_uuid,result,
            reason:result.outcome === 'completed' ? ready.reason : 'The host reports an unknown outcome. Do not retry this request.'});
          attempt.resolve(frame === selected && currentOwner(selected) === attempt.owner
            && availability(selected) === attempt.availability ? result : null);
        } catch {
          if (flight === attempt) {invalidate();refresh();}
        }
      });
      return promise;
    },
    dispose() {
      if (disposed) return;
      disposed=true;detach();offOwner();emit(initial());listeners.clear();
    },
  });
}
