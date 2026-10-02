import type { Context } from '@deepseek-ai/cordis'
import { createElement, useSyncExternalStore } from 'react'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@aukora/face-layout/client'
import { createPrimeOwnerController, createHttpAuthority, readHttpCapabilities } from './controller.mjs'
import type { Binding, ConnectionWitness, Controller } from './controller.mjs'
import { OwnerSurface, OwnerMenu, CapabilityBadge } from './OwnerSurface.tsx'
import { PrimeProviderEditor } from './PrimeProviderEditor.tsx'
import type { ProviderCardExtrasOwnerProps } from './PrimeProviderEditor.tsx'
import { createPrimeProviderController, createPublicProviderApi } from './provider-controller.mjs'
import type { Controller as ProviderController, ProviderBinding } from './provider-controller.mjs'
import type { MemoryPilotBinding } from './PilotMemoryPanel'

export { createPrimeOwnerController, createHttpAuthority } from './controller.mjs'
export { OwnerSurface, CapabilityBadge } from './OwnerSurface.tsx'
export { AumaReplyView } from './AumaReplyView.tsx'
export type { PilotInferenceResult } from './AumaReplyView.tsx'
export { PilotMemoryPanel } from './PilotMemoryPanel'
export type { MemoryPilotBinding } from './PilotMemoryPanel'
export type { Binding, ConnectionWitness, Controller } from './controller.mjs'
export { createPrimeProviderController, createPublicProviderApi } from './provider-controller.mjs'
export type { ProviderBinding, ProviderController }
/** Trusted native connection ordering only; never an owner or effect grant. */
export interface NativeOwnerConnection {
  readonly controller:Controller
  readonly isConnected:(binding:Binding)=>boolean
}
declare module '@deepseek-ai/cordis' { interface Context { primeOwnerUi:Controller; primeAuthority:Binding; primeProviderUi:ProviderController; primeProviderSettings:Omit<ProviderBinding,'ownerController'>;primePilotMemory:MemoryPilotBinding;primeOwnerNativeConnection:NativeOwnerConnection } }
// Exact keyed slot subset from pinned MIT ui-settings-models/slot-contract.ts.
// The stock Models client remains its runtime declarer. No Models dependency,
// alternate settings namespace or backend controller is introduced.
declare module '@deepseek-ai/dsh-client-ui-slots' { interface SlotMap {
  'settings.models.provider-card':{kind:'keyed';scope:'root';owner:ProviderCardExtrasOwnerProps}
} }
export const inject = ['slots','layout','locale']

export function apply(ctx:Context):void {
  const controller = createPrimeOwnerController()
  const providers = createPrimeProviderController()
  // Optional UI-only projection of H's already attached owner memory client.
  // Providing this service performs no login, attachment, recovery or effect.
  let memoryPilot:MemoryPilotBinding|undefined
  const memoryListeners = new Set<() => void>()
  const memorySnapshot = () => memoryPilot
  const memorySubscribe = (listener:() => void) => {memoryListeners.add(listener);return () => {memoryListeners.delete(listener)}}
  const setMemoryPilot = (value:MemoryPilotBinding|undefined) => {memoryPilot=value;for(const listener of memoryListeners)listener()}
  function PilotOwnerSurface(props:PropsRuntime<'shell.surface'> & {controller:Controller}) {
    const current = useSyncExternalStore(memorySubscribe,memorySnapshot,memorySnapshot)
    return createElement(OwnerSurface,{...props,...(current ? {memoryPilot:current} : {})})
  }
  let supplied = false
  let nativeDisposed = false
  let nativeConnection:{binding:Binding;active:boolean;witness:ConnectionWitness|null}|undefined
  const nativeAcknowledgement:NativeOwnerConnection = Object.freeze({controller,
    isConnected:(expected:Binding) => !nativeDisposed && nativeConnection?.active === true
      && nativeConnection.binding === expected && nativeConnection.witness?.isCurrent() === true,
  })
  let providerSupplied = false
  let providerContracts:Binding['contracts']|undefined
  const connectPublicProvider = () => {
    if (!providerSupplied && providerContracts) {
      providers.connect({ownerController:controller,contracts:providerContracts,api:createPublicProviderApi(providerContracts)})
      void providers.load()
    }
  }
  ctx.effect(() => { const off = ctx.reflect.provide('primeOwnerUi', controller); return () => { controller.dispose(); off() } }, 'prime owner UI controller')
  ctx.effect(() => {
    const off = ctx.reflect.provide('primeOwnerNativeConnection',nativeAcknowledgement)
    return () => {nativeDisposed=true;if(nativeConnection)nativeConnection.active=false;nativeConnection=undefined;off()}
  },'prime native binding acknowledgement')
  ctx.effect(() => { const off = ctx.reflect.provide('primeProviderUi',providers); return () => { providers.dispose();off() } }, 'prime Models card controller')
  ctx.inject(['primePilotMemory'], binding => {
    const selected = binding.primePilotMemory
    setMemoryPilot(selected)
    binding.effect(() => () => {if(memoryPilot===selected)setMemoryPilot(undefined)},'prime pilot memory view binding')
  })
  ctx.inject(['primeProviderSettings'], binding => {
    providerSupplied = true
    providers.connect({...binding.primeProviderSettings,ownerController:controller})
    void providers.load()
    binding.effect(() => () => { providerSupplied=false;providers.disconnect();connectPublicProvider() },'prime owner provider binding')
  })
  ctx.inject(['primeAuthority'], binding => {
    if (nativeDisposed) return
    const selected = binding.primeAuthority
    const owned = {binding:selected,active:true,witness:null as ConnectionWitness|null}
    nativeConnection = owned
    supplied = true
    // Own cleanup before connect's synchronous notifications can remove or
    // replace this injection. Old cleanup must not disconnect its replacement.
    binding.effect(() => () => {
      owned.active=false
      const witness = owned.witness
      owned.witness=null
      if (nativeConnection !== owned) return
      nativeConnection=undefined;supplied=false
      if (witness) void controller.disconnect(witness)
    }, 'prime authority UI binding')
    if (!owned.active || nativeDisposed || nativeConnection !== owned) return
    const witness = controller.connect(selected,{onConnection:current => {
      if (owned.active && !nativeDisposed && nativeConnection === owned) owned.witness=current
    }})
    if (owned.active && !nativeDisposed && nativeConnection === owned && witness?.isCurrent() === true) owned.witness=witness
  })
  ctx.effect(() => {
    let disposed = false
    // H serves these exact browser-safe contract modules under the guarded module route.
    const load = (url:string):Promise<Binding['contracts']> => import(/* @vite-ignore */ url)
    void load('/prime/contracts/browser.mjs').then(contracts => {
      if (!disposed) { providerContracts=contracts;connectPublicProvider() }
      if (!disposed && !supplied) {
        controller.connect({ authority:createHttpAuthority(undefined, contracts), contracts, requiresCapabilities:true })
        void readHttpCapabilities(undefined, contracts).then(capabilities => {
          if (!disposed && !supplied) controller.setCapabilities(capabilities)
        }).catch(() => { if (!disposed && !supplied) controller.capabilitiesUnavailable() })
      }
    }).catch(() => { /* The initial unavailable state remains honest. */ })
    return () => { disposed = true }
  }, 'prime browser contract helper')
  ctx.slots.inject('shell.surface', () => ctx.slots.register({ name:'shell.surface', id:'prime-owner', order:70,
    inject: () => ({controller}) }, PilotOwnerSurface))
  ctx.slots.inject('shell.menu.system', () => ctx.slots.register({ name:'shell.menu.system', id:'prime-owner', order:70 }, OwnerMenu))
  ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name:'shell.overlay', id:'prime-capabilities', order:70,
    inject: () => ({controller}) }, CapabilityBadge))
  ctx.slots.inject('settings.models.provider-card', () => ctx.slots.register({name:'settings.models.provider-card',key:'prime-inference',
    inject:()=>({controller:providers})},PrimeProviderEditor))
}
