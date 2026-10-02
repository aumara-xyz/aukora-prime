import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@aukora/face-layout/client'
import { createPrimeOwnerController, createHttpAuthority, readHttpCapabilities } from './controller.mjs'
import type { Binding, Controller } from './controller.mjs'
import { OwnerSurface, OwnerMenu, CapabilityBadge } from './OwnerSurface.tsx'
import { PrimeProviderEditor } from './PrimeProviderEditor.tsx'
import type { ProviderCardExtrasOwnerProps } from './PrimeProviderEditor.tsx'
import { createPrimeProviderController, createPublicProviderApi } from './provider-controller.mjs'
import type { Controller as ProviderController, ProviderBinding } from './provider-controller.mjs'

export { createPrimeOwnerController, createHttpAuthority } from './controller.mjs'
export { OwnerSurface, CapabilityBadge } from './OwnerSurface.tsx'
export type { Binding, Controller } from './controller.mjs'
export { createPrimeProviderController, createPublicProviderApi } from './provider-controller.mjs'
export type { ProviderBinding, ProviderController }
declare module '@deepseek-ai/cordis' { interface Context { primeOwnerUi:Controller; primeAuthority:Binding; primeProviderUi:ProviderController; primeProviderSettings:Omit<ProviderBinding,'ownerController'> } }
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
  let supplied = false
  let providerSupplied = false
  let providerContracts:Binding['contracts']|undefined
  const connectPublicProvider = () => {
    if (!providerSupplied && providerContracts) {
      providers.connect({ownerController:controller,contracts:providerContracts,api:createPublicProviderApi(providerContracts)})
      void providers.load()
    }
  }
  ctx.effect(() => { const off = ctx.reflect.provide('primeOwnerUi', controller); return () => { controller.dispose(); off() } }, 'prime owner UI controller')
  ctx.effect(() => { const off = ctx.reflect.provide('primeProviderUi',providers); return () => { providers.dispose();off() } }, 'prime Models card controller')
  ctx.inject(['primeProviderSettings'], binding => {
    providerSupplied = true
    providers.connect({...binding.primeProviderSettings,ownerController:controller})
    void providers.load()
    binding.effect(() => () => { providerSupplied=false;providers.disconnect();connectPublicProvider() },'prime owner provider binding')
  })
  ctx.inject(['primeAuthority'], binding => {
    supplied = true
    controller.connect(binding.primeAuthority)
    binding.effect(() => () => { supplied = false; controller.disconnect() }, 'prime authority UI binding')
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
    inject: () => ({controller}) }, OwnerSurface))
  ctx.slots.inject('shell.menu.system', () => ctx.slots.register({ name:'shell.menu.system', id:'prime-owner', order:70 }, OwnerMenu))
  ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name:'shell.overlay', id:'prime-capabilities', order:70,
    inject: () => ({controller}) }, CapabilityBadge))
  ctx.slots.inject('settings.models.provider-card', () => ctx.slots.register({name:'settings.models.provider-card',key:'prime-inference',
    inject:()=>({controller:providers})},PrimeProviderEditor))
}
