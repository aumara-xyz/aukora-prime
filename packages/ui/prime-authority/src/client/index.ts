import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@aukora/face-layout/client'
import { createPrimeOwnerController, createHttpAuthority } from './controller.mjs'
import type { Binding, Controller } from './controller.mjs'
import { OwnerSurface, OwnerMenu } from './OwnerSurface.tsx'

export { createPrimeOwnerController, createHttpAuthority } from './controller.mjs'
export { OwnerSurface } from './OwnerSurface.tsx'
export type { Binding, Controller } from './controller.mjs'
declare module '@deepseek-ai/cordis' { interface Context { primeOwnerUi:Controller; primeAuthority:Binding } }
export const inject = ['slots','layout','locale']

export function apply(ctx:Context):void {
  const controller = createPrimeOwnerController()
  let supplied = false
  ctx.effect(() => { const off = ctx.reflect.provide('primeOwnerUi', controller); return () => { controller.dispose(); off() } }, 'prime owner UI controller')
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
      if (!disposed && !supplied) controller.connect({ authority:createHttpAuthority(), contracts })
    }).catch(() => { /* The initial unavailable state remains honest. */ })
    return () => { disposed = true }
  }, 'prime browser contract helper')
  ctx.slots.inject('shell.surface', () => ctx.slots.register({ name:'shell.surface', id:'prime-owner', order:70,
    inject: () => ({controller}) }, OwnerSurface))
  ctx.slots.inject('shell.menu.system', () => ctx.slots.register({ name:'shell.menu.system', id:'prime-owner', order:70 }, OwnerMenu))
}
