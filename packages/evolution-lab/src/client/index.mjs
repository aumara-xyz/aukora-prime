import * as React from 'react'
import { ActionButton, Card, SectionHeader, PortalButton } from '@aukora/face-layout/client'
import { createEvolutionController } from '../controller.mjs'
import { createEvolutionComponents } from '../view.mjs'
import './style.css'

export const { EvolutionSurface, EvolutionMenu } = createEvolutionComponents(React, { ActionButton, Card, SectionHeader, PortalButton })
export const inject = ['slots', 'layout']

/** Integrator-owned registration. manifestJson is an optional sanitized JSON string. */
export function apply(ctx, config = {}) {
  const controller = createEvolutionController(config.manifestJson)
  ctx.effect(() => () => controller.dispose(), 'evolution lab read-only controller')
  ctx.slots.inject('shell.surface', () => ctx.slots.register({ name: 'shell.surface',
    id: 'evolution-lab', order: 80, inject: () => ({ controller }) }, EvolutionSurface))
  ctx.slots.inject('shell.menu.system', () => ctx.slots.register({ name: 'shell.menu.system',
    id: 'evolution-lab', order: 80 }, EvolutionMenu))
  return controller
}
