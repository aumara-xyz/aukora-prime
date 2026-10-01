// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto'
import { canonicalJson } from '../../contracts/src/runtime.mjs'
import { refused } from './policy.mjs'

const digest=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value),'utf8').digest('hex')
export function executorRequestDigest(request) {
  const {signal,...value}=request
  return digest('aukora-prime.executor-request.v1',value)
}
export const executionReceiptDigest=receipt=>digest('aukora-prime.execution-receipt.v1',receipt)

export function brokerRefusal(result) {
  return refused(result?.reason??'trusted authority binding refused',result?.error_code??'RECONCILIATION_REQUIRED')
}
export function requireBroker(broker) {
  if(!broker||['claimDispatch','requestCancel','settle','reconcileSettlement'].some(key=>typeof broker[key]!=='function'))
    throw refused('durable authority dispatch/cancel/settlement join required','UNAVAILABLE')
  return broker
}
