// SPDX-License-Identifier: AGPL-3.0-or-later
// Closed host-owned profile for OpenShell 6648bd0. SandboxTemplate resources
// and Docker driver_config use the pinned proto/driver fields. No caller
// supplies a resource quantity, mount, image workdir or operator option.
import { createHash } from 'node:crypto'
import { posix } from 'node:path'
import { canonicalJson } from '../../contracts/src/runtime.mjs'

export const GUEST_WORKDIR='/sandbox/work'
export const IMAGE_WORKDIR='/sandbox'
export const CREATE_PROFILE_ID='openshell-linux-foreground-v1'
export const CREATE_BOUNDS=Object.freeze({cpu_millicores:500,memory_bytes:536870912,
  scratch_bytes:134217728,pids:64,wall_time_ms:30000,max_output_bytes:65536})
const mounts=[
  {type:'tmpfs',target:GUEST_WORKDIR,size_bytes:67108864,mode:448,
    options:['rw','nosuid','nodev','noexec','uid=1000','gid=1000']},
  {type:'tmpfs',target:'/sandbox/.dsh',size_bytes:33554432,mode:448,
    options:['rw','nosuid','nodev','noexec','uid=1000','gid=1000']},
  {type:'tmpfs',target:'/tmp',size_bytes:33554432,mode:1023,
    options:['rw','nosuid','nodev','noexec']},
]
export const DOCKER_REQUIREMENTS=Object.freeze({sandbox_pids_limit:64,
  allow_driver_config:true,enable_bind_mounts:false,image_pull_policy:'never'})
const fail=message=>{throw Object.assign(new Error(`aukora-openshell: ${message}`),{code:'UNAVAILABLE'})}
const jsonClone=value=>JSON.parse(canonicalJson(value))
export const createMounts=()=>jsonClone(mounts)

export function createTemplate(image) {
  if(typeof image!=='string'||!/^(?:[-a-zA-Z0-9._:/]+@)?sha256:[a-f0-9]{64}$/u.test(image))fail('immutable workload image output required')
  // google.protobuf.Struct is JsonObject in the actual source-built SDK.
  // Its opaque Docker JSON keys stay snake_case inside camelCase driverConfig.
  return {image,resources:{limits:{cpu:'500m',memory:'512Mi'}},
    driverConfig:{docker:{mounts:createMounts()}}}
}

/** Resource/template identity for the private owned ledger and H handoff.
 * It is separate from, and never replaces, frozen v1 operation/request digests. */
export function createProfileDigest(image) {
  return 'sha256:'+createHash('sha256').update('aukora-prime.create-profile.v1\0'+canonicalJson({
    profile:CREATE_PROFILE_ID,image_workdir:IMAGE_WORKDIR,execution_workdir:GUEST_WORKDIR,
    bounds:CREATE_BOUNDS,operator:DOCKER_REQUIREMENTS,template:createTemplate(image),
  })).digest('hex')
}

export function guestWorkdir(logicalWorkdir,logicalRoot) {
  if(typeof logicalRoot!=='string'||!logicalRoot.startsWith('/')||posix.normalize(logicalRoot)!==logicalRoot
    ||/[\x00-\x1f\x7f]/u.test(logicalRoot)||logicalWorkdir!==logicalRoot)fail('exact approved logical workdir mapping required')
  return GUEST_WORKDIR
}

export function assertCreateBounds(bounds) {
  if(!bounds||!Number.isSafeInteger(bounds.wall_time_ms)||bounds.wall_time_ms<1||bounds.wall_time_ms>CREATE_BOUNDS.wall_time_ms
    ||!Number.isSafeInteger(bounds.max_output_bytes)||bounds.max_output_bytes<1||bounds.max_output_bytes>CREATE_BOUNDS.max_output_bytes)fail('operation exceeds closed foreground profile')
}

export function matchesCreateResourceBounds(bounds) {
  return !!bounds&&['cpu_millicores','memory_bytes','scratch_bytes','pids'].every(key=>bounds[key]===CREATE_BOUNDS[key])
    &&Number.isSafeInteger(bounds.wall_time_ms)&&bounds.wall_time_ms>0&&bounds.wall_time_ms<=CREATE_BOUNDS.wall_time_ms
    &&Number.isSafeInteger(bounds.max_output_bytes)&&bounds.max_output_bytes>0&&bounds.max_output_bytes<=CREATE_BOUNDS.max_output_bytes
}

/** Readback corroborates desired resources/mounts; kernel enforcement remains
 * a distinct observed qualification obligation. Generated protobuf defaults
 * are permitted; unknown fields, extra environment and user namespaces refuse. */
export function assertCreateTemplate(value,image) {
  const keys=['image','resources','driverConfig','runtimeClassName','agentSocket','labels','annotations','environment','userNamespaces']
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail('exact create template readback required')
  for(const key of Reflect.ownKeys(value)) {
    const descriptor=Object.getOwnPropertyDescriptor(value,key)
    if(typeof key!=='string'||!descriptor||!Object.hasOwn(descriptor,'value'))fail('unsafe template readback')
    if(key==='$typeName') {if(descriptor.value!=='openshell.v1.SandboxTemplate')fail('template protobuf type differs')}
    else if(key==='$unknown') {if(descriptor.value!==undefined&&(!Array.isArray(descriptor.value)||descriptor.value.length))fail('unknown template wire fields')}
    else if(!keys.includes(key))fail('unknown template field')
  }
  for(const key of ['runtimeClassName','agentSocket'])if(value[key]!==undefined&&value[key]!=='')fail('additional runtime template input')
  for(const key of ['labels','annotations','environment'])if(value[key]!==undefined&&canonicalJson(value[key])!=='{}')fail('additional template metadata/environment')
  if(value.userNamespaces!==undefined)fail('user namespace override unavailable')
  const expected=createTemplate(image)
  if(value.image!==image||!Object.hasOwn(value,'resources')||!Object.hasOwn(value,'driverConfig')
    ||canonicalJson(value.resources)!==canonicalJson(expected.resources)
    ||canonicalJson(value.driverConfig)!==canonicalJson(expected.driverConfig))fail('admitted resources or mounts differ')
  return expected
}
