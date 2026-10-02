// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only proposal. This module performs no control/backend operations,
// grants no authority, and is deliberately not exported by the executor package.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const pilotBounds=Object.freeze({cpu_millicores:500,memory_bytes:536870912,
  scratch_bytes:134217728,pids:64,wall_time_ms:30000,max_output_bytes:65536})
const mounts=[
  {type:'tmpfs',target:'/sandbox/work',size_bytes:67108864,mode:448,
    options:['rw','nosuid','nodev','noexec','uid=1000','gid=1000']},
  {type:'tmpfs',target:'/sandbox/.dsh',size_bytes:33554432,mode:448,
    options:['rw','nosuid','nodev','noexec','uid=1000','gid=1000']},
  {type:'tmpfs',target:'/tmp',size_bytes:33554432,mode:1023,
    options:['rw','nosuid','nodev','noexec']},
]
export function proposedCreateTemplate(image) {
  if(typeof image!=='string'||!(/^(?:sha256:[a-f0-9]{64}|[^\s]+@sha256:[a-f0-9]{64})$/u.test(image))) {
    throw new Error('actual immutable workload image output required')
  }
  // SandboxTemplate protobuf names are camelCase. Opaque Docker JSON remains
  // snake_case; none of these values comes from model/caller configuration.
  return {image,resources:{limits:{cpu:'500m',memory:'512Mi'}},
    driverConfig:{docker:{mounts:structuredClone(mounts)}}}
}
export function proposedPolicy(mode) {
  if(!['read-only','workspace-write'].includes(mode))throw new Error('bounded mode required')
  return {version:1,filesystem:{includeWorkdir:false,
    readOnly:['/usr','/lib','/lib64','/bin','/etc','/proc','/dev/urandom','/sandbox','/tmp'],
    readWrite:mode==='workspace-write'?['/sandbox/work','/sandbox/.dsh','/tmp','/dev/null']:['/dev/null']},
    landlock:{compatibility:'hard_requirement'},process:{runAsUser:'1000',runAsGroup:'1000'},
    networkPolicies:{},networkMiddlewares:{}}
}
export function pilotPlan() {
  const pins=JSON.parse(readFileSync(new URL('./pins.json',import.meta.url),'utf8'))
  return {status:'PROPOSED_UNAVAILABLE',approved:false,runtime_qualified:false,source_commit:pins.openshell_source_commit,
    image_oci_workdir:'/sandbox',execution_workdir:'/sandbox/work',bounds:pilotBounds,
    workload_image: pins.workload_image_config_digest,
    create_template:pins.workload_image_config_digest?proposedCreateTemplate(pins.workload_image_config_digest):null,
    policy:proposedPolicy('read-only'),planned_mounts:structuredClone(mounts),
    docker_operator:{sandbox_pids_limit:64,allow_driver_config:true,enable_bind_mounts:false,image_pull_policy:'never'},
    aggregate_host_slice:{cpu_quota_percent:150,memory_max_bytes:2147483648,memory_swap_max_bytes:0,tasks_max:256},
    allowed_probe:{action_type:'shell.bash.foreground',command:"/usr/bin/id -u; /usr/bin/id -g; /bin/pwd; /usr/bin/printf 'prime-qualification\\n'; exit 1",
      workdir:'/sandbox/work',sandbox_mode:'read-only',stdin:'',env:{},dsh_env:{},timeout_ms:30000,max_output_bytes:65536},
    pending_source_joins:['H/C timeout124 receipt semantics','trusted closed resource/mount profile and policy/workdir/digest mapping',
      'Cordis effect disposer in the mounted factory','independent durable scoped cleanup guardian'],
    required_observations:['immutable image outputs','actual admitted policy/driver mounts','Docker HostConfig and kernel cgroup2 bounds',
      'private control placement/TLS/UIDs','guest absence plus owned auxiliary/volume cleanup','typed genuine command exit and drained RPC',
      'restart/late-create fencing and cleanup evidence'],
    qualification_limits:'One inert foreground call cannot qualify timeout, restart, late creation, or active network denial.'}
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1])console.log(JSON.stringify(pilotPlan(),null,2))
