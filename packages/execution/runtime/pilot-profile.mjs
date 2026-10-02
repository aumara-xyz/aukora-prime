// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only proposal. This module performs no control/backend operations,
// grants no authority, and is deliberately not exported by the executor package.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { CREATE_BOUNDS, createTemplate, createMounts, IMAGE_WORKDIR, GUEST_WORKDIR, DOCKER_REQUIREMENTS } from '../src/create-profile.mjs'
import { guestPolicy } from '../src/policy.mjs'

export const pilotBounds=CREATE_BOUNDS
export function proposedCreateTemplate(image) {
  return createTemplate(image)
}
export function proposedPolicy(mode) {
  const p=guestPolicy(mode)
  return {version:p.version,filesystem:{includeWorkdir:p.filesystem_policy.include_workdir,
    readOnly:p.filesystem_policy.read_only,readWrite:p.filesystem_policy.read_write},landlock:p.landlock,
    process:{runAsUser:p.process.run_as_user,runAsGroup:p.process.run_as_group},
    networkPolicies:{},networkMiddlewares:{}}
}
export function pilotPlan() {
  const pins=JSON.parse(readFileSync(new URL('./pins.json',import.meta.url),'utf8'))
  return {status:'PROPOSED_UNAVAILABLE',approved:false,runtime_qualified:false,source_commit:pins.openshell_source_commit,
    image_oci_workdir:IMAGE_WORKDIR,execution_workdir:GUEST_WORKDIR,bounds:pilotBounds,
    workload_image: pins.workload_image_config_digest,
    create_template:pins.workload_image_config_digest?proposedCreateTemplate(pins.workload_image_config_digest):null,
    policy:proposedPolicy('read-only'),planned_mounts:createMounts(),
    docker_operator:DOCKER_REQUIREMENTS,
    aggregate_host_slice:{cpu_quota_percent:150,memory_max_bytes:2147483648,memory_swap_max_bytes:0,tasks_max:256},
    allowed_probe:{action_type:'shell.bash.foreground',command:"/usr/bin/id -u; /usr/bin/id -g; /bin/pwd; /usr/bin/printf 'prime-qualification\\n'; exit 1",
      workdir:'/sandbox/work',sandbox_mode:'read-only',stdin:'',env:{},dsh_env:{},timeout_ms:30000,max_output_bytes:65536},
    pending_source_joins:['independent durable scoped cleanup guardian','reviewed atomic configuration generation/freeze'],
    source_increment_status:'resource/tmpfs/workdir/policy mappings implemented; focused checks/builds not run',
    required_observations:['immutable image outputs','actual admitted policy/driver mounts','Docker HostConfig and kernel cgroup2 bounds',
      'private control placement/TLS/UIDs','guest absence plus owned auxiliary/volume cleanup','typed genuine command exit and drained RPC',
      'restart/late-create fencing and cleanup evidence'],
    qualification_limits:'One inert foreground call cannot qualify timeout, restart, late creation, or active network denial.'}
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1])console.log(JSON.stringify(pilotPlan(),null,2))
