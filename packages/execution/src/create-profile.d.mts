export const GUEST_WORKDIR:'/sandbox/work'
export const IMAGE_WORKDIR:'/sandbox'
export const CREATE_PROFILE_ID:'openshell-linux-foreground-v1'
export const CREATE_BOUNDS:Readonly<{cpu_millicores:500;memory_bytes:536870912;scratch_bytes:134217728;pids:64;wall_time_ms:30000;max_output_bytes:65536}>
export const DOCKER_REQUIREMENTS:Readonly<{sandbox_pids_limit:64;allow_driver_config:true;enable_bind_mounts:false;image_pull_policy:'never'}>
export type CreateTemplate={image:string;resources:{limits:{cpu:'500m';memory:'512Mi'}};
  driverConfig:{docker:{mounts:Array<{type:'tmpfs';target:string;size_bytes:number;mode:number;options:string[]}>}}}
export function createMounts():CreateTemplate['driverConfig']['docker']['mounts']
export function createTemplate(image:string):CreateTemplate
export function createProfileDigest(image:string):`sha256:${string}`
export function guestWorkdir(logicalWorkdir:string,logicalRoot:string):'/sandbox/work'
export function assertCreateBounds(bounds:{wall_time_ms:number;max_output_bytes:number}):void
export function matchesCreateResourceBounds(bounds:unknown):boolean
export function assertCreateTemplate(value:unknown,image:string):CreateTemplate
