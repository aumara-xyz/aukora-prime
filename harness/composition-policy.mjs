// Exact pinned services for a disposable preview. No user profile, patches, HMR or plugin administration.
export const pinnedIds = Object.freeze(`
timer llm llm-deepseek deepseek-llm-api-extensions session session-log-deepseek typert typert-loader session-title
user-questions agent agent-default-model session-persistence-jsonl attachment-local
session-query-sqlite session-projection storage storage-json storage-domain session-projection-cache
sandbox-policy approval permission shell-env commands goal token-meter tools system-prompt agent-loop
workspace session-reference session-stats session-turn-outline session-controller settings-controller
webserver web-runtime modules api-remotes
ui-theme locale ui-renderer ui-session resources ui-sidebar-right ui-sidebar-documentpreview
ui-settings ui-settings-models ui-settings-unarchive-sessions ui-conversation ui-approval ui-chat
ui-brand-official ui-attachment ui-tool ui-input-trigger ui-commands ui-reference ui-message-feedback
ui-model-selection ui-permission ui-user-questions ui-trajectory
`.trim().split(/\s+/));
export const faceNames=Object.freeze(['layout','sidebar','threads','apps','messages','memory','aumlok','documents','settings']);
export const ownedEntries=Object.freeze([
 {id:'prime-credentials',name:'./harness/preview-credentials.mjs'},
 {id:'prime-settings',name:'./harness/preview-settings.mjs'},
 {id:'prime-uploads',name:'./harness/preview-uploads.mjs'},
 {id:'prime-deepseek-pilot',name:'./harness/deepseek-pilot.mjs'},
 {id:'prime-gateway',name:'./packages/api/gateway/lib/prime-host.mjs'},
 {id:'prime-connection',name:'./packages/client/connection/lib/prime-host.mjs',config:{trustedHosts:[],cookieMaxAgeDays:1,maxRequestBodyBytes:8388608}},
 {id:'prime-shell',name:'./harness/shell-unavailable.mjs'},
 {id:'prime-host',name:'./harness/host.mjs'},
 // Client metadata only; native workspace actions stay unavailable.
 {id:'prime-workspace-client',name:'./packages/api/workspace-controller/lib/prime-host.mjs'},
 {id:'prime-file-upload-client',name:'./packages/client/file-upload/lib/prime-host.mjs'},
 {id:'aukora-foundation',name:'./plugins/aukora-foundation/lib/index.js'},
 ...faceNames.map(name=>({id:'aukora-face-'+name,name:'./plugins/aukora-face-'+name+'/lib/prime-host.mjs'})),
 {id:'prime-owner-ui',name:'./plugins/prime-authority/lib/index.js'},
 {id:'prime-native-host',name:'./harness/native-host/index.mjs'},
]);
export function assertEntrySet(entries) {
 const expected=[...pinnedIds,...ownedEntries.map(e=>e.id)];const ids=entries.map(e=>e.id);
 if(ids.length!==expected.length||new Set(ids).size!==ids.length||expected.some(id=>!ids.includes(id)))throw new Error('PRIME_PLUGIN_SET_MISMATCH');
 if(entries.some(e=>e.disabled||e.inject||e.intercept||e.isolate||Object.keys(e).some(k=>!['id','name','config'].includes(k))))throw new Error('PRIME_PLUGIN_OPTIONS_REFUSED');
 for(const e of ownedEntries)if(entries.find(x=>x.id===e.id)?.name!==e.name)throw new Error('PRIME_OWNED_PLUGIN_MISMATCH');
 return entries;
}
