// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFile, realpath } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { SDK_SOURCE_COMMIT, SDK_PACKAGE_VERSION, SdkTransport } from './sdk-transport.ts'
import { refused } from './policy.mjs'

/** Trusted H composition supplies the SDK build root and control-plane TLS
 * credentials. Nothing in this module forwards them to the sandbox. The A
 * release closure must separately hash SDK dependencies and runtime bytes. */
export async function loadPinnedSdk(sdkRoot, connectOptions) {
  let endpoint
  try {endpoint=new URL(connectOptions?.gateway)}catch{throw refused('explicit HTTPS gateway required','UNAVAILABLE')}
  if(endpoint.protocol!=='https:'||endpoint.username||endpoint.password||endpoint.pathname!=='/'||endpoint.search||endpoint.hash
    ||connectOptions.insecureSkipVerify||connectOptions.allowInsecureAuth)throw refused('verified HTTPS control plane required','UNAVAILABLE')
  if(resolve(sdkRoot)!==sdkRoot||await realpath(sdkRoot)!==sdkRoot)throw refused('canonical SDK build root required','UNAVAILABLE')
  const manifest=JSON.parse(await readFile(join(sdkRoot,'prime-sdk-build.json'),'utf8'))
  const metadata=JSON.parse(await readFile(join(sdkRoot,'package.json'),'utf8'))
  if(manifest.source_commit!==SDK_SOURCE_COMMIT||manifest.package_version!==SDK_PACKAGE_VERSION||manifest.built!==true
    ||manifest.archive_sha256!=='298ee3c0566c51e593e9eadc724a0e1c072fbb542b4f362b82e82a254f8eaea6'
    ||metadata.name!=='@nvidia/openshell-sdk'||metadata.version!==SDK_PACKAGE_VERSION||!manifest.output_sha256?.['dist/index.js'])throw refused('reviewed source SDK build missing','UNAVAILABLE')
  for(const [name,expected] of Object.entries(manifest.output_sha256)) {
    if(!/^dist\/[a-zA-Z0-9_./-]+$/.test(name)||name.split('/').includes('..')||!/^[a-f0-9]{64}$/.test(expected))throw refused('SDK manifest path invalid','UNAVAILABLE')
    const file=join(sdkRoot,name)
    if(await realpath(file)!==file||createHash('sha256').update(await readFile(file)).digest('hex')!==expected)throw refused('SDK build bytes differ','UNAVAILABLE')
  }
  const {OpenShellClient}=await import(pathToFileURL(join(sdkRoot,'dist/index.js')).href)
  const client=await OpenShellClient.connect(connectOptions)
  return {client,transport:new SdkTransport(client.raw,{gatewayIdentity:new URL(connectOptions.gateway).href})}
}
