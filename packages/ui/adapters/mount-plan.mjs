import { readFileSync } from 'node:fs'

/** Native DSH modules: the host supplies its existing ModuleLoader and Cordis client. */
export const faceOrder = Object.freeze([
  'layout', 'sidebar', 'threads', 'apps', 'messages', 'memory', 'aumlok', 'documents', 'settings',
])

export const faces = Object.freeze(faceOrder.map(face => {
  const directory = new URL(`../faces/${face}/`, import.meta.url)
  const metadata = JSON.parse(readFileSync(new URL('package.json', directory), 'utf8'))
  return Object.freeze({
    face,
    id: metadata.name,
    version: metadata.version,
    directory,
    clientBundle: new URL('lib/client.js', directory),
    client: Object.freeze(metadata.dsh.client),
    // Original host bundles retain legacy side effects. Prime mounts its own routes separately.
    mountDonorHost: false,
  })
}))

/** Keep DSH's manifest shape authoritative; caller maps these descriptors into its pinned loader. */
export function clientMountPlan() {
  return faces.map(({ face, id, version, directory, clientBundle, client, mountDonorHost }) => ({
    face, id, version, directory, clientBundle, client, mountDonorHost,
  }))
}
