/** Resolve the installed memory location without copying any credentials. Explicit arguments are preferred for scratch use. */
import { openVikingHome, readBridgeConfig } from './recall-openviking.mjs'
import { resolveMemoryIdentity } from './memory-identity.mjs'
export function memoryDeployment({ stateDir, subject, supportRoot, config, installed = false } = {}) {
  const identity = resolveMemoryIdentity({ stateDir, subject, supportRoot, installed })
  return { ...identity, config: config ?? readBridgeConfig(openVikingHome(identity.stateDir)) }
}
export function deploymentArgs(argv) {
  const get = flag => { const at = argv.indexOf(flag); return at < 0 ? undefined : argv[at + 1] }
  return memoryDeployment({ stateDir: get('--state-dir'), subject: get('--subject'), supportRoot: get('--support-root'), installed: argv.includes('--installed') })
}
