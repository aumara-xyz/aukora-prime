#!/usr/bin/env node
import { createVikingDoor } from '../../plugins/aukora-kira/lib/viking-door.mjs'
import { deploymentArgs } from '../../plugins/aukora-kira/lib/memory-deployment.mjs'
import { MemoryIdentityError } from '../../plugins/aukora-kira/lib/memory-identity.mjs'
import { readDoorCredential, VikingCredentialError } from './viking-auth.mjs'
const fail = error => {
  const message = error instanceof MemoryIdentityError ? error.message
    : error instanceof VikingCredentialError || error?.code === 'viking.door:credential-missing' ? error.code
    : 'Viking door failed; details suppressed.'
  process.stderr.write(`${message}\n`); process.exitCode = 1
}
try {
  const args = process.argv.slice(2), at = args.indexOf('--port')
  const port = at < 0 ? 8766 : Number(args[at + 1])
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('invalid-port')
  const keyFile = process.env.AUKORA_VIKING_DOOR_KEY_FILE
  const auth = keyFile === undefined ? {} : { authToken: readDoorCredential(keyFile) }
  const door = createVikingDoor({ ...deploymentArgs(args), ...auth, port })
  await door.listen()
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => void door.close())
} catch (error) { fail(error) }
