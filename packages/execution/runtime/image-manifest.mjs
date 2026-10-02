// SPDX-License-Identifier: AGPL-3.0-or-later
// Source/byte inspection only. No build, backend call, image pin mutation or
// runtime acceptance. The trusted host owns build provenance and approval.
import { createHash } from 'node:crypto'
import { lstatSync, readFileSync } from 'node:fs'
import { canonicalJson, parseStrictJson } from '../../contracts/src/runtime.mjs'

const DIGEST = /^sha256:[0-9a-f]{64}$/u
const OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
const OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
const packageRoot = new URL('../', import.meta.url)
const definitionFile = new URL('./image/source-inputs.json', import.meta.url)
const buildPaths = ['runtime/image/Dockerfile', 'runtime/image/.dockerignore']
const profilePaths = ['src/create-profile.mjs', 'src/policy.mjs']
const metadataPaths = ['runtime/pins.json', 'runtime/registry-metadata.json', 'runtime/pilot-official-metadata.json']
const digest = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex')
const freeze = value => {
  if (value && typeof value === 'object') {
    for (const member of Object.values(value)) freeze(member)
    Object.freeze(value)
  }
  return value
}
function fail(message) { throw new TypeError('UNAVAILABLE: workload image ' + message) }
function same(left, right) { return canonicalJson(left) === canonicalJson(right) }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) }
function bytes(input, label) {
  // Copy bytes before hashing/parsing; preserve their exact UTF-8 serialization.
  if (!(input instanceof Uint8Array) || input.byteLength < 1 || input.byteLength > 2 * 1024 * 1024) fail(label + ' bytes required within 2 MiB')
  return Buffer.from(input)
}
function json(input, label) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(input)
  const value = parseStrictJson(text, { maxBytes: 2 * 1024 * 1024, maxDepth: 32 })
  if (!object(value)) fail(label + ' object required')
  return value
}
function checkFiles(files, expectedPaths) {
  if (!Array.isArray(files) || files.length !== expectedPaths.length) fail('closed source file list required')
  for (let i = 0; i < expectedPaths.length; i++) {
    const file = files[i]
    if (!object(file) || !same(Object.keys(file).sort(), ['path', 'sha256'])
      || file.path !== expectedPaths[i] || !DIGEST.test(file.sha256)) fail('source file identity differs')
    const location = new URL(file.path, packageRoot)
    if (!lstatSync(location).isFile() || digest(readFileSync(location)) !== file.sha256) fail('source bytes differ: ' + file.path)
  }
}

export function workloadImageDefinition() {
  const raw = readFileSync(definitionFile)
  const definition = json(raw, 'source definition')
  if (definition.version !== 1 || definition.status !== 'SOURCE_ONLY_UNQUALIFIED'
    || definition.platform !== 'linux/amd64'
    || definition.openshell_source_commit !== '6648bd0c290efbc41ba131ee9831ee45cd431f94'
    || definition.sdk_package_version !== '0.0.0'
    || definition.base?.reference !== 'docker.io/library/debian@sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b'
    || definition.base?.manifest_digest !== 'sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b'
    || definition.base?.config_digest !== 'sha256:db9f02c6bde9fa90cc8074c92754b2b046947392f1a857726e77f041febb7b82'
    || definition.execution_workdir !== '/sandbox/work'
    || definition.build?.status !== 'UNPERFORMED'
    || definition.build?.source_date_epoch !== 1790564896
    || definition.build?.network !== 'none'
    || definition.runtime_qualified !== false
    || !same(definition.expected_output, { workload_image_config_digest: null, workload_oci_manifest_digest: null })
    || !same(definition.expected_image_config, { User: '1000:1000', WorkingDir: '/sandbox', Entrypoint: ['/bin/bash'], Cmd: ['-c', 'exit 0'], Volumes: null, HOME: '/sandbox' })) {
    fail('source definition differs from the reviewed proposal')
  }
  checkFiles(definition.build_context_files, buildPaths)
  checkFiles(definition.metadata_files, metadataPaths)
  if (definition.profile_source_files !== null) checkFiles(definition.profile_source_files, profilePaths)
  return freeze({ definition, definition_digest: digest(raw), build_inputs_verified: true,
    profile_inputs_verified: definition.profile_source_files !== null,
    runtime_qualified: false })
}

// `loaded_image` is an explicit projection of a trusted local image-inspect
// readback: {Id,Os,Architecture,Config:{User,WorkingDir,Entrypoint,Cmd,Volumes,Env},
// RootFS:{Type,Layers}}. It is a host evidence input, never guest transport.
// An optional expected pair must come from separately reviewed real artifacts.
export function inspectWorkloadImageOutput({ manifest_bytes, config_bytes, loaded_image, expected_output = null }) {
  const source = workloadImageDefinition()
  const manifestRaw = bytes(manifest_bytes, 'OCI manifest'), configRaw = bytes(config_bytes, 'OCI config')
  const manifest = json(manifestRaw, 'OCI manifest'), config = json(configRaw, 'OCI config')
  const configDigest = digest(configRaw), manifestDigest = digest(manifestRaw)
  const loaded = JSON.parse(canonicalJson(loaded_image))
  if (manifest.schemaVersion !== 2 || manifest.mediaType !== OCI_MANIFEST
    || manifest.config?.mediaType !== OCI_CONFIG || manifest.config?.digest !== configDigest
    || manifest.config?.size !== configRaw.length || !Array.isArray(manifest.layers) || manifest.layers.length < 1
    || manifest.layers.some(layer => !object(layer) || !DIGEST.test(layer.digest)
      || !Number.isSafeInteger(layer.size) || layer.size < 1
      || !['application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.oci.image.layer.v1.tar+zstd'].includes(layer.mediaType))) fail('OCI manifest/config binding differs')
  const expected = source.definition.expected_image_config, image = config.config
  if (config.os !== 'linux' || config.architecture !== 'amd64' || (config.variant !== undefined && config.variant !== '')
    || !object(image) || image.User !== expected.User || image.WorkingDir !== expected.WorkingDir
    || !same(image.Entrypoint, expected.Entrypoint) || !same(image.Cmd, expected.Cmd)
    || (image.Volumes !== undefined && image.Volumes !== null && !same(image.Volumes, {}))
    || !Array.isArray(image.Env) || image.Env.some(item => typeof item !== 'string')
    || image.Env.filter(item => item.startsWith('HOME=')).length !== 1 || !image.Env.includes('HOME=/sandbox')
    || config.rootfs?.type !== 'layers' || !Array.isArray(config.rootfs.diff_ids)
    || config.rootfs.diff_ids.length !== manifest.layers.length || config.rootfs.diff_ids.some(item => !DIGEST.test(item))) fail('output config differs from the source proposal')
  if (!object(loaded) || !same(Object.keys(loaded).sort(), ['Architecture', 'Config', 'Id', 'Os', 'RootFS'])
    || loaded.Id !== configDigest || loaded.Os !== 'linux' || loaded.Architecture !== 'amd64'
    || !object(loaded.Config) || !same(Object.keys(loaded.Config).sort(), ['Cmd', 'Entrypoint', 'Env', 'User', 'Volumes', 'WorkingDir'])
    || loaded.Config.User !== image.User || loaded.Config.WorkingDir !== image.WorkingDir
    || !same(loaded.Config.Entrypoint, image.Entrypoint) || !same(loaded.Config.Cmd, image.Cmd)
    || !same(loaded.Config.Env, image.Env)
    || (loaded.Config.Volumes !== null && !same(loaded.Config.Volumes, {}))
    || !object(loaded.RootFS) || !same(Object.keys(loaded.RootFS).sort(), ['Layers', 'Type'])
    || loaded.RootFS.Type !== 'layers' || !same(loaded.RootFS.Layers, config.rootfs.diff_ids)) fail('loaded image readback differs from output bytes')
  const pair = { workload_image_config_digest: configDigest, workload_oci_manifest_digest: manifestDigest }
  if (expected_output !== null) {
    const expectedPair = JSON.parse(canonicalJson(expected_output))
    if (!object(expectedPair) || !same(Object.keys(expectedPair).sort(), ['workload_image_config_digest', 'workload_oci_manifest_digest'])
      || !DIGEST.test(expectedPair.workload_image_config_digest) || !DIGEST.test(expectedPair.workload_oci_manifest_digest)
      || !same(expectedPair, pair)) fail('output differs from the separately approved digest pair')
  }
  return freeze({ version: 1, status: 'OUTPUT_EVIDENCE_UNQUALIFIED', definition_digest: source.definition_digest,
    ...pair, image_digest: configDigest, platform: 'linux/amd64', image_oci_workdir: '/sandbox', execution_workdir: '/sandbox/work',
    expected_output_matches: expected_output === null ? null : true,
    profile_inputs_verified: source.profile_inputs_verified, source_build_binding_verified: false,
    layer_bytes_verified: false, runtime_qualified: false })
}
