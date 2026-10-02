# Workload image source

This directory defines the local Linux amd64 workload image for OpenShell
`6648bd0c290efbc41ba131ee9831ee45cd431f94` (v0.1.2). It adds no package,
credential, host file, service, image volume or executable download. No command
removes base license/copyright files; their actual presence/content still needs
approved layer inspection. The TypeScript SDK version remains source-built
**0.0.0**.

The OCI user is `1000:1000` and workdir is `/sandbox`; foreground execution must
explicitly select `/sandbox/work`. The pinned driver validates mounts relative
to the image workdir and rejects mounts covering it. The prepared child
directories match the trusted create profile: `/sandbox/work` (64 MiB tmpfs,
0700, UID/GID 1000), `/sandbox/.dsh` (32 MiB, 0700, UID/GID 1000), `/tmp` (32 MiB,
01777). These are runtime mounts, not `VOLUME` declarations. The image does not
enforce mount sizes, CPU, RAM, PIDs, Landlock or command deadlines; those require
independent admitted configuration and kernel observations.

`source-inputs.json` records exact Dockerfile/build-context hashes, the recorded
base manifest/config pair, source pin and intended build parameters.
`../image-manifest.mjs` verifies the checked-in input hashes and inspects supplied
OCI manifest/config bytes against a projected local Docker image readback. It
performs no build, pull, daemon or gateway operation and returns unqualified
evidence only. Exact byte digests distinguish the OCI manifest from the image
config ID; no output digest is synthesized from a recipe.

An authorized build must capture the exact input hashes and invocation, use the
recorded platform/epoch/build tools, and export the single-platform image manifest
without provenance/index wrappers. Preserve actual config, manifest, layer bytes,
build metadata and license files. Verify all content-addressed descriptors and
layer bytes, the output platform/config, and that the approved local image load
returns the same config ID and layer diff IDs. Rebuild equality remains
unverified. The source helper checks the config/manifest binding and projected
load readback; it does not establish that a builder used the recorded source or
that layer bytes were verified.

The expected output pair remains **null** until review of those real artifacts.
The trusted host must then record both `workload_image_config_digest` and
`workload_oci_manifest_digest` separately. For local-only execution,
`image_digest` is the approved `sha256:<config-id>` and the operator pull policy
is `never`; a registry name, mutable tag, manifest index or guessed output is not
a substitute. Compare fresh actual config/manifest/load evidence with that exact
approved pair before accepting an image. This source document/helper cannot
authorize execution, qualify a runtime, or change `pins.json`.

No build or runtime check has run for this increment. Source preparation leaves
the actual F factory unavailable. Separate approval is required for keyless
local checks/builds and for any host setup or real guest qualification.

The minimum image-build approval covers only the three named actions: read the
recorded immutable base layers, build/export one local single-platform OCI image
from this allowlisted context with the fixed inputs, and load/inspect that image
on the approved private daemon. Tool installation/daemon start, other image
pulls, keys, gateway start and guest calls require their separately scoped setup
approval. Preserve the actual digest pair and source/build/layer evidence for
review; neither a completed build nor a Docker image ID qualifies execution.
