Prime transport contracts v1 are frozen by the integration owner. All transport envelopes are closed-field objects and version 1. Only safe integers are transport numbers; currency amounts use decimal strings. UTC timestamps end in Z. operationDigest hashes the domain prefix aukora-prime.operation.v1 followed by NUL and sorted-key compact JSON. A proof is untrusted input until the authority lane verifies material, owner/audience/epoch/expiry/nonce and the exact digest, then durably reserves the consumed grant. The shared validator performs structural validation only; it grants no authority.

MemoryRecord wraps the exact original UTF-8 canonical_bytes with its donor format/canonicalizer and ID. Do not call canonicalJson on the inner original bytes, recanonicalize v0/v1 records or generate salts. Saved and index status are separate. Records never grant authority.

Execution uses OwnedExecutor.execute with operation, consumed_grant, request_id, image_digest, policy_digest, wall_time_ms, max_output_bytes and optional AbortSignal. No argv confinement abstraction or host fallback. Complete means exit zero, fully drained RPC and owned cleanup confirmed absent. Transport failure preserves an observed exit while retaining outcome uncertainty. SDK child launchers remain unavailable until qualified.

Extensions require an integration review and version change for closed fields. Each lane may have local richer interfaces and map them at the transport boundary.

