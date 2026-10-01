window.__ModuleLoader__.load({
	id: "@aukora/prime-authority-ui",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		let react_jsx_runtime = require("react/jsx-runtime");
		let react = require("react");
		let _aukora_face_layout_client = require("@aukora/face-layout/client");
		//#region adapters/transport.mjs
		/**
		* UI transport boundary. Authority owns challenges, signature verification and durable grants.
		* The composition injects browser-safe frozen contract helpers and transport methods; no URLs
		* or signing keys live here. Session tokens remain in memory, outside presentation objects.
		*/
		var PrimeTransportError = class extends Error {
			constructor(code, reason) {
				super(reason);
				this.name = "PrimeTransportError";
				this.code = code;
			}
		};
		const fail = (code, reason) => {
			throw new PrimeTransportError(code, reason);
		};
		const kinds = new Set(["owner_key", "passkey"]);
		const labels = Object.freeze({
			version: "Version",
			operation_id: "Operation",
			task_id: "Task",
			owner_id: "Owner",
			agent_id: "Agent",
			audience: "Audience",
			action_type: "Action",
			target_identity: "Target",
			canonical_parameters: "Exact parameters",
			data_scope: "Data scope",
			expected_state_version: "Expected state",
			provider_and_region: "Provider and region",
			maximum_cost: "Maximum cost",
			expiry: "Expires",
			nonce: "Nonce",
			policy_version: "Policy version",
			authorization_epoch: "Authorization epoch"
		});
		function freeze(value) {
			if (value && typeof value === "object") {
				for (const child of Object.values(value)) freeze(child);
				Object.freeze(value);
			}
			return value;
		}
		function createPrimeTransport({ authority, contracts, ownerSigner, passkeySigner, now = Date.now }) {
			for (const name of [
				"validateContract",
				"validateApprovalTemplate",
				"canonicalJson",
				"operationDigest"
			]) if (typeof contracts?.[name] !== "function") fail("UNAVAILABLE", `ui:contract-helper-unavailable:${name}`);
			const { canonicalJson, operationDigest } = contracts;
			const validateContract = (kind, value) => {
				try {
					return contracts.validateContract(kind, value);
				} catch {
					fail("INVALID", `ui:invalid-${kind}`);
				}
			};
			const exact = (value, label = "transport-json") => {
				try {
					return canonicalJson(value);
				} catch {
					fail("INVALID", `ui:invalid-${label}`);
				}
			};
			const copy = (value, label) => freeze(JSON.parse(exact(value, label)));
			const object = (value, label) => {
				if (!value || typeof value !== "object" || Array.isArray(value)) fail("INVALID", `ui:invalid-${label}`);
				return value;
			};
			let session = null;
			let loginPending = null;
			let loginOwner = null;
			let authRevision = 0;
			const presentations = /* @__PURE__ */ new WeakMap();
			const submissions = /* @__PURE__ */ new Map();
			function checkSignal(signal) {
				if (signal?.aborted) fail("CANCELLED", "ui:cancelled");
			}
			function checkExpiry(expiry) {
				if (typeof expiry !== "string" || !Number.isFinite(Date.parse(expiry))) fail("INVALID", "ui:invalid-expiry");
				if (Date.parse(expiry) <= now()) fail("EXPIRED", "ui:expired");
			}
			function ownerSession() {
				if (!session) fail("UNAUTHORIZED", "ui:login-required");
				checkExpiry(session.expiry);
				return session;
			}
			function sameSession(current) {
				if (session !== current) fail("UNAUTHORIZED", "ui:approval-session-changed");
				checkExpiry(current.expiry);
			}
			async function call(name, input, signal, mutation = false) {
				checkSignal(signal);
				if (typeof authority?.[name] !== "function") fail("UNAVAILABLE", `ui:authority-method-unavailable:${name}`);
				let answer;
				try {
					answer = await authority[name](input, { signal });
				} catch (error) {
					if (error instanceof PrimeTransportError) throw error;
					if (mutation) fail("OUTCOME_UNKNOWN", "ui:approval-submission-outcome-unknown");
					if (signal?.aborted || error?.name === "AbortError") fail("CANCELLED", "ui:cancelled");
					fail("UNAVAILABLE", `ui:authority-transport-unavailable:${name}`);
				}
				if (!answer || typeof answer !== "object") fail(mutation ? "OUTCOME_UNKNOWN" : "INVALID", "ui:invalid-authority-answer");
				if (answer.ok !== true) fail(typeof answer.error_code === "string" ? answer.error_code : "INVALID", typeof answer.reason === "string" ? answer.reason : "ui:authority-refused");
				return answer;
			}
			async function sign(kind, purpose, request, signal, public_key) {
				checkSignal(signal);
				const signer = kind === "owner_key" ? ownerSigner : passkeySigner;
				if (typeof signer !== "function") fail("UNAVAILABLE", `ui:${kind}-signer-unavailable`);
				let material;
				try {
					material = await signer({
						purpose,
						request,
						signal,
						public_key
					});
				} catch (error) {
					if (signal?.aborted || error?.name === "AbortError" || error?.name === "NotAllowedError") fail("CANCELLED", "ui:credential-request-cancelled");
					if (error instanceof PrimeTransportError) throw error;
					fail("UNAVAILABLE", `ui:${kind}-signer-unavailable`);
				}
				checkSignal(signal);
				object(material, "signature-material");
				if (material.kind !== kind) fail("INVALID", "ui:signature-kind-mismatch");
				if (typeof material.signature !== "string" || !material.signature) fail("INVALID", "ui:invalid-signature-material");
				if (kind === "owner_key" && purpose === "login" && Object.keys(material).sort().join(",") !== "kind,signature") fail("INVALID", "ui:login-material-fields");
				if (kind === "owner_key" && purpose === "approval") {
					object(material.request, "signed-review-request");
					if (exact(material.request, "signed-review-request") !== exact(request, "review-request")) fail("TARGET_MISMATCH", "ui:signed-review-request-changed");
				}
				return copy(material);
			}
			function proofMatches(proof, operation, digest, request) {
				const expected = {
					version: 1,
					operation_id: operation.operation_id,
					operation_digest: digest,
					owner_id: operation.owner_id,
					audience: operation.audience,
					authorization_epoch: operation.authorization_epoch,
					expiry: (/* @__PURE__ */ new Date(request.expiresAt * 1e3)).toISOString(),
					nonce: request.challenge
				};
				for (const [key, value] of Object.entries(expected)) if (proof?.[key] !== value) fail("TARGET_MISMATCH", `ui:approval-binding-mismatch:${key}`);
				checkExpiry(proof.expiry);
				if (Date.parse(proof.expiry) > Date.parse(operation.expiry)) fail("EXPIRED", "ui:approval-outlives-operation");
			}
			function reviewMatches(request, digest) {
				object(request, "review-request");
				if (Object.keys(request).sort().join(",") !== [
					"domain",
					"subject",
					"activeControlDigest",
					"operationDigest",
					"challenge",
					"issuedAt",
					"expiresAt"
				].sort().join(",") || request.domain !== "aukora:owner-approval-request:v1" || request.operationDigest !== digest.slice(7) || !/^aukora:1:[a-f0-9]{64}$/.test(request.subject) || !/^[a-f0-9]{64}$/.test(request.activeControlDigest) || !/^[a-f0-9]{64}$/.test(request.challenge) || !Number.isSafeInteger(request.issuedAt) || !Number.isSafeInteger(request.expiresAt) || request.issuedAt < 0 || request.expiresAt <= request.issuedAt) fail("TARGET_MISMATCH", "ui:approval-review-request-mismatch");
			}
			async function login({ owner_id, kind = "passkey", signal } = {}) {
				if (typeof owner_id !== "string" || !owner_id || !kinds.has(kind)) fail("INVALID", "ui:invalid-login-request");
				if (loginPending) {
					if (loginOwner !== `${kind}:${owner_id}`) fail("UNAUTHORIZED", "ui:another-login-in-progress");
					return loginPending;
				}
				session = null;
				const revision = ++authRevision;
				loginOwner = `${kind}:${owner_id}`;
				loginPending = (async () => {
					const answer = await call("loginChallenge", {
						owner_id,
						kind
					}, signal);
					const challenge = copy(object(answer.challenge, "login-challenge"), "login-challenge");
					if (challenge.owner_id !== owner_id) fail("UNAUTHORIZED", "ui:login-owner-mismatch");
					if (challenge.version !== 1 || typeof challenge.challenge !== "string" || !challenge.challenge || typeof challenge.audience !== "string" || !challenge.audience || !Number.isSafeInteger(challenge.authorization_epoch) || challenge.authorization_epoch < 0) fail("INVALID", "ui:invalid-login-challenge");
					checkExpiry(challenge.expiry);
					const material = await sign(kind, "login", challenge, signal, answer.public_key ? copy(answer.public_key) : void 0);
					if (authRevision !== revision) fail("CANCELLED", "ui:login-cancelled");
					checkExpiry(challenge.expiry);
					const complete = await call("loginComplete", {
						challenge,
						material
					}, signal);
					if (authRevision !== revision) fail("CANCELLED", "ui:login-cancelled");
					checkSignal(signal);
					if (complete.owner_id !== owner_id || typeof complete.session_token !== "string" || !complete.session_token) fail("UNAUTHORIZED", "ui:login-session-mismatch");
					checkExpiry(complete.expiry);
					session = {
						owner_id,
						session_token: complete.session_token,
						expiry: complete.expiry
					};
					return freeze({
						owner_id,
						expiry: complete.expiry
					});
				})();
				try {
					return await loginPending;
				} finally {
					loginPending = null;
					loginOwner = null;
				}
			}
			async function prepareApproval(proposal, { signal } = {}) {
				const current = ownerSession();
				validateContract("OperationProposal", proposal);
				const operation = copy(proposal);
				if (operation.owner_id !== current.owner_id) fail("UNAUTHORIZED", "ui:operation-owner-mismatch");
				checkExpiry(operation.expiry);
				const digest = await operationDigest(operation);
				const answer = await call("approvalChallenge", {
					session_token: current.session_token,
					operation
				}, signal);
				sameSession(current);
				validateContract("OperationProposal", answer.operation);
				if (canonicalJson(answer.operation) !== canonicalJson(operation) || answer.operation_digest !== digest) fail("TARGET_MISMATCH", "ui:approval-operation-changed");
				const proofTemplate = copy(object(answer.proof_template, "approval-template"), "approval-template");
				const request = copy(object(answer.approval_request, "review-request"), "review-request");
				reviewMatches(request, digest);
				try {
					contracts.validateApprovalTemplate(proofTemplate);
				} catch {
					fail("INVALID", "ui:invalid-approval-template");
				}
				proofMatches(proofTemplate, operation, digest, request);
				checkSignal(signal);
				checkExpiry(operation.expiry);
				const presentation = freeze({
					operation,
					operation_digest: digest,
					approval_expiry: proofTemplate.expiry,
					review_challenge: request,
					canonical_operation: canonicalJson(operation),
					rows: Object.keys(labels).map((key) => ({
						key,
						label: labels[key],
						value: operation[key],
						exact: canonicalJson(operation[key])
					}))
				});
				presentations.set(presentation, {
					operation,
					digest,
					proofTemplate,
					request,
					owner_id: current.owner_id,
					session_token: current.session_token,
					public_key: answer.public_key ? copy(answer.public_key) : void 0
				});
				return presentation;
			}
			async function approve(presentation, { kind = "passkey", signal } = {}) {
				if (!kinds.has(kind)) fail("INVALID", "ui:invalid-signature-kind");
				const record = presentations.get(presentation);
				if (!record) fail("INVALID", "ui:foreign-approval-presentation");
				if (kind !== record.proofTemplate.material.kind) fail("INVALID", "ui:signature-kind-mismatch");
				const current = ownerSession();
				if (record.owner_id !== current.owner_id || record.session_token !== current.session_token) fail("UNAUTHORIZED", "ui:approval-session-changed");
				const prior = submissions.get(record.digest);
				if (prior?.pending) {
					if (prior.decision !== "approve") fail("RECONCILIATION_REQUIRED", "ui:another-decision-pending");
					return prior.pending;
				}
				if (prior) fail(prior.code, prior.reason);
				checkExpiry(record.operation.expiry);
				checkExpiry(record.proofTemplate.expiry);
				const pending = (async () => {
					const material = await sign(kind, "approval", record.request, signal, record.public_key);
					sameSession(current);
					checkExpiry(record.operation.expiry);
					checkSignal(signal);
					const proof = copy({
						...record.proofTemplate,
						material
					});
					validateContract("ApprovalProof", proof);
					proofMatches(proof, record.operation, record.digest, record.request);
					submissions.set(record.digest, {
						code: "RECONCILIATION_REQUIRED",
						reason: "ui:approval-submission-needs-reconciliation"
					});
					let answer;
					try {
						answer = await call("approvalComplete", {
							session_token: current.session_token,
							proof
						}, signal, true);
					} catch (error) {
						submissions.set(record.digest, {
							code: error.code ?? "OUTCOME_UNKNOWN",
							reason: error.message
						});
						throw error;
					}
					if (answer.status !== "APPROVED") fail("OUTCOME_UNKNOWN", "ui:approval-result-unknown");
					try {
						validateContract("ApprovalProof", answer.approval_proof);
						proofMatches(answer.approval_proof, record.operation, record.digest, record.request);
						if (exact(answer.approval_proof) !== exact(proof)) fail("TARGET_MISMATCH", "ui:approval-proof-changed");
					} catch {
						submissions.set(record.digest, {
							code: "OUTCOME_UNKNOWN",
							reason: "ui:approval-result-invalid-needs-reconciliation"
						});
						fail("OUTCOME_UNKNOWN", "ui:approval-result-invalid-needs-reconciliation");
					}
					submissions.set(record.digest, {
						code: "REPLAYED",
						reason: "ui:approval-already-submitted"
					});
					return freeze({
						status: "APPROVED",
						approval_proof: copy(answer.approval_proof)
					});
				})();
				submissions.set(record.digest, {
					pending,
					decision: "approve"
				});
				try {
					return await pending;
				} catch (error) {
					if (submissions.get(record.digest)?.pending === pending) submissions.delete(record.digest);
					throw error;
				}
			}
			async function decline(presentation, { signal } = {}) {
				const record = presentations.get(presentation);
				if (!record) fail("INVALID", "ui:foreign-approval-presentation");
				const current = ownerSession();
				if (record.session_token !== current.session_token) fail("UNAUTHORIZED", "ui:approval-session-changed");
				const prior = submissions.get(record.digest);
				if (prior?.pending) {
					if (prior.decision !== "decline") fail("RECONCILIATION_REQUIRED", "ui:another-decision-pending");
					return prior.pending;
				}
				if (prior) fail(prior.code, prior.reason);
				checkSignal(signal);
				checkExpiry(record.operation.expiry);
				checkExpiry(record.proofTemplate.expiry);
				const pending = Promise.resolve().then(async () => {
					try {
						if ((await call("declineApproval", {
							session_token: current.session_token,
							operation_id: record.operation.operation_id
						}, signal, true)).status !== "DENIED") fail("OUTCOME_UNKNOWN", "ui:denial-result-unknown");
						submissions.set(record.digest, {
							code: "REPLAYED",
							reason: "ui:approval-denied"
						});
						return freeze({ status: "DENIED" });
					} catch (error) {
						submissions.set(record.digest, {
							code: error.code ?? "OUTCOME_UNKNOWN",
							reason: error.message
						});
						throw error;
					}
				});
				submissions.set(record.digest, {
					pending,
					decision: "decline"
				});
				return pending;
			}
			return Object.freeze({
				login,
				prepareApproval,
				approve,
				decline,
				logout() {
					session = null;
					authRevision++;
				},
				owner() {
					return session ? freeze({
						owner_id: session.owner_id,
						expiry: session.expiry
					}) : null;
				}
			});
		}
		//#endregion
		//#region adapters/passkey.mjs
		function binary(value) {
			if (value instanceof ArrayBuffer) return new Uint8Array(value);
			if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
			throw new PrimeTransportError("INVALID", "ui:invalid-assertion-bytes");
		}
		function encode(value) {
			return btoa(Array.from(binary(value), (byte) => String.fromCharCode(byte)).join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		}
		function decode(value) {
			if (typeof value !== "string" || !value || !/^[A-Za-z0-9_-]+$/.test(value)) throw new PrimeTransportError("INVALID", "ui:invalid-passkey-options");
			const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
			let bytes;
			try {
				bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
			} catch {
				throw new PrimeTransportError("INVALID", "ui:invalid-passkey-options");
			}
			if (encode(bytes) !== value) throw new PrimeTransportError("INVALID", "ui:noncanonical-passkey-options");
			return bytes;
		}
		/** Existing-credential assertion only. This module has no credentials.create or enrollment route. */
		function createBrowserPasskeySigner({ getCredential, contracts, profile, environment = globalThis } = {}) {
			if (profile && typeof profile === "object") profile = Object.freeze({ ...profile });
			const get = getCredential ?? (async (options) => {
				if (typeof environment.navigator?.credentials?.get !== "function") throw new PrimeTransportError("UNAVAILABLE", "ui:passkey-api-unavailable");
				return environment.navigator.credentials.get(options);
			});
			return async ({ purpose, request, public_key, signal }) => {
				if (!profile || Object.keys(profile).sort().join(",") !== "origin,profile,rp_id" || typeof profile.origin !== "string" || typeof profile.rp_id !== "string") throw new PrimeTransportError("UNAVAILABLE", "ui:passkey-profile-unavailable");
				let origin;
				try {
					origin = new URL(profile.origin);
				} catch {
					throw new PrimeTransportError("UNAVAILABLE", "ui:passkey-profile-unavailable");
				}
				const validRp = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(profile.rp_id) && !/^\d+(?:\.\d+){3}$/.test(profile.rp_id);
				const configuredHttps = profile.profile === "https" && origin.protocol === "https:" && validRp && (origin.hostname === profile.rp_id || origin.hostname.endsWith("." + profile.rp_id));
				const localhostPilot = profile.profile === "localhost-pilot-v1" && profile.origin === "http://localhost:18731" && profile.rp_id === "localhost";
				if (origin.origin !== profile.origin || !configuredHttps && !localhostPilot || environment.location?.origin !== profile.origin || environment.isSecureContext !== true || typeof environment.navigator?.credentials?.get !== "function" || typeof environment.PublicKeyCredential !== "function" || public_key?.rpId !== profile.rp_id) throw new PrimeTransportError("UNAVAILABLE", "ui:passkey-browser-profile-unavailable");
				if (!public_key || public_key.userVerification !== "required" || typeof public_key.rpId !== "string" || !public_key.rpId || !Array.isArray(public_key.allowCredentials) || !public_key.allowCredentials.length) throw new PrimeTransportError("UNAVAILABLE", "ui:passkey-not-configured");
				if (typeof contracts?.canonicalJson !== "function" || !globalThis.crypto?.subtle) throw new PrimeTransportError("UNAVAILABLE", "ui:passkey-contract-helper-unavailable");
				const domain = purpose === "login" ? "aukora-prime.owner-login.v1" : purpose === "approval" ? "aukora:owner-approval-signature:v1" : null;
				if (!domain) throw new PrimeTransportError("INVALID", "ui:passkey-purpose-invalid");
				if (encode(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(domain + "\0" + contracts.canonicalJson(request)))) !== public_key.challenge) throw new PrimeTransportError("TARGET_MISMATCH", "ui:passkey-challenge-request-mismatch");
				const credential = await get({
					publicKey: {
						...public_key,
						challenge: decode(public_key.challenge),
						allowCredentials: public_key.allowCredentials.map((credential) => {
							if (credential.type !== "public-key") throw new PrimeTransportError("INVALID", "ui:invalid-passkey-options");
							return {
								...credential,
								id: decode(credential.id)
							};
						})
					},
					signal
				});
				if (!credential || credential.type !== "public-key" || !credential.response) throw new PrimeTransportError("CANCELLED", "ui:passkey-assertion-cancelled");
				const credentialId = encode(credential.rawId);
				if (!public_key.allowCredentials.some((allowed) => allowed.id === credentialId)) throw new PrimeTransportError("UNAUTHORIZED", "ui:passkey-credential-mismatch");
				return Object.freeze({
					kind: "passkey",
					credential_id: credentialId,
					client_data_json: encode(credential.response.clientDataJSON),
					authenticator_data: encode(credential.response.authenticatorData),
					signature: encode(credential.response.signature),
					user_handle: credential.response.userHandle === null ? null : encode(credential.response.userHandle)
				});
			};
		}
		//#endregion
		//#region lib/types/client/controller.mjs
		async function readJson(response, contracts) {
			if (typeof contracts?.parseStrictJson !== "function") throw new PrimeTransportError("UNAVAILABLE", "ui:strict-json-helper-unavailable");
			try {
				return contracts.parseStrictJson(await response.text(), {
					maxBytes: 8388608,
					maxDepth: 64
				});
			} catch {
				throw new PrimeTransportError("INVALID", "ui:invalid-response-json");
			}
		}
		function createHttpAuthority(fetcher = globalThis.fetch, contracts) {
			return Object.freeze(Object.fromEntries([
				"loginChallenge",
				"loginComplete",
				"approvalChallenge",
				"approvalComplete",
				"declineApproval"
			].map((method) => [method, async (input, { signal } = {}) => {
				if (typeof contracts?.parseStrictJson !== "function" || typeof contracts?.canonicalJson !== "function") throw new PrimeTransportError("UNAVAILABLE", "ui:strict-json-helper-unavailable");
				let body;
				try {
					body = contracts.canonicalJson(input);
				} catch {
					throw new PrimeTransportError("INVALID", "ui:invalid-request-json");
				}
				const response = await fetcher("/api/prime/authority/" + method, {
					method: "POST",
					credentials: "same-origin",
					redirect: "error",
					cache: "no-store",
					headers: { "content-type": "application/json" },
					body,
					signal
				});
				let answer;
				try {
					answer = await readJson(response, contracts);
				} catch (error) {
					if (method === "approvalComplete" || method === "declineApproval") throw new PrimeTransportError("OUTCOME_UNKNOWN", "ui:decision-response-invalid-needs-reconciliation");
					throw error;
				}
				if (!response.ok && answer?.ok !== false) throw new Error("Authority response unavailable");
				return answer;
			}])));
		}
		const capabilityIds = Object.freeze([
			"owner-passkey",
			"approved-shell",
			"sdk-child-launchers",
			"model-inference",
			"durable-memory",
			"messaging",
			"media-generation"
		]);
		const CAPABILITY_LABELS = Object.freeze({
			"owner-passkey": "Owner passkey",
			"approved-shell": "Approved shell",
			"sdk-child-launchers": "SDK child launchers",
			"model-inference": "Model inference",
			"durable-memory": "Durable memory",
			messaging: "Messaging",
			"media-generation": "Media generation"
		});
		function validateCapabilities(value) {
			if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== [
				"version",
				"source_commit",
				"runtime_pid",
				"release_digest",
				"unavailable_capabilities",
				"phase",
				"qualification"
			].sort().join(",") || value.version !== 1 || !/^[a-f0-9]{40}$/.test(value.source_commit) || !Number.isSafeInteger(value.runtime_pid) || value.runtime_pid <= 0 || !/^sha256:[a-f0-9]{64}$/.test(value.release_digest) || value.phase !== "disposable-preview" || value.qualification !== "PENDING" || !Array.isArray(value.unavailable_capabilities) || value.unavailable_capabilities.some((id) => !capabilityIds.includes(id)) || new Set(value.unavailable_capabilities).size !== value.unavailable_capabilities.length) throw new PrimeTransportError("INVALID", "ui:invalid-capability-status");
			return immutable({
				...value,
				unavailable_capabilities: [...value.unavailable_capabilities]
			});
		}
		async function readHttpCapabilities(fetcher = globalThis.fetch, contracts, signal) {
			const response = await fetcher("/api/prime/capabilities", {
				method: "GET",
				credentials: "same-origin",
				redirect: "error",
				cache: "no-store",
				signal
			});
			if (!response.ok) throw new PrimeTransportError("UNAVAILABLE", "ui:capability-status-unavailable");
			return validateCapabilities(await readJson(response, contracts));
		}
		const immutable = (value) => {
			if (value && typeof value === "object") {
				for (const child of Object.values(value)) immutable(child);
				Object.freeze(value);
			}
			return value;
		};
		/** Observable presentation owner; only the injected host can authenticate or approve. */
		function createPrimeOwnerController({ now = Date.now, schedule = setTimeout, unschedule = clearTimeout } = {}) {
			const listeners = /* @__PURE__ */ new Set();
			let binding, transport, pending, timer, revision = 0, operation, ownerKind;
			let state = Object.freeze({
				phase: "unavailable",
				owner: null,
				owner_id: "",
				presentation: null,
				operation_available: false,
				login_kinds: ["passkey"],
				fixture: false,
				expired: false,
				reason: "Authority transport is unavailable.",
				error_code: "UNAVAILABLE",
				capabilities: null,
				capability_status: "pending",
				authority_available: false
			});
			const notify = (patch) => {
				state = Object.freeze({
					...state,
					...patch
				});
				for (const listen of listeners) listen();
			};
			const stopTimer = () => {
				if (timer) unschedule(timer);
				timer = void 0;
			};
			const checkExpiry = () => {
				stopTimer();
				const expires = [
					state.owner?.expiry,
					state.presentation?.approval_expiry,
					state.presentation?.operation.expiry
				].filter(Boolean).map(Date.parse);
				if (!expires.length) return;
				const remaining = Math.min(...expires) - now();
				if (remaining <= 0) {
					notify({
						expired: true,
						...pending ? {} : {
							phase: "expired",
							reason: "This session or review has expired. Sign in or request a fresh review."
						}
					});
					return;
				}
				timer = schedule(checkExpiry, Math.min(remaining, 2 ** 31 - 1));
			};
			const fail = (error) => {
				const code = typeof error?.code === "string" ? error.code : "UNAVAILABLE";
				const uncertain = ["OUTCOME_UNKNOWN", "RECONCILIATION_REQUIRED"].includes(code);
				notify({
					phase: uncertain ? "outcome_unknown" : code === "EXPIRED" ? "expired" : code === "UNAVAILABLE" ? "unavailable" : "refused",
					error_code: code,
					reason: uncertain ? "The host has not confirmed the result. Reconciliation is required; do not retry this approval." : String(error?.message ?? "Authority request failed."),
					expired: code === "EXPIRED" || state.expired
				});
			};
			async function action(phase, work, finish) {
				if (pending) return pending.promise;
				const current = revision;
				const abort = new AbortController();
				notify({
					phase,
					error_code: null,
					reason: phase === "login_pending" ? "Waiting for the authenticator and host confirmation." : phase === "review_pending" ? "Requesting a fresh review challenge." : "Waiting for host confirmation."
				});
				pending = {
					abort,
					promise: null
				};
				const promise = (async () => {
					try {
						const result = await work(abort.signal);
						if (current === revision) finish(result);
						return result;
					} catch (error) {
						if (current === revision) fail(error);
						return null;
					} finally {
						if (current === revision) {
							pending = void 0;
							checkExpiry();
						}
					}
				})();
				pending.promise = promise;
				return promise;
			}
			const api = {
				getSnapshot: () => state,
				subscribe(listener) {
					listeners.add(listener);
					return () => listeners.delete(listener);
				},
				connect(next) {
					++revision;
					pending?.abort.abort();
					pending = void 0;
					transport?.logout();
					stopTimer();
					operation = void 0;
					ownerKind = void 0;
					binding = next;
					try {
						transport = createPrimeTransport({
							authority: next.authority,
							contracts: next.contracts,
							ownerSigner: next.ownerSigner,
							passkeySigner: next.passkeySigner ?? createBrowserPasskeySigner({
								contracts: next.contracts,
								profile: next.passkeyProfile
							}),
							now
						});
						const available = next.requiresCapabilities !== true;
						notify({
							phase: available ? "logged_out" : "unavailable",
							owner: null,
							owner_id: next.owner_id ?? "",
							presentation: null,
							operation_available: false,
							login_kinds: Object.freeze((next.loginKinds ?? ["passkey"]).filter((kind) => kind === "passkey" || kind === "owner_key")),
							fixture: next.fixture === true,
							capabilities: null,
							capability_status: next.fixture === true ? "fixture" : "pending",
							authority_available: available,
							expired: false,
							error_code: available ? null : "UNAVAILABLE",
							reason: available ? "Sign in with an existing credential. The host must confirm your identity." : "Owner access is unavailable until the host supplies its capability status."
						});
						if (next.operation) api.setOperation(next.operation);
					} catch (error) {
						transport = void 0;
						fail(error);
					}
				},
				setCapabilities(value) {
					const capabilities = validateCapabilities(value);
					const available = binding?.requiresCapabilities !== true || !capabilities.unavailable_capabilities.includes("owner-passkey");
					notify({
						capabilities,
						capability_status: "loaded",
						authority_available: available,
						...!pending && !state.owner && transport ? {
							phase: available ? "logged_out" : "unavailable",
							error_code: available ? null : "UNAVAILABLE",
							reason: available ? "Sign in with an existing credential. The host must confirm your identity." : "Owner passkey access is unavailable in this disposable preview."
						} : {}
					});
				},
				capabilitiesUnavailable() {
					notify({
						capabilities: null,
						capability_status: "unavailable",
						...binding?.requiresCapabilities === true ? { authority_available: false } : {}
					});
				},
				setOwnerId(owner_id) {
					if (!pending && !state.owner) notify({ owner_id });
				},
				setOperation(proposal) {
					if (pending || state.phase === "outcome_unknown") throw new PrimeTransportError("RECONCILIATION_REQUIRED", "An authority request is pending or needs reconciliation.");
					binding.contracts.validateContract("OperationProposal", proposal);
					operation = immutable(JSON.parse(binding.contracts.canonicalJson(proposal)));
					notify({
						operation_available: true,
						presentation: null,
						expired: false,
						phase: state.owner ? "authenticated" : state.phase,
						reason: "The host supplied an operation. Request a fresh review before deciding."
					});
					checkExpiry();
				},
				login(kind = "passkey") {
					if (!transport || !state.authority_available || !state.login_kinds.includes(kind)) {
						fail(new PrimeTransportError("UNAVAILABLE", "This credential method is unavailable."));
						return Promise.resolve(null);
					}
					return action("login_pending", (signal) => transport.login({
						owner_id: state.owner_id,
						kind,
						signal
					}), (owner) => {
						ownerKind = kind;
						notify({
							phase: "authenticated",
							owner,
							presentation: null,
							expired: false,
							error_code: null,
							reason: "The host confirmed this owner session."
						});
					});
				},
				prepare() {
					if (!transport || !state.authority_available || !operation) {
						fail(new PrimeTransportError("UNAVAILABLE", "An available authority and a host operation are required."));
						return Promise.resolve(null);
					}
					return action("review_pending", (signal) => transport.prepareApproval(operation, { signal }), (presentation) => {
						notify({
							phase: "review_ready",
							presentation,
							expired: false,
							error_code: null,
							reason: "Review every field below. Approval requests a fresh assertion and requires host confirmation."
						});
					});
				},
				approve() {
					if (state.phase !== "review_ready" || state.expired || !state.authority_available) return Promise.resolve(null);
					const presentation = state.presentation;
					return action("approval_pending", (signal) => transport.approve(presentation, {
						kind: ownerKind ?? "passkey",
						signal
					}), (result) => {
						notify({
							phase: "approved",
							error_code: null,
							reason: result.status === "APPROVED" ? "The host confirmed approval of this exact operation. Execution has not been confirmed." : "The result is unknown."
						});
					});
				},
				decline() {
					if (state.phase !== "review_ready" || state.expired || !state.authority_available) return Promise.resolve(null);
					const presentation = state.presentation;
					return action("decline_pending", (signal) => transport.decline(presentation, { signal }), () => {
						notify({
							phase: "denied",
							error_code: null,
							reason: "The host confirmed that this operation was declined."
						});
					});
				},
				logout() {
					++revision;
					pending?.abort.abort();
					pending = void 0;
					transport?.logout();
					stopTimer();
					ownerKind = void 0;
					notify({
						phase: transport && state.authority_available ? "logged_out" : "unavailable",
						owner: null,
						presentation: null,
						expired: false,
						reason: "Signed out. A new host-confirmed session is required.",
						error_code: null
					});
				},
				disconnect() {
					++revision;
					pending?.abort.abort();
					pending = void 0;
					transport?.logout();
					transport = void 0;
					ownerKind = void 0;
					operation = void 0;
					stopTimer();
					notify({
						phase: "unavailable",
						owner: null,
						presentation: null,
						operation_available: false,
						expired: false,
						error_code: "UNAVAILABLE",
						reason: "Authority transport is unavailable.",
						authority_available: false
					});
				},
				dispose() {
					++revision;
					pending?.abort.abort();
					pending = void 0;
					transport?.logout();
					stopTimer();
					listeners.clear();
				}
			};
			return Object.freeze(api);
		}
		//#endregion
		//#region \0dsh-css:packages/client/aukora-prime-authority/src/client/OwnerSurface.module.css.mjs
		const css = ".rHd7va_surface[hidden]{display:none!important}.rHd7va_surface{box-sizing:border-box;overscroll-behavior:contain;width:100%;min-width:0;max-width:46rem;height:100%;min-height:0;color:var(--aukora-text);background:0 0;flex-direction:column;gap:18px;margin:0 auto;padding:22px 20px 48px;display:flex;position:relative;overflow-y:auto}.rHd7va_header{flex-direction:column;align-items:flex-start;gap:4px}.rHd7va_header h1{margin:0;font-size:20px;font-weight:600;line-height:28px}.rHd7va_header p{color:var(--aukora-text-secondary);margin:0}.rHd7va_card{min-width:0;padding:16px}.rHd7va_card h2{margin-top:0;font-size:16px;font-weight:600}.rHd7va_card pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 var(--dsw-font-family-mono);margin:4px 0}.rHd7va_fields{flex-direction:column;gap:12px;display:flex}.rHd7va_fields dd{margin:0}.rHd7va_fields dt{color:var(--aukora-text-secondary);font-size:13px}.rHd7va_actions{flex-wrap:wrap;gap:8px;margin-top:12px;display:flex}.rHd7va_owner{flex-direction:column;gap:8px;display:flex}.rHd7va_owner input{box-sizing:border-box;border:1px solid var(--aukora-border);border-radius:var(--aukora-radius);background:var(--aukora-surface);color:var(--aukora-text);font:inherit;padding:10px 14px}.rHd7va_owner input:focus-visible{outline:2px solid var(--aukora-blue);outline-offset:2px}.rHd7va_error{color:var(--aukora-red-warning)}.rHd7va_menu{width:100%}.rHd7va_capabilities{margin:12px 0 0;padding-left:18px;font-size:12px;line-height:1.7}.rHd7va_badge{max-width:min(26rem,100% - 96px);color:var(--aukora-text);border:1px solid var(--aukora-border);border-radius:var(--aukora-radius);background:var(--aukora-surface);font-size:11px;position:absolute;bottom:20px;left:50%;transform:translate(-50%)}.rHd7va_badge summary{cursor:pointer;color:var(--aukora-text-secondary);padding:7px 10px}.rHd7va_badgePanel{overflow-wrap:anywhere;max-height:clamp(0px,100dvh - 120px,30rem);padding:0 12px 12px;overflow:auto}.rHd7va_badgePanel h2{font-size:14px}";
		const tagId = "@aukora/prime-authority-ui/OwnerSurface.module.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "@aukora/prime-authority-ui";
			tag.dataset.pluginCss = tagId;
			tag.textContent = css;
			document.head.appendChild(tag);
		}
		var OwnerSurface_module_css_default = {
			"actions": "rHd7va_actions",
			"badge": "rHd7va_badge",
			"badgePanel": "rHd7va_badgePanel",
			"capabilities": "rHd7va_capabilities",
			"card": "rHd7va_card",
			"error": "rHd7va_error",
			"fields": "rHd7va_fields",
			"header": "rHd7va_header",
			"menu": "rHd7va_menu",
			"owner": "rHd7va_owner",
			"surface": "rHd7va_surface"
		};
		//#endregion
		//#region lib/types/client/OwnerSurface.js
		function OwnerSurface({ activeSurface, controller }) {
			const state = (0, react.useSyncExternalStore)(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
			const busy = state.phase.endsWith("_pending");
			const locked = busy || state.phase === "outcome_unknown";
			const view = state.presentation;
			return (0, react_jsx_runtime.jsxs)("section", {
				className: OwnerSurface_module_css_default.surface,
				hidden: activeSurface !== "prime-owner",
				"data-prime-owner-surface": true,
				"data-phase": state.phase,
				children: [
					(0, react_jsx_runtime.jsxs)(_aukora_face_layout_client.SectionHeader, {
						className: OwnerSurface_module_css_default.header,
						children: [(0, react_jsx_runtime.jsx)("h1", { children: "Owner access and approvals" }), (0, react_jsx_runtime.jsx)("p", { children: "Use an existing credential. Enrollment is unavailable here." })]
					}),
					state.fixture && (0, react_jsx_runtime.jsx)("p", {
						role: "alert",
						"data-disposable-fixture": true,
						children: "Disposable UI fixture. Authentication and approvals below are synthetic; no effect is executed."
					}),
					(0, react_jsx_runtime.jsx)(_aukora_face_layout_client.Panel, {
						className: OwnerSurface_module_css_default.card,
						children: (0, react_jsx_runtime.jsx)(CapabilityDetails, { controller })
					}),
					(0, react_jsx_runtime.jsxs)(_aukora_face_layout_client.Panel, {
						className: OwnerSurface_module_css_default.card,
						children: [
							(0, react_jsx_runtime.jsx)("h2", { children: "Owner session" }),
							state.owner ? (0, react_jsx_runtime.jsxs)(react_jsx_runtime.Fragment, { children: [(0, react_jsx_runtime.jsxs)("p", {
								"data-owner-confirmed": true,
								children: ["Host-confirmed owner: ", (0, react_jsx_runtime.jsx)("code", { children: state.owner.owner_id })]
							}), (0, react_jsx_runtime.jsxs)("p", { children: ["Session expires: ", (0, react_jsx_runtime.jsx)("time", { children: state.owner.expiry })] })] }) : (0, react_jsx_runtime.jsxs)("label", {
								className: OwnerSurface_module_css_default.owner,
								children: ["Owner ID", (0, react_jsx_runtime.jsx)("input", {
									autoComplete: "off",
									value: state.owner_id,
									disabled: busy,
									onChange: (event) => controller.setOwnerId(event.target.value),
									"aria-label": "Owner ID"
								})]
							}),
							(0, react_jsx_runtime.jsxs)("div", {
								className: OwnerSurface_module_css_default.actions,
								children: [!state.owner && state.login_kinds.map((kind) => (0, react_jsx_runtime.jsx)(_aukora_face_layout_client.ActionButton, {
									disabled: busy || !state.owner_id || !state.authority_available || state.phase === "unavailable",
									onClick: () => {
										controller.login(kind);
									},
									children: kind === "passkey" ? "Sign in with passkey" : "Sign in with owner key"
								}, kind)), state.owner && (0, react_jsx_runtime.jsx)(_aukora_face_layout_client.ActionButton, {
									disabled: busy,
									onClick: () => controller.logout(),
									children: "Sign out"
								})]
							})
						]
					}),
					(0, react_jsx_runtime.jsxs)(_aukora_face_layout_client.Panel, {
						className: OwnerSurface_module_css_default.card,
						children: [
							(0, react_jsx_runtime.jsx)("h2", { children: "Exact operation" }),
							!state.operation_available && (0, react_jsx_runtime.jsx)("p", { children: "No operation has been supplied by the host." }),
							state.operation_available && (0, react_jsx_runtime.jsx)(_aukora_face_layout_client.ActionButton, {
								disabled: !state.owner || locked || !state.authority_available || state.phase === "approved" || state.phase === "denied",
								onClick: () => {
									controller.prepare();
								},
								children: "Request fresh review"
							}),
							view && (0, react_jsx_runtime.jsxs)(react_jsx_runtime.Fragment, { children: [
								(0, react_jsx_runtime.jsx)("dl", {
									className: OwnerSurface_module_css_default.fields,
									"data-exact-operation": true,
									children: view.rows.map((row) => (0, react_jsx_runtime.jsxs)("div", {
										"data-operation-field": row.key,
										children: [(0, react_jsx_runtime.jsxs)("dt", { children: [
											row.label,
											" ",
											(0, react_jsx_runtime.jsxs)("code", { children: [
												"(",
												row.key,
												")"
											] })
										] }), (0, react_jsx_runtime.jsx)("dd", { children: (0, react_jsx_runtime.jsx)("pre", { children: row.exact }) })]
									}, row.key))
								}),
								(0, react_jsx_runtime.jsx)("p", { children: "Operation digest" }),
								(0, react_jsx_runtime.jsx)("pre", {
									"data-operation-digest": true,
									children: view.operation_digest
								}),
								(0, react_jsx_runtime.jsxs)("p", { children: ["Review expires: ", (0, react_jsx_runtime.jsx)("time", {
									"data-approval-expiry": true,
									children: view.approval_expiry
								})] }),
								(0, react_jsx_runtime.jsx)("p", { children: "Fresh review challenge" }),
								(0, react_jsx_runtime.jsx)("pre", {
									"data-review-challenge": true,
									children: JSON.stringify(view.review_challenge, null, 2)
								}),
								(0, react_jsx_runtime.jsx)("p", { children: "Exact canonical operation" }),
								(0, react_jsx_runtime.jsx)("pre", {
									"data-canonical-operation": true,
									children: view.canonical_operation
								}),
								(0, react_jsx_runtime.jsxs)("div", {
									className: OwnerSurface_module_css_default.actions,
									children: [(0, react_jsx_runtime.jsx)(_aukora_face_layout_client.ActionButton, {
										variant: "gold",
										disabled: state.phase !== "review_ready" || state.expired || !state.authority_available,
										onClick: () => {
											controller.approve();
										},
										children: "Approve exact operation"
									}), (0, react_jsx_runtime.jsx)(_aukora_face_layout_client.ActionButton, {
										variant: "red-warning",
										disabled: state.phase !== "review_ready" || state.expired || !state.authority_available,
										onClick: () => {
											controller.decline();
										},
										children: "Decline"
									})]
								})
							] })
						]
					}),
					(0, react_jsx_runtime.jsx)("p", {
						role: "status",
						"aria-live": "polite",
						"data-prime-authority-status": true,
						children: state.reason
					}),
					state.error_code && (0, react_jsx_runtime.jsx)("p", {
						role: "alert",
						className: OwnerSurface_module_css_default.error,
						"data-authority-error": state.error_code,
						children: state.error_code
					}),
					state.expired && (0, react_jsx_runtime.jsx)("p", {
						role: "alert",
						children: "This session or review has expired."
					})
				]
			});
		}
		function CapabilityDetails({ controller }) {
			const state = (0, react.useSyncExternalStore)(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
			const value = state.capabilities;
			return (0, react_jsx_runtime.jsxs)("div", {
				"data-prime-capability-status": state.capability_status,
				children: [
					(0, react_jsx_runtime.jsx)("h2", { children: "Disposable preview · qualification pending" }),
					(0, react_jsx_runtime.jsx)("p", { children: "Source metadata does not prove that memory is loaded or a capability is working." }),
					!value && (0, react_jsx_runtime.jsx)("p", { children: state.fixture ? "Synthetic fixture only. Runtime capability status is unavailable." : state.capability_status === "pending" ? "Waiting for runtime capability status." : "Runtime capability status is unavailable." }),
					value && (0, react_jsx_runtime.jsxs)("dl", {
						className: OwnerSurface_module_css_default.fields,
						children: [
							(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Source commit" }), (0, react_jsx_runtime.jsx)("dd", { children: (0, react_jsx_runtime.jsx)("code", {
								"data-source-commit": true,
								children: value.source_commit
							}) })] }),
							(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Runtime PID" }), (0, react_jsx_runtime.jsx)("dd", {
								"data-runtime-pid": true,
								children: value.runtime_pid
							})] }),
							(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Release digest" }), (0, react_jsx_runtime.jsx)("dd", { children: (0, react_jsx_runtime.jsx)("code", {
								"data-release-digest": true,
								children: value.release_digest
							}) })] })
						]
					}),
					(0, react_jsx_runtime.jsx)("ul", {
						className: OwnerSurface_module_css_default.capabilities,
						children: Object.entries(CAPABILITY_LABELS).map(([id, label]) => (0, react_jsx_runtime.jsxs)("li", {
							"data-capability": id,
							children: [
								label,
								": ",
								(0, react_jsx_runtime.jsx)("strong", { children: value?.unavailable_capabilities.includes(id) ? "Unavailable" : "Not qualified" })
							]
						}, id))
					})
				]
			});
		}
		function CapabilityBadge({ controller }) {
			return (0, react_jsx_runtime.jsxs)("details", {
				className: OwnerSurface_module_css_default.badge,
				"data-prime-capability-badge": true,
				"data-reserves-hot-corners": true,
				children: [(0, react_jsx_runtime.jsx)("summary", { children: "Disposable preview · pending" }), (0, react_jsx_runtime.jsx)("div", {
					className: OwnerSurface_module_css_default.badgePanel,
					children: (0, react_jsx_runtime.jsx)(CapabilityDetails, { controller })
				})]
			});
		}
		function OwnerMenu({ activeSurface, openSurface }) {
			return (0, react_jsx_runtime.jsx)(_aukora_face_layout_client.ActionButton, {
				className: OwnerSurface_module_css_default.menu,
				"aria-current": activeSurface === "prime-owner" ? "page" : void 0,
				"data-prime-owner-launcher": true,
				onClick: () => openSurface("prime-owner", void 0, "contained"),
				children: "Owner access"
			});
		}
		//#endregion
		//#region lib/types/client/index.js
		var __rewriteRelativeImportExtension = function(path, preserveJsx) {
			if (typeof path === "string" && /^\.\.?\//.test(path)) return path.replace(/\.(tsx)$|((?:\.d)?)((?:\.[^./]+?)?)\.([cm]?)ts$/i, function(m, tsx, d, ext, cm) {
				return tsx ? preserveJsx ? ".jsx" : ".js" : d && (!ext || !cm) ? m : d + ext + "." + cm.toLowerCase() + "js";
			});
			return path;
		};
		const inject = [
			"slots",
			"layout",
			"locale"
		];
		function apply(ctx) {
			const controller = createPrimeOwnerController();
			let supplied = false;
			ctx.effect(() => {
				const off = ctx.reflect.provide("primeOwnerUi", controller);
				return () => {
					controller.dispose();
					off();
				};
			}, "prime owner UI controller");
			ctx.inject(["primeAuthority"], (binding) => {
				supplied = true;
				controller.connect(binding.primeAuthority);
				binding.effect(() => () => {
					supplied = false;
					controller.disconnect();
				}, "prime authority UI binding");
			});
			ctx.effect(() => {
				let disposed = false;
				const load = (url) => import(__rewriteRelativeImportExtension(
					/* @vite-ignore */
					url
				));
				load("/prime/contracts/browser.mjs").then((contracts) => {
					if (!disposed && !supplied) {
						controller.connect({
							authority: createHttpAuthority(void 0, contracts),
							contracts,
							requiresCapabilities: true
						});
						readHttpCapabilities(void 0, contracts).then((capabilities) => {
							if (!disposed && !supplied) controller.setCapabilities(capabilities);
						}).catch(() => {
							if (!disposed && !supplied) controller.capabilitiesUnavailable();
						});
					}
				}).catch(() => {});
				return () => {
					disposed = true;
				};
			}, "prime browser contract helper");
			ctx.slots.inject("shell.surface", () => ctx.slots.register({
				name: "shell.surface",
				id: "prime-owner",
				order: 70,
				inject: () => ({ controller })
			}, OwnerSurface));
			ctx.slots.inject("shell.menu.system", () => ctx.slots.register({
				name: "shell.menu.system",
				id: "prime-owner",
				order: 70
			}, OwnerMenu));
			ctx.slots.inject("shell.overlay", () => ctx.slots.register({
				name: "shell.overlay",
				id: "prime-capabilities",
				order: 70,
				inject: () => ({ controller })
			}, CapabilityBadge));
		}
		//#endregion
		exports.CapabilityBadge = CapabilityBadge;
		exports.OwnerSurface = OwnerSurface;
		exports.apply = apply;
		exports.createHttpAuthority = createHttpAuthority;
		exports.createPrimeOwnerController = createPrimeOwnerController;
		exports.inject = inject;
		return module.exports;
	}
});

//# sourceMappingURL=client.js.map