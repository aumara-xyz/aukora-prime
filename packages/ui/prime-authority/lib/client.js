window.__ModuleLoader__.load({
	id: "@aukora/prime-authority-ui",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		let react_jsx_runtime = require("react/jsx-runtime");
		let react = require("react");
		let _aukora_face_layout_client = require("@aukora/face-layout/client");
		const CAPTURE_ATTRIBUTIONS = Object.freeze([
			"owner",
			"owner-voice",
			"owner-edit",
			"backfill",
			"lane-requester",
			"dream",
			"agent"
		]);
		const CAPTURE_PARAMETER_FIELDS = Object.freeze([
			"capture_sha256",
			"idempotency_key_sha256",
			"heads",
			"statement",
			"attributed_to"
		]);
		const fail$2 = () => {
			throw new TypeError("memory:capture-review-invalid");
		};
		const object = (value, fields) => {
			if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail$2();
			const keys = Reflect.ownKeys(value);
			if (keys.length !== fields.length || keys.some((k) => typeof k !== "string" || !fields.includes(k))) fail$2();
			for (const key of keys) {
				const descriptor = Object.getOwnPropertyDescriptor(value, key);
				if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail$2();
			}
		};
		function statement(value) {
			if (typeof value !== "string" || value.length === 0 || value.length > 4096 || !value.trim() || /[\u0000-\u0008\u000b-\u001f\u007f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value)) fail$2();
			for (let i = 0; i < value.length; i++) {
				const unit = value.charCodeAt(i);
				if (unit >= 55296 && unit <= 56319) {
					const next = value.charCodeAt(++i);
					if (!(next >= 56320 && next <= 57343)) fail$2();
				} else if (unit >= 56320 && unit <= 57343) fail$2();
			}
		}
		function validateCaptureDraft(draft) {
			object(draft, ["statement", "attributed_to"]);
			statement(draft.statement);
			if (!CAPTURE_ATTRIBUTIONS.includes(draft.attributed_to)) fail$2();
			return Object.freeze({
				statement: draft.statement,
				attributed_to: draft.attributed_to
			});
		}
		function validateCaptureReview(parameters, immutableDraft) {
			object(parameters, CAPTURE_PARAMETER_FIELDS);
			const draft = validateCaptureDraft(immutableDraft);
			if (typeof parameters.capture_sha256 !== "string" || typeof parameters.idempotency_key_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(parameters.capture_sha256) || !/^[0-9a-f]{64}$/.test(parameters.idempotency_key_sha256)) fail$2();
			if (!parameters.heads || ![Object.prototype, null].includes(Object.getPrototypeOf(parameters.heads))) fail$2();
			object(parameters.heads, Object.keys(parameters.heads));
			for (const [domain, head] of Object.entries(parameters.heads)) if (![
				"remembered",
				"approved",
				"legacy-presplit"
			].includes(domain) || typeof head !== "string" || !(head === "aukora:aura-record:v1" || /^[0-9a-f]{64}$/.test(head))) fail$2();
			if (parameters.statement !== draft.statement || parameters.attributed_to !== draft.attributed_to) fail$2();
			return draft;
		}
		//#endregion
		//#region lib/types/adapters/capture-metadata.mjs
		function validateCaptureMetadata(value) {
			const fields = [
				"profile",
				"category",
				"valid_from",
				"observed_at",
				"confidence_percent",
				"sensitivity"
			];
			if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Reflect.ownKeys(value).length !== fields.length || Reflect.ownKeys(value).some((key) => !fields.includes(key))) throw new TypeError("ui:fixed-capture-metadata-required");
			for (const key of fields) {
				const descriptor = Object.getOwnPropertyDescriptor(value, key);
				if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new TypeError("ui:fixed-capture-metadata-required");
			}
			if (value.profile !== "prime-pilot-memory-capture/v1" || value.category !== "fact" || value.confidence_percent !== 70 || value.sensitivity !== "none" || typeof value.observed_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.observed_at) || !Number.isFinite(Date.parse(value.observed_at)) || new Date(value.observed_at).toISOString().replace(".000Z", "Z") !== value.observed_at || value.valid_from !== value.observed_at.slice(0, 10)) throw new TypeError("ui:fixed-capture-metadata-required");
			return Object.freeze({ ...value });
		}
		const FORGET_STATEMENT_MAX_BYTES = 16384;
		const FORGET_REFERENCE_MAX_BYTES = 1024;
		const FORGET_SUMMARY_FIELDS = Object.freeze([
			"record_id",
			"revision",
			"statement",
			"attributed_to"
		]);
		const FORGET_PARAMETER_FIELDS = Object.freeze([
			"profile",
			"record_id",
			"revision",
			"canonical_sha256",
			"at",
			"heads",
			"statement",
			"attributed_to"
		]);
		const OPERATION_FIELDS = Object.freeze([
			"version",
			"operation_id",
			"task_id",
			"owner_id",
			"agent_id",
			"audience",
			"action_type",
			"target_identity",
			"canonical_parameters",
			"data_scope",
			"expected_state_version",
			"provider_and_region",
			"maximum_cost",
			"expiry",
			"nonce",
			"policy_version",
			"authorization_epoch"
		]);
		const HEX64 = /^[a-f0-9]{64}$/;
		const DOMAINS = Object.freeze([
			"remembered",
			"approved",
			"legacy-presplit"
		]);
		const encoder = new TextEncoder();
		const fail$1 = () => {
			throw new TypeError("ui:forget-review-invalid");
		};
		function scalar(value) {
			if (typeof value !== "string") fail$1();
			for (let index = 0; index < value.length; index++) {
				const unit = value.charCodeAt(index);
				if (unit >= 55296 && unit <= 56319) {
					const next = value.charCodeAt(++index);
					if (!(next >= 56320 && next <= 57343)) fail$1();
				} else if (unit >= 56320 && unit <= 57343) fail$1();
			}
		}
		function text$1(value, maxBytes) {
			scalar(value);
			if (!value.length || encoder.encode(value).length > maxBytes) fail$1();
		}
		function dataObject(value, fields) {
			if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail$1();
			const keys = Reflect.ownKeys(value);
			if (fields && (keys.length !== fields.length || keys.some((key) => typeof key !== "string" || !fields.includes(key)))) fail$1();
			const detached = Object.create(null);
			for (const key of keys) {
				if (typeof key !== "string") fail$1();
				scalar(key);
				const descriptor = Object.getOwnPropertyDescriptor(value, key);
				if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail$1();
				detached[key] = descriptor.value;
			}
			return detached;
		}
		function dataOnly(value, ancestors = /* @__PURE__ */ new Set(), depth = 0) {
			if (depth > 64) fail$1();
			if (value === null || typeof value === "boolean") return;
			if (typeof value === "string") {
				scalar(value);
				return;
			}
			if (typeof value === "number") {
				if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail$1();
				return;
			}
			if (typeof value !== "object" || ancestors.has(value)) fail$1();
			ancestors.add(value);
			if (Array.isArray(value)) {
				if (Object.getPrototypeOf(value) !== Array.prototype) fail$1();
				const length = Object.getOwnPropertyDescriptor(value, "length");
				if (!length || !Object.hasOwn(length, "value") || !Number.isSafeInteger(length.value) || length.value < 0) fail$1();
				const keys = Reflect.ownKeys(value);
				if (keys.length !== length.value + 1 || keys.some((key) => typeof key !== "string" || key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key))) fail$1();
				for (let index = 0; index < length.value; index++) {
					const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
					if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail$1();
					dataOnly(descriptor.value, ancestors, depth + 1);
				}
			} else for (const child of Object.values(dataObject(value))) dataOnly(child, ancestors, depth + 1);
			ancestors.delete(value);
		}
		/** Match an independent retained record summary to the signed forget proposal.
		* Hash/head syntax is checked; their values are not independently audited here.
		* Legacy text, attribution, whitespace and Unicode remain literal and unchanged. */
		function validateForgetReview(operation, independentlyRetainedRecordSummary) {
			const op = dataObject(operation, OPERATION_FIELDS);
			dataOnly(operation);
			if (op.version !== 1 || op.action_type !== "memory.forget" || op.audience !== "aukora-prime.memory") fail$1();
			const target = dataObject(op.target_identity, ["kind", "owner_subject"]);
			if (target.kind !== "prime-memory" || typeof target.owner_subject !== "string" || !/^aukora:1:[a-f0-9]{64}$/.test(target.owner_subject) || typeof op.expected_state_version !== "string" || !/^sha256:[a-f0-9]{64}$/.test(op.expected_state_version)) fail$1();
			const parameters = dataObject(op.canonical_parameters, FORGET_PARAMETER_FIELDS);
			if (parameters.profile !== "prime-logical-forget/v1" || typeof parameters.canonical_sha256 !== "string" || !HEX64.test(parameters.canonical_sha256)) fail$1();
			const heads = dataObject(parameters.heads);
			for (const [domain, head] of Object.entries(heads)) if (!DOMAINS.includes(domain) || typeof head !== "string" || head !== "aukora:aura-record:v1" && !HEX64.test(head)) fail$1();
			if (typeof parameters.at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(parameters.at)) fail$1();
			const at = new Date(parameters.at);
			if (!Number.isFinite(at.valueOf()) || at.toISOString().slice(0, 19) + "Z" !== parameters.at) fail$1();
			const summary = dataObject(independentlyRetainedRecordSummary, FORGET_SUMMARY_FIELDS);
			for (const source of [summary, parameters]) {
				text$1(source.record_id, FORGET_REFERENCE_MAX_BYTES);
				text$1(source.revision, FORGET_REFERENCE_MAX_BYTES);
				text$1(source.statement, FORGET_STATEMENT_MAX_BYTES);
				if (source.attributed_to !== null) text$1(source.attributed_to, FORGET_REFERENCE_MAX_BYTES);
			}
			if (FORGET_SUMMARY_FIELDS.some((field) => parameters[field] !== summary[field])) fail$1();
			return Object.freeze({
				record_id: summary.record_id,
				revision: summary.revision,
				statement: summary.statement,
				attributed_to: summary.attributed_to
			});
		}
		//#endregion
		//#region lib/types/adapters/transport.mjs
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
		function freeze$1(value) {
			if (value && typeof value === "object") {
				for (const child of Object.values(value)) freeze$1(child);
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
			const copy = (value, label) => freeze$1(JSON.parse(exact(value, label)));
			const object = (value, label) => {
				if (!value || typeof value !== "object" || Array.isArray(value)) fail("INVALID", `ui:invalid-${label}`);
				return value;
			};
			let session = null;
			let loginPending = null;
			let loginOwner = null;
			let authRevision = 0;
			let logoutFlight = null;
			let logoutResult = null;
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
				if (logoutFlight) fail("RECONCILIATION_REQUIRED", "ui:logout-pending");
				if (loginPending) {
					if (loginOwner !== `${kind}:${owner_id}`) fail("UNAUTHORIZED", "ui:another-login-in-progress");
					return loginPending;
				}
				session = null;
				logoutResult = null;
				const revision = ++authRevision;
				loginOwner = `${kind}:${owner_id}`;
				const flight = (async () => {
					const answer = await call("loginChallenge", {
						owner_id,
						kind
					}, signal);
					if (authRevision !== revision) fail("CANCELLED", "ui:login-cancelled");
					checkSignal(signal);
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
					return freeze$1({
						owner_id,
						expiry: complete.expiry
					});
				})();
				loginPending = flight;
				try {
					return await flight;
				} finally {
					if (loginPending === flight) {
						loginPending = null;
						loginOwner = null;
					}
				}
			}
			function logout() {
				if (logoutFlight) return logoutFlight;
				if (!session && !loginPending && logoutResult) return Promise.resolve(logoutResult);
				const current = session;
				session = null;
				authRevision++;
				loginPending = null;
				loginOwner = null;
				const unconfirmed = (code) => freeze$1({
					ok: false,
					error_code: code,
					reason: code === "UNAVAILABLE" ? "ui:server-logout-unavailable" : code === "UNAUTHORIZED" ? "ui:server-logout-refused" : "ui:server-logout-not-confirmed"
				});
				let resolveAnswer;
				const flight = new Promise((resolve) => {
					resolveAnswer = resolve;
				}).then((result) => {
					if (result && !Array.isArray(result) && Object.keys(result).sort().join(",") === "ok,status" && result.ok === true && result.status === "LOGGED_OUT") return freeze$1({
						ok: true,
						status: "LOGGED_OUT"
					});
					return unconfirmed(result?.ok === false && ["UNAUTHORIZED", "UNAVAILABLE"].includes(result.error_code) ? result.error_code : "OUTCOME_UNKNOWN");
				}).catch(() => unconfirmed("OUTCOME_UNKNOWN")).then((result) => {
					logoutResult = result;
					return result;
				}).finally(() => {
					if (logoutFlight === flight) logoutFlight = null;
				});
				logoutFlight = flight;
				try {
					resolveAnswer(typeof authority?.logout === "function" ? authority.logout(current ? { session_token: current.session_token } : {}) : unconfirmed("UNAVAILABLE"));
				} catch {
					resolveAnswer(unconfirmed("OUTCOME_UNKNOWN"));
				}
				return flight;
			}
			async function prepareApproval(proposal, { signal, memoryCapture, captureMetadata, recordSummary } = {}) {
				const current = ownerSession();
				validateContract("OperationProposal", proposal);
				const operation = copy(proposal);
				let memoryDraft = null;
				let forgetDraft = null;
				let metadata = null;
				if (operation.action_type === "memory.save") {
					try {
						validateCaptureReview(operation.canonical_parameters, memoryCapture);
					} catch {
						fail("TARGET_MISMATCH", "ui:memory-capture-review-missing-or-mismatched");
					}
					memoryDraft = copy(memoryCapture, "memory-capture-draft");
					if (captureMetadata !== void 0) try {
						metadata = validateCaptureMetadata(captureMetadata);
					} catch {
						fail("TARGET_MISMATCH", "ui:fixed-capture-metadata-required");
					}
				} else if (operation.action_type === "memory.forget") try {
					forgetDraft = validateForgetReview(operation, recordSummary);
				} catch {
					fail("TARGET_MISMATCH", "ui:forget-record-review-missing-or-mismatched");
				}
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
				const presentation = freeze$1({
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
					})),
					memory_review: memoryDraft ? {
						statement: memoryDraft.statement,
						attributed_to: memoryDraft.attributed_to,
						capture_sha256: operation.canonical_parameters.capture_sha256
					} : null,
					capture_metadata: metadata,
					forget_review: forgetDraft ? {
						...forgetDraft,
						canonical_sha256: operation.canonical_parameters.canonical_sha256
					} : null
				});
				presentations.set(presentation, {
					operation,
					digest,
					proofTemplate,
					request,
					owner_id: current.owner_id,
					session_token: current.session_token,
					public_key: answer.public_key ? copy(answer.public_key) : void 0,
					memoryDraft,
					forgetDraft
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
				if (record.operation.action_type === "memory.save") try {
					validateCaptureReview(record.operation.canonical_parameters, record.memoryDraft);
				} catch {
					fail("TARGET_MISMATCH", "ui:memory-capture-review-missing-or-mismatched");
				}
				else if (record.operation.action_type === "memory.forget") try {
					validateForgetReview(record.operation, record.forgetDraft);
				} catch {
					fail("TARGET_MISMATCH", "ui:forget-record-review-missing-or-mismatched");
				}
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
					return freeze$1({
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
						return freeze$1({ status: "DENIED" });
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
				logout,
				owner() {
					return session ? freeze$1({
						owner_id: session.owner_id,
						expiry: session.expiry
					}) : null;
				}
			});
		}
		//#endregion
		//#region lib/types/adapters/passkey.mjs
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
		//#region lib/types/adapters/forget-result.mjs
		const DIGEST = /^sha256:[a-f0-9]{64}$/, HEX = /^[a-f0-9]{64}$/;
		const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
		const FIELDS = [
			"phase",
			"operation",
			"record_summary",
			"operation_digest",
			"approval",
			"forget",
			"forgotten",
			"result",
			"receipt",
			"receipt_digest",
			"authority_settlement",
			"reconciliation_required",
			"error_code",
			"recovery_status",
			"recovery_operation_id",
			"recovery_operation_digest"
		];
		const SUMMARY = [
			"record_id",
			"revision",
			"statement",
			"attributed_to"
		];
		const REVIEW = [...SUMMARY, "canonical_sha256"];
		const RESULT = [
			"record_id",
			"state",
			"canonical_payload_retained",
			"physical_media_erasure",
			"authority_approval_history_erased",
			"backups_erased",
			"wal_erased",
			"grants_authority"
		];
		const RECEIPT = [
			"version",
			"kind",
			"operation_id",
			"operation_digest",
			"grant_id",
			"request_id",
			"request_digest",
			"owner_subject",
			"action_type",
			"status",
			"result_digest",
			"result"
		];
		const ERRORS = [
			"UNAVAILABLE",
			"INVALID",
			"UNAUTHORIZED",
			"STALE",
			"REVOKED",
			"REPLAYED",
			"EXPIRED",
			"TARGET_MISMATCH",
			"SCOPE_MISMATCH",
			"CANCELLED",
			"OUTCOME_UNKNOWN",
			"RECONCILIATION_REQUIRED"
		];
		const fault = (code, reason) => {
			throw Object.assign(new TypeError(reason), {
				code,
				error_code: code
			});
		};
		const requireValue = (condition, reason = "ui:invalid-forget-workflow-snapshot", code = "INVALID") => {
			if (!condition) fault(code, reason);
		};
		function closed$2(value, fields) {
			requireValue(value && [Object.prototype, null].includes(Object.getPrototypeOf(value)));
			const keys = Reflect.ownKeys(value);
			requireValue(keys.length === fields.length && keys.every((key) => typeof key === "string" && fields.includes(key)));
			for (const key of keys) {
				const descriptor = Object.getOwnPropertyDescriptor(value, key);
				requireValue(descriptor?.enumerable === true && Object.hasOwn(descriptor, "value"));
			}
			return value;
		}
		function immutable$1(value) {
			if (value && typeof value === "object") {
				for (const child of Object.values(value)) immutable$1(child);
				Object.freeze(value);
			}
			return value;
		}
		function copied(value, contracts) {
			requireValue(typeof contracts?.canonicalJson === "function" && typeof contracts?.parseStrictJson === "function", "ui:forget-contract-helper-unavailable", "UNAVAILABLE");
			try {
				return contracts.parseStrictJson(contracts.canonicalJson(value), {
					maxBytes: 65536,
					maxDepth: 32
				});
			} catch {
				fault("INVALID", "ui:invalid-forget-workflow-json");
			}
		}
		const text = (value, max) => typeof value === "string" && value.length > 0 && new TextEncoder().encode(value).length <= max;
		const digestValue = (value) => typeof value === "string" && DIGEST.test(value);
		function logicalResult(value) {
			closed$2(value, RESULT);
			requireValue(text(value.record_id, 1024) && value.state === "tombstoned" && value.canonical_payload_retained === true && value.physical_media_erasure === false && value.authority_approval_history_erased === false && value.backups_erased === false && value.wal_erased === false && value.grants_authority === false);
		}
		function receiptShape(value) {
			closed$2(value, RECEIPT);
			requireValue(value.version === 1 && value.kind === "prime-memory-effect/v1" && text(value.operation_id, 1024) && digestValue(value.operation_digest) && typeof value.grant_id === "string" && /^grant:[a-f0-9]{64}$/.test(value.grant_id) && typeof value.request_id === "string" && UUID.test(value.request_id) && digestValue(value.request_digest) && typeof value.owner_subject === "string" && /^aukora:1:[a-f0-9]{64}$/.test(value.owner_subject) && value.action_type === "memory.forget" && value.status === "applied" && digestValue(value.result_digest));
			logicalResult(value.result);
		}
		/** Detached exact current 16-field bridge snapshot; no cryptographic authority claim. */
		function validateForgetWorkflowSnapshot(value, contracts) {
			closed$2(value, FIELDS);
			const result = copied(value, contracts);
			requireValue([
				"idle",
				"proposal_pending",
				"proposed",
				"approval_pending",
				"forget_pending",
				"forgotten",
				"refused",
				"outcome_unknown",
				"unavailable"
			].includes(result.phase) && [
				"not_requested",
				"pending",
				"approved",
				"refused",
				"unknown"
			].includes(result.approval) && [
				"not_attempted",
				"pending",
				"forgotten",
				"refused",
				"unknown"
			].includes(result.forget) && [
				true,
				false,
				null
			].includes(result.forgotten) && typeof result.reconciliation_required === "boolean" && [
				null,
				"completed",
				"pending"
			].includes(result.authority_settlement) && (result.error_code === null || ERRORS.includes(result.error_code)) && [
				"not_requested",
				"pending",
				"idle",
				"known_unsent",
				"saved",
				"forgotten",
				"unknown",
				"refused"
			].includes(result.recovery_status));
			requireValue(result.operation_digest === null || digestValue(result.operation_digest));
			requireValue(result.receipt_digest === null || digestValue(result.receipt_digest));
			requireValue(result.recovery_operation_id === null || text(result.recovery_operation_id, 1024));
			requireValue(result.recovery_operation_digest === null || digestValue(result.recovery_operation_digest));
			requireValue(result.recovery_operation_id === null === (result.recovery_operation_digest === null));
			requireValue(!["not_requested", "idle"].includes(result.recovery_status) || result.recovery_operation_id === null);
			requireValue(![
				"known_unsent",
				"saved",
				"forgotten",
				"unknown"
			].includes(result.recovery_status) || result.recovery_operation_id !== null);
			requireValue(result.operation === null === (result.record_summary === null) && result.operation === null === (result.operation_digest === null));
			if (result.operation !== null) {
				requireValue(typeof contracts?.validateContract === "function", "ui:forget-contract-helper-unavailable", "UNAVAILABLE");
				try {
					contracts.validateContract("OperationProposal", result.operation);
					validateForgetReview(result.operation, result.record_summary);
				} catch {
					fault("INVALID", "ui:invalid-forget-workflow-operation");
				}
			}
			requireValue(result.result === null === (result.receipt === null));
			if (result.result !== null) logicalResult(result.result);
			if (result.receipt !== null) receiptShape(result.receipt);
			requireValue(result.receipt_digest === null || result.receipt !== null);
			return immutable$1(result);
		}
		function reviewed(presentation, contracts) {
			requireValue(presentation && [Object.prototype, null].includes(Object.getPrototypeOf(presentation)), "ui:forget-review-required", "TARGET_MISMATCH");
			const selected = {};
			for (const name of [
				"operation",
				"canonical_operation",
				"operation_digest",
				"forget_review"
			]) {
				const descriptor = Object.getOwnPropertyDescriptor(presentation, name);
				requireValue(descriptor?.enumerable === true && Object.hasOwn(descriptor, "value"), "ui:forget-review-required", "TARGET_MISMATCH");
				selected[name] = descriptor.value;
			}
			const view = copied(selected, contracts);
			closed$2(view.forget_review, REVIEW);
			const summary = Object.fromEntries(SUMMARY.map((name) => [name, view.forget_review[name]]));
			try {
				contracts.validateContract("OperationProposal", view.operation);
				validateForgetReview(view.operation, summary);
			} catch {
				fault("TARGET_MISMATCH", "ui:forget-review-mismatch");
			}
			requireValue(view.canonical_operation === contracts.canonicalJson(view.operation) && digestValue(view.operation_digest) && view.forget_review.canonical_sha256 === view.operation.canonical_parameters.canonical_sha256, "ui:forget-review-mismatch", "TARGET_MISMATCH");
			return immutable$1({
				...view,
				summary
			});
		}
		async function digest(domain, value, contracts) {
			requireValue(typeof globalThis.crypto?.subtle?.digest === "function", "ui:forget-digest-unavailable", "UNAVAILABLE");
			let result;
			try {
				result = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(domain + "\0" + contracts.canonicalJson(value)));
			} catch {
				fault("UNAVAILABLE", "ui:forget-digest-unavailable");
			}
			return "sha256:" + Array.from(new Uint8Array(result), (byte) => byte.toString(16).padStart(2, "0")).join("");
		}
		/** The caller must fence its captured owner/revision again after this async check. */
		async function validateForgetWorkflowResult(value, { presentation, approved, proofNonce, contracts } = {}) {
			const result = validateForgetWorkflowSnapshot(value, contracts), view = reviewed(presentation, contracts);
			requireValue(typeof contracts.operationDigest === "function", "ui:forget-contract-helper-unavailable", "UNAVAILABLE");
			let originalDigest;
			try {
				originalDigest = await contracts.operationDigest(view.operation);
			} catch {
				fault("TARGET_MISMATCH", "ui:forget-operation-digest-mismatch");
			}
			requireValue(originalDigest === view.operation_digest, "ui:forget-operation-digest-mismatch", "TARGET_MISMATCH");
			if (result.operation !== null) requireValue(contracts.canonicalJson(result.operation) === view.canonical_operation && result.operation_digest === view.operation_digest && contracts.canonicalJson(result.record_summary) === contracts.canonicalJson(view.summary), "ui:forget-operation-changed", "TARGET_MISMATCH");
			if ([
				"proposal_pending",
				"approval_pending",
				"forget_pending"
			].includes(result.phase) || result.approval === "pending" || result.forget === "pending" || result.recovery_status === "pending") fault("OUTCOME_UNKNOWN", "ui:forget-action-still-pending");
			if (!(result.forgotten === true || result.forget === "forgotten" || result.phase === "forgotten" || result.result !== null)) {
				requireValue(result.authority_settlement === null && result.receipt_digest === null && result.forgotten !== true, "ui:forget-result-contradictory", "OUTCOME_UNKNOWN");
				requireValue(!([result.approval, result.forget].includes("unknown") || result.phase === "outcome_unknown" || result.approval === "approved" || result.forgotten === null || ["OUTCOME_UNKNOWN", "RECONCILIATION_REQUIRED"].includes(result.error_code)) || result.reconciliation_required, "ui:forget-result-contradictory", "OUTCOME_UNKNOWN");
				return result;
			}
			requireValue(approved === true && typeof proofNonce === "string" && HEX.test(proofNonce) && result.phase === "forgotten" && result.approval === "approved" && result.forget === "forgotten" && result.forgotten === true && result.result !== null && result.receipt !== null, "ui:forget-result-not-bound-to-approval", "TARGET_MISMATCH");
			if (result.operation === null) requireValue(result.recovery_status === "forgotten" && result.recovery_operation_id === view.operation.operation_id && result.recovery_operation_digest === view.operation_digest, "ui:forget-recovery-not-bound-to-review", "TARGET_MISMATCH");
			const receipt = result.receipt, operation = view.operation;
			requireValue(result.result.record_id === view.forget_review.record_id && receipt.operation_id === operation.operation_id && receipt.operation_digest === view.operation_digest && receipt.grant_id === "grant:" + proofNonce && receipt.owner_subject === operation.target_identity.owner_subject && contracts.canonicalJson(receipt.result) === contracts.canonicalJson(result.result), "ui:forget-receipt-mismatch", "TARGET_MISMATCH");
			requireValue(result.authority_settlement === "completed" && result.reconciliation_required === false && digestValue(result.receipt_digest) || result.authority_settlement === "pending" && result.reconciliation_required === true, "ui:forget-settlement-mismatch", "OUTCOME_UNKNOWN");
			requireValue(result.authority_settlement !== "completed" || !["OUTCOME_UNKNOWN", "RECONCILIATION_REQUIRED"].includes(result.error_code), "ui:forget-result-uncertain", "OUTCOME_UNKNOWN");
			requireValue(receipt.result_digest === await digest("aukora-prime.memory-result.v1", result.result, contracts), "ui:forget-result-digest-mismatch", "TARGET_MISMATCH");
			const request = {
				version: 1,
				action_type: "memory.forget",
				owner_subject: operation.target_identity.owner_subject,
				operation_id: operation.operation_id,
				operation_digest: view.operation_digest,
				parameters: operation.canonical_parameters
			};
			requireValue(receipt.request_digest === await digest("aukora-prime.memory.effect.v1", request, contracts), "ui:forget-request-digest-mismatch", "TARGET_MISMATCH");
			if (result.receipt_digest !== null) requireValue(result.receipt_digest === await digest("aukora-prime.memory-receipt.v1", receipt, contracts), "ui:forget-receipt-digest-mismatch", "TARGET_MISMATCH");
			return result;
		}
		/** Content-free terminal facts only; this never presents a recovered receipt. */
		function validateCancelledForgetWorkflow(value, contracts) {
			let result;
			try {
				result = validateForgetWorkflowSnapshot(value, contracts);
			} catch {
				fault("OUTCOME_UNKNOWN", "ui:invalid-cancelled-forget-result");
			}
			const cleared = ["idle", "unavailable"].includes(result.phase) && [
				"operation",
				"record_summary",
				"operation_digest",
				"result",
				"receipt",
				"receipt_digest",
				"recovery_operation_id",
				"recovery_operation_digest"
			].every((name) => result[name] === null) && result.recovery_status === "not_requested" && [null, "UNAVAILABLE"].includes(result.error_code) && result.reconciliation_required === false;
			const unsent = result.approval === "not_requested" && result.forget === "not_attempted" && result.forgotten === false && result.authority_settlement === null;
			const completed = result.approval === "approved" && result.forget === "forgotten" && result.forgotten === true && result.authority_settlement === "completed";
			requireValue(cleared && (unsent || completed), "ui:cancelled-forget-needs-reconciliation", "OUTCOME_UNKNOWN");
			return result;
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
				"declineApproval",
				"logout"
			].map((method) => [method, async (input, { signal } = {}) => {
				if (method === "logout" && (typeof input?.session_token !== "string" || !input.session_token)) return {
					ok: false,
					error_code: "UNAUTHORIZED",
					reason: "ui:no-known-server-session"
				};
				if (typeof contracts?.parseStrictJson !== "function" || typeof contracts?.canonicalJson !== "function") throw new PrimeTransportError("UNAVAILABLE", "ui:strict-json-helper-unavailable");
				let body;
				try {
					body = contracts.canonicalJson(input);
				} catch {
					throw new PrimeTransportError("INVALID", "ui:invalid-request-json");
				}
				const response = await fetcher("/api/prime/authority/" + (method === "logout" ? "logoutSession" : method), {
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
					if (method === "approvalComplete" || method === "declineApproval" || method === "logout") throw new PrimeTransportError("OUTCOME_UNKNOWN", "ui:decision-response-invalid-needs-reconciliation");
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
			let binding, transport, pending, timer, revision = 0, operation, ownerKind, memoryCapture, captureMetadata, recordSummary;
			let logoutFlight = null;
			let approvalAction = null, forgetAction = null, approvalFlight = null, approvalActionBlocked = false;
			const configuredAction = () => operation?.action_type === "memory.forget" ? forgetAction : approvalAction;
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
				authority_available: false,
				approval_action_available: false,
				approval_action_pending: false,
				approval_action_result: null,
				forget_action_result: null,
				logout_status: "idle",
				logout_error_code: null
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
				const flight = {
					abort,
					promise: null
				};
				pending = flight;
				const promise = Promise.resolve().then(async () => {
					try {
						if (current !== revision || abort.signal.aborted) return null;
						const result = await work(abort.signal);
						if (current === revision) finish(result);
						return result;
					} catch (error) {
						if (current === revision) fail(error);
						return null;
					} finally {
						if (pending === flight) {
							pending = void 0;
							if (current === revision) checkExpiry();
						}
					}
				});
				flight.promise = promise;
				notify({
					phase,
					error_code: null,
					reason: phase === "login_pending" ? "Waiting for the authenticator and host confirmation." : phase === "review_pending" ? "Requesting a fresh review challenge." : "Waiting for host confirmation."
				});
				return promise;
			}
			const cancelApprovalAction = () => {
				approvalFlight?.abort.abort();
			};
			function revokeTransport(selected, patch, showReason) {
				if (logoutFlight) {
					logoutFlight.revision = revision;
					logoutFlight.showReason = showReason;
					notify({
						...patch,
						logout_status: "pending",
						logout_error_code: null
					});
					return logoutFlight.promise;
				}
				let resolveAnswer;
				const answer = new Promise((resolve) => {
					resolveAnswer = resolve;
				});
				const flight = {
					revision,
					showReason,
					promise: null
				};
				logoutFlight = flight;
				flight.promise = answer.catch(() => ({
					ok: false,
					error_code: "OUTCOME_UNKNOWN"
				})).then((result) => {
					const confirmed = result?.ok === true && result.status === "LOGGED_OUT" && Object.keys(result).sort().join(",") === "ok,status";
					const code = confirmed ? null : ["UNAVAILABLE", "UNAUTHORIZED"].includes(result?.error_code) ? result.error_code : "OUTCOME_UNKNOWN";
					const status = confirmed ? "confirmed" : code === "UNAVAILABLE" ? "unavailable" : code === "UNAUTHORIZED" ? "refused" : "unknown";
					const outcome = confirmed ? Object.freeze({
						ok: true,
						status: "LOGGED_OUT"
					}) : Object.freeze({
						ok: false,
						error_code: code,
						reason: "ui:server-logout-not-confirmed"
					});
					if (logoutFlight === flight) logoutFlight = null;
					if (flight.revision === revision) notify({
						logout_status: status,
						logout_error_code: code,
						...flight.showReason ? { reason: confirmed ? "Local access was removed. The host confirmed server logout." : "Local access was removed. Server logout is unconfirmed; no retry was sent." } : {}
					});
					return outcome;
				});
				notify({
					...patch,
					logout_status: "pending",
					logout_error_code: null
				});
				try {
					resolveAnswer(selected ? selected.logout() : {
						ok: false,
						error_code: "UNAVAILABLE"
					});
				} catch {
					resolveAnswer({
						ok: false,
						error_code: "OUTCOME_UNKNOWN"
					});
				}
				return flight.promise;
			}
			function workflowSnapshot(value, flight) {
				const result = immutable(JSON.parse(flight.contracts.canonicalJson(value)));
				if (!result || Array.isArray(result) || Object.keys(result).sort().join(",") !== [
					"phase",
					"operation",
					"memory_capture",
					"operation_digest",
					"approval",
					"save",
					"saved",
					"record",
					"receipt",
					"receipt_digest",
					"citation",
					"citation_status",
					"index",
					"authority_settlement",
					"reconciliation_required",
					"error_code",
					"read_error_code"
				].sort().join(",") || ![
					"idle",
					"proposal_pending",
					"proposed",
					"approval_pending",
					"save_pending",
					"saved",
					"refused",
					"outcome_unknown",
					"unavailable"
				].includes(result.phase) || ![
					"not_requested",
					"pending",
					"approved",
					"refused",
					"unknown"
				].includes(result.approval) || ![
					"not_attempted",
					"pending",
					"saved",
					"refused",
					"unknown"
				].includes(result.save) || ![
					true,
					false,
					null
				].includes(result.saved) || typeof result.reconciliation_required !== "boolean" || !result.index || Object.keys(result.index).sort().join(",") !== "indexed,searchable,status" || ![
					"unconfirmed",
					"pending",
					"failed",
					"indexed",
					"searchable"
				].includes(result.index.status) || ![
					true,
					false,
					null
				].includes(result.index.indexed) || ![
					true,
					false,
					null
				].includes(result.index.searchable) || ![
					"not_requested",
					"pending",
					"verified",
					"unverified",
					"missing",
					"unavailable"
				].includes(result.citation_status) || ![
					null,
					"completed",
					"pending"
				].includes(result.authority_settlement) || [result.error_code, result.read_error_code].some((code) => code !== null && (typeof code !== "string" || code.length > 128)) || result.receipt_digest !== null && !/^sha256:[a-f0-9]{64}$/.test(result.receipt_digest)) throw new PrimeTransportError("INVALID", "ui:invalid-memory-workflow-result");
				return result;
			}
			function cancelledWorkflowResult(value, flight) {
				let result;
				try {
					result = workflowSnapshot(value, flight);
				} catch {
					throw new PrimeTransportError("OUTCOME_UNKNOWN", "ui:invalid-cancelled-memory-action-result");
				}
				const cleared = ["idle", "unavailable"].includes(result.phase) && [
					"operation",
					"memory_capture",
					"operation_digest",
					"record",
					"receipt",
					"receipt_digest",
					"citation"
				].every((field) => result[field] === null) && result.citation_status === "not_requested" && result.read_error_code === null && result.index.status === "unconfirmed" && result.index.indexed === null && result.index.searchable === null && [null, "UNAVAILABLE"].includes(result.error_code) && result.reconciliation_required === false;
				const unsent = result.save === "not_attempted" && result.saved === false && result.approval === "not_requested" && result.authority_settlement === null;
				const completed = result.save === "saved" && result.saved === true && result.approval === "approved" && result.authority_settlement === "completed";
				if (!cleared || !unsent && !completed) throw new PrimeTransportError("OUTCOME_UNKNOWN", "ui:cancelled-memory-action-needs-reconciliation");
			}
			function workflowResult(value, flight) {
				const result = workflowSnapshot(value, flight), contracts = flight.contracts;
				if (result.operation) {
					if (contracts.canonicalJson(result.operation) !== flight.presentation.canonical_operation || result.operation_digest !== flight.presentation.operation_digest) throw new PrimeTransportError("TARGET_MISMATCH", "ui:memory-workflow-operation-changed");
					validateCaptureReview(result.operation.canonical_parameters, result.memory_capture);
				}
				if (result.saved === true || result.save === "saved") {
					contracts.validateContract("MemoryRecord", result.record);
					const original = JSON.parse(result.record.canonical_bytes);
					const view = flight.presentation, receipt = result.receipt;
					if (!flight.approved || result.saved !== true || result.save !== "saved" || result.approval !== "approved" || !result.operation || result.record.storage_status !== "saved" || result.record.owner_subject !== view.operation.target_identity.owner_subject || result.record.task_id !== view.operation.task_id || original.statement !== view.memory_review.statement || original.attributedTo !== view.memory_review.attributed_to || receipt?.status !== "applied" || receipt.operation_id !== view.operation.operation_id || receipt.operation_digest !== view.operation_digest || receipt.grant_id !== "grant:" + flight.proofNonce || contracts.canonicalJson(receipt.result) !== contracts.canonicalJson(result.record) || !["completed", "pending"].includes(result.authority_settlement) || result.authority_settlement === "completed" && result.reconciliation_required || result.authority_settlement === "pending" && !result.reconciliation_required) throw new PrimeTransportError("TARGET_MISMATCH", "ui:memory-workflow-receipt-mismatch");
				}
				return result;
			}
			const api = {
				getSnapshot: () => state,
				subscribe(listener) {
					listeners.add(listener);
					return () => listeners.delete(listener);
				},
				connect(next) {
					cancelApprovalAction();
					approvalAction = null;
					forgetAction = null;
					const previous = transport;
					const hadPending = !!pending;
					++revision;
					pending?.abort.abort();
					pending = void 0;
					transport = void 0;
					stopTimer();
					operation = void 0;
					ownerKind = void 0;
					memoryCapture = void 0;
					captureMetadata = void 0;
					recordSummary = void 0;
					if (previous && (previous.owner() || hadPending || logoutFlight)) revokeTransport(previous, {
						owner: null,
						presentation: null,
						operation_available: false,
						approval_action_pending: false,
						approval_action_result: null,
						forget_action_result: null
					}, false);
					else if (previous) previous.logout();
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
							approval_action_available: false,
							approval_action_pending: false,
							approval_action_result: null,
							forget_action_result: null,
							...!logoutFlight ? {
								logout_status: "idle",
								logout_error_code: null
							} : {},
							expired: false,
							error_code: available ? null : "UNAVAILABLE",
							reason: available ? "Sign in with an existing credential. The host must confirm your identity." : "Owner access is unavailable until the host supplies its capability status."
						});
						if (next.operation) api.setOperation(next.operation, {
							memoryCapture: next.memoryCapture,
							captureMetadata: next.captureMetadata,
							recordSummary: next.recordSummary
						});
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
				setOperation(proposal, options = {}) {
					if (pending || approvalFlight || approvalActionBlocked || state.phase === "outcome_unknown") throw new PrimeTransportError("RECONCILIATION_REQUIRED", "An authority request is pending or needs reconciliation.");
					try {
						binding.contracts.validateContract("OperationProposal", proposal);
						const proposed = immutable(JSON.parse(binding.contracts.canonicalJson(proposal)));
						if (proposed.action_type === "memory.save") {
							try {
								validateCaptureReview(proposed.canonical_parameters, options.memoryCapture);
							} catch {
								throw new PrimeTransportError("TARGET_MISMATCH", "ui:memory-capture-review-missing-or-mismatched");
							}
							if (options.captureMetadata !== void 0) validateCaptureMetadata(options.captureMetadata);
						} else if (proposed.action_type === "memory.forget") try {
							validateForgetReview(proposed, options.recordSummary);
						} catch {
							throw new PrimeTransportError("TARGET_MISMATCH", "ui:forget-record-review-missing-or-mismatched");
						}
						memoryCapture = proposed.action_type === "memory.save" ? immutable(JSON.parse(binding.contracts.canonicalJson(options.memoryCapture))) : void 0;
						captureMetadata = proposed.action_type === "memory.save" && options.captureMetadata !== void 0 ? validateCaptureMetadata(options.captureMetadata) : void 0;
						recordSummary = proposed.action_type === "memory.forget" ? validateForgetReview(proposed, options.recordSummary) : void 0;
						operation = proposed;
					} catch (error) {
						operation = void 0;
						memoryCapture = void 0;
						captureMetadata = void 0;
						recordSummary = void 0;
						notify({
							operation_available: false,
							presentation: null
						});
						fail(error);
						throw error;
					}
					notify({
						operation_available: true,
						presentation: null,
						expired: false,
						approval_action_result: null,
						forget_action_result: null,
						approval_action_available: !!configuredAction() && !approvalActionBlocked,
						phase: state.owner ? "authenticated" : state.phase,
						reason: "The host supplied an operation. Request a fresh review before deciding."
					});
					checkExpiry();
				},
				login(kind = "passkey") {
					if (logoutFlight) {
						notify({ reason: "Local access was removed. Waiting for the server logout response." });
						return Promise.resolve(null);
					}
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
							reason: "The host confirmed this owner session.",
							logout_status: "idle",
							logout_error_code: null
						});
					});
				},
				prepare() {
					if (approvalFlight || approvalActionBlocked) {
						fail(new PrimeTransportError("RECONCILIATION_REQUIRED", "A memory action is pending or needs reconciliation."));
						return Promise.resolve(null);
					}
					if (!transport || !state.authority_available || !operation) {
						fail(new PrimeTransportError("UNAVAILABLE", "An available authority and a host operation are required."));
						return Promise.resolve(null);
					}
					return action("review_pending", (signal) => transport.prepareApproval(operation, {
						signal,
						memoryCapture,
						captureMetadata,
						recordSummary
					}), (presentation) => {
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
						if (approvalFlight?.revision === revision && approvalFlight.presentation === presentation) {
							approvalFlight.approved = true;
							approvalFlight.proofNonce = result.approval_proof.nonce;
						}
						notify({
							phase: "approved",
							error_code: null,
							reason: result.status === "APPROVED" ? "The host confirmed approval of this exact operation. Execution has not been confirmed." : "The result is unknown."
						});
					});
				},
				setApprovalAction(handler) {
					if (handler !== null && typeof handler !== "function") throw new PrimeTransportError("INVALID", "ui:invalid-approval-action");
					if (approvalFlight && handler !== null) throw new PrimeTransportError("RECONCILIATION_REQUIRED", "A memory action is still pending.");
					if (handler === null && approvalFlight) api.logout();
					else if (handler === null) cancelApprovalAction();
					approvalAction = handler;
					notify({ approval_action_available: !!configuredAction() && !approvalActionBlocked });
				},
				setForgetAction(handler) {
					if (handler !== null && typeof handler !== "function") throw new PrimeTransportError("INVALID", "ui:invalid-forget-action");
					if (approvalFlight && handler !== null) throw new PrimeTransportError("RECONCILIATION_REQUIRED", "A memory action is still pending.");
					if (handler === null && approvalFlight) api.logout();
					else if (handler === null) cancelApprovalAction();
					forgetAction = handler;
					notify({ approval_action_available: !!configuredAction() && !approvalActionBlocked });
				},
				submitApproval() {
					if (approvalActionBlocked) {
						fail(new PrimeTransportError("RECONCILIATION_REQUIRED", "The memory action needs reconciliation; do not retry."));
						return Promise.resolve(null);
					}
					if (approvalFlight) {
						if (approvalFlight.revision === revision && approvalFlight.presentation === state.presentation) return approvalFlight.promise;
						fail(new PrimeTransportError("RECONCILIATION_REQUIRED", "A previous memory action is unresolved."));
						return Promise.resolve(null);
					}
					if (state.phase !== "review_ready" || state.expired || !state.authority_available) return Promise.resolve(null);
					const forgetting = state.presentation.operation.action_type === "memory.forget";
					if (!forgetting && state.presentation.operation.action_type !== "memory.save") return api.approve();
					const handler = configuredAction();
					if (!handler) {
						fail(new PrimeTransportError("UNAVAILABLE", forgetting ? "ui:forget-approval-action-unavailable" : "ui:memory-approval-action-unavailable"));
						return Promise.resolve(null);
					}
					const flight = {
						revision,
						presentation: state.presentation,
						owner: state.owner,
						handler,
						contracts: binding.contracts,
						started: false,
						approved: false,
						abort: new AbortController(),
						promise: null
					};
					approvalFlight = flight;
					flight.promise = Promise.resolve().then(async () => {
						try {
							if (revision !== flight.revision || state.owner !== flight.owner || flight.abort.signal.aborted) return null;
							flight.started = true;
							const value = await flight.handler(flight.presentation, { signal: flight.abort.signal });
							if (revision !== flight.revision || state.owner !== flight.owner || flight.abort.signal.aborted) {
								if (forgetting) validateCancelledForgetWorkflow(value, flight.contracts);
								else cancelledWorkflowResult(value, flight);
								return null;
							}
							const result = forgetting ? await validateForgetWorkflowResult(value, flight) : workflowResult(value, flight);
							if (revision !== flight.revision || state.owner !== flight.owner || flight.abort.signal.aborted) {
								if (!(forgetting && result.forgotten === true && result.authority_settlement === "completed" && !result.reconciliation_required)) if (forgetting) validateCancelledForgetWorkflow(result, flight.contracts);
								else cancelledWorkflowResult(result, flight);
								return null;
							}
							const unresolved = result.reconciliation_required || (forgetting ? result.forget : result.save) === "unknown" || result.phase === "outcome_unknown";
							if (unresolved) approvalActionBlocked = true;
							const completed = forgetting ? result.forget === "forgotten" : result.save === "saved";
							notify({
								...forgetting ? {
									forget_action_result: result,
									approval_action_result: null
								} : {
									approval_action_result: result,
									forget_action_result: null
								},
								approval_action_available: !!configuredAction() && !approvalActionBlocked,
								phase: unresolved ? "outcome_unknown" : completed ? "approved" : result.phase === "refused" ? "refused" : state.phase,
								error_code: unresolved ? "RECONCILIATION_REQUIRED" : result.error_code,
								reason: forgetting ? completed ? unresolved ? "The host confirmed logical forget; authority settlement needs reconciliation." : "The host confirmed logical forget with its receipt. Canonical payloads and external copies remain retained." : unresolved ? "The host has not confirmed the forget outcome. Reconciliation is required; do not retry." : "The host workflow did not confirm logical forget." : result.save === "saved" ? unresolved ? "The host workflow confirmed the save; authority settlement needs reconciliation." : "The host workflow confirmed the save with its receipt. Index and citation status are shown separately." : unresolved ? "The host has not confirmed the memory save outcome. Reconciliation is required; do not retry." : "The host workflow did not confirm a memory save. Approval alone does not confirm storage."
							});
							return result;
						} catch (error) {
							if (flight.approved || flight.started && (revision !== flight.revision || state.owner !== flight.owner || flight.abort.signal.aborted) || ["OUTCOME_UNKNOWN", "RECONCILIATION_REQUIRED"].includes(error?.code)) approvalActionBlocked = true;
							if (revision === flight.revision && state.owner === flight.owner) {
								fail(approvalActionBlocked ? new PrimeTransportError("OUTCOME_UNKNOWN", "ui:memory-action-outcome-unknown") : error);
								notify({ approval_action_available: !!configuredAction() && !approvalActionBlocked });
							}
							return null;
						} finally {
							if (approvalFlight === flight) approvalFlight = null;
							notify({
								approval_action_available: !!configuredAction() && !approvalActionBlocked,
								...revision === flight.revision ? { approval_action_pending: false } : {}
							});
						}
					});
					notify({
						approval_action_pending: true,
						approval_action_result: null,
						forget_action_result: null
					});
					return flight.promise;
				},
				decline() {
					if (approvalFlight || approvalActionBlocked) {
						fail(new PrimeTransportError("RECONCILIATION_REQUIRED", "A memory action is pending or needs reconciliation."));
						return Promise.resolve(null);
					}
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
					if (logoutFlight?.revision === revision) return logoutFlight.promise;
					cancelApprovalAction();
					++revision;
					pending?.abort.abort();
					pending = void 0;
					stopTimer();
					ownerKind = void 0;
					return revokeTransport(transport, {
						phase: transport && state.authority_available ? "logged_out" : "unavailable",
						owner: null,
						presentation: null,
						expired: false,
						approval_action_pending: false,
						approval_action_result: null,
						forget_action_result: null,
						approval_action_available: !!configuredAction() && !approvalActionBlocked,
						reason: "Local access was removed. Waiting for the server logout response.",
						error_code: null
					}, true);
				},
				disconnect() {
					cancelApprovalAction();
					approvalAction = null;
					forgetAction = null;
					const previous = transport;
					++revision;
					pending?.abort.abort();
					pending = void 0;
					transport = void 0;
					ownerKind = void 0;
					operation = void 0;
					memoryCapture = void 0;
					captureMetadata = void 0;
					recordSummary = void 0;
					stopTimer();
					return revokeTransport(previous, {
						phase: "unavailable",
						owner: null,
						presentation: null,
						operation_available: false,
						expired: false,
						error_code: "UNAVAILABLE",
						reason: "Authority transport is unavailable.",
						authority_available: false,
						approval_action_available: false,
						approval_action_pending: false,
						approval_action_result: null,
						forget_action_result: null
					}, false);
				},
				dispose() {
					api.disconnect();
					listeners.clear();
				}
			};
			return Object.freeze(api);
		}
		//#endregion
		//#region lib/types/adapters/capture-presentation.mjs
		const FORMAT_CONTROL = /\p{Cf}/u;
		const LATIN = /\p{Script=Latin}/u;
		const GREEK = /\p{Script=Greek}/u;
		const CYRILLIC = /\p{Script=Cyrillic}/u;
		const TOKEN = /[\p{L}\p{M}\p{N}_]+/gu;
		const ASCII_LOOKALIKES = Object.freeze({
			"Α": "A",
			"Β": "B",
			"Ε": "E",
			"Ζ": "Z",
			"Η": "H",
			"Ι": "I",
			"Κ": "K",
			"Μ": "M",
			"Ν": "N",
			"Ο": "O",
			"Ρ": "P",
			"Τ": "T",
			"Υ": "Y",
			"Χ": "X",
			"ο": "o",
			"ρ": "p",
			"ν": "v",
			"А": "A",
			"В": "B",
			"Е": "E",
			"К": "K",
			"М": "M",
			"Н": "H",
			"О": "O",
			"Р": "P",
			"С": "C",
			"Т": "T",
			"Х": "X",
			"а": "a",
			"е": "e",
			"о": "o",
			"р": "p",
			"с": "c",
			"у": "y",
			"х": "x",
			"і": "i",
			"ј": "j",
			"ѕ": "s"
		});
		const LIMIT = 16;
		const codePoint = (character) => "U+" + character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
		const script = (character) => LATIN.test(character) ? "Latin" : GREEK.test(character) ? "Greek" : CYRILLIC.test(character) ? "Cyrillic" : null;
		const freeze = (value) => {
			for (const child of Object.values(value)) if (child && typeof child === "object") freeze(child);
			return Object.freeze(value);
		};
		/** UTF-16 indexes address the unchanged JavaScript string; code points make invisible characters reviewable. */
		function capturePresentationWarnings(statement) {
			if (typeof statement !== "string") throw new TypeError("memory:capture-presentation-invalid");
			const controls = [], lookalikes = [], mixed = [];
			let controlCount = 0, lookalikeCount = 0, mixedCount = 0, index = 0;
			for (const character of statement) {
				if (FORMAT_CONTROL.test(character)) {
					controlCount++;
					if (controls.length < LIMIT) controls.push({
						index,
						code_point: codePoint(character)
					});
				}
				if (Object.hasOwn(ASCII_LOOKALIKES, character)) {
					lookalikeCount++;
					if (lookalikes.length < LIMIT) lookalikes.push({
						index,
						code_point: codePoint(character),
						resembles: ASCII_LOOKALIKES[character],
						script: script(character)
					});
				}
				index += character.length;
			}
			for (const token of statement.matchAll(TOKEN)) {
				const scripts = [...new Set([...token[0]].map(script).filter(Boolean))];
				if (scripts.length < 2) continue;
				mixedCount++;
				if (mixed.length < LIMIT) mixed.push({
					index: token.index,
					length: token[0].length,
					scripts
				});
			}
			const warnings = [];
			if (controlCount) warnings.push({
				code: "format-controls",
				count: controlCount,
				examples: controls,
				text: "Text contains Unicode format controls that can change its presentation. Exact characters are preserved."
			});
			if (lookalikeCount) warnings.push({
				code: "ascii-lookalikes",
				count: lookalikeCount,
				examples: lookalikes,
				text: "Some Greek or Cyrillic letters may resemble Latin letters. This is a limited hint; exact characters are preserved."
			});
			if (mixedCount) warnings.push({
				code: "mixed-scripts",
				count: mixedCount,
				examples: mixed,
				text: "Some words mix Latin, Greek, or Cyrillic scripts. Script mixing can be legitimate; inspect the exact characters."
			});
			return freeze(warnings);
		}
		//#endregion
		//#region lib/types/client/MemoryCaptureHints.js
		const POLICY = Object.freeze([
			["Policy version", "1"],
			["Category", "fact"],
			["Confidence", "0.7"],
			["Sensitivity", "none"],
			["Privacy", "local"],
			["Scope", "owner"],
			["Links", "empty"],
			["Origin", "prime.capture/v1"],
			["Body override", "none (null)"],
			["Observed time", "exact selected source event time"],
			["Valid from", "source event calendar date"],
			["Evidence", "derived from the exact selected source event"],
			["Authority grants", "none"]
		]);
		function exampleText(example) {
			const position = `UTF-16 index ${example.index}`;
			if ("code_point" in example) return `${position}: ${example.code_point}${"resembles" in example ? `, ${example.script ?? "Unicode"} letter resembling ${example.resembles}` : ""}`;
			return `${position}, length ${example.length}: ${example.scripts.join(", ")}`;
		}
		function MemoryCaptureHints({ statement }) {
			const warnings = capturePresentationWarnings(statement);
			return (0, react_jsx_runtime.jsxs)("div", {
				"data-memory-capture-hints": true,
				children: [
					(0, react_jsx_runtime.jsx)("h4", { children: "Text review hints" }),
					(0, react_jsx_runtime.jsx)("p", { children: "Hints aid review and preserve the exact text. Examples use UTF-16 indexes and Unicode code points, with up to 16 examples per category. Greek and Cyrillic lookalike examples are limited, and script mixing can be legitimate." }),
					warnings.length === 0 && (0, react_jsx_runtime.jsx)("p", {
						"data-memory-no-presentation-hints": true,
						children: "These limited checks produced no hints. Review the exact statement above."
					}),
					warnings.map((warning) => (0, react_jsx_runtime.jsxs)("div", {
						"data-memory-unicode-hint": warning.code,
						children: [
							(0, react_jsx_runtime.jsx)("p", { children: warning.text }),
							(0, react_jsx_runtime.jsxs)("p", { children: ["Occurrences: ", warning.count] }),
							(0, react_jsx_runtime.jsx)("ul", { children: warning.examples.map((example, index) => (0, react_jsx_runtime.jsx)("li", { children: (0, react_jsx_runtime.jsx)("code", { children: exampleText(example) }) }, index)) })
						]
					}, warning.code)),
					(0, react_jsx_runtime.jsx)("h4", { children: "Fixed new-capture policy" }),
					(0, react_jsx_runtime.jsx)("p", { children: "This pilot uses the documented fixed policy for new captures." }),
					(0, react_jsx_runtime.jsx)("dl", {
						"data-memory-fixed-capture-policy": true,
						children: POLICY.map(([label, value]) => (0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: label }), (0, react_jsx_runtime.jsx)("dd", { children: value })] }, label))
					})
				]
			});
		}
		//#endregion
		//#region \0dsh-css:packages/client/aukora-prime-authority/src/client/OwnerSurface.module.css.mjs
		const css$1 = "._7wS6_G_surface[hidden]{display:none!important}._7wS6_G_surface{box-sizing:border-box;overscroll-behavior:contain;width:100%;min-width:0;max-width:46rem;height:100%;min-height:0;color:var(--aukora-text);background:0 0;flex-direction:column;gap:18px;margin:0 auto;padding:22px 20px 48px;display:flex;position:relative;overflow-y:auto}._7wS6_G_header{flex-direction:column;align-items:flex-start;gap:4px}._7wS6_G_header h1{margin:0;font-size:20px;font-weight:600;line-height:28px}._7wS6_G_header p{color:var(--aukora-text-secondary);margin:0}._7wS6_G_card{min-width:0;padding:16px}._7wS6_G_card h2{margin-top:0;font-size:16px;font-weight:600}._7wS6_G_card pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 var(--dsw-font-family-mono);margin:4px 0}._7wS6_G_fields{flex-direction:column;gap:12px;display:flex}._7wS6_G_fields dd{margin:0}._7wS6_G_fields dt{color:var(--aukora-text-secondary);font-size:13px}._7wS6_G_actions{flex-wrap:wrap;gap:8px;margin-top:12px;display:flex}._7wS6_G_owner{flex-direction:column;gap:8px;display:flex}._7wS6_G_owner input{box-sizing:border-box;border:1px solid var(--aukora-border);border-radius:var(--aukora-radius);background:var(--aukora-surface);color:var(--aukora-text);font:inherit;padding:10px 14px}._7wS6_G_owner input:focus-visible{outline:2px solid var(--aukora-blue);outline-offset:2px}._7wS6_G_error{color:var(--aukora-red-warning)}._7wS6_G_menu{width:100%}._7wS6_G_capabilities{margin:12px 0 0;padding-left:18px;font-size:12px;line-height:1.7}._7wS6_G_badge{max-width:min(26rem,100% - 96px);color:var(--aukora-text);border:1px solid var(--aukora-border);border-radius:var(--aukora-radius);background:var(--aukora-surface);font-size:11px;position:absolute;bottom:20px;left:50%;transform:translate(-50%)}._7wS6_G_badge summary{cursor:pointer;color:var(--aukora-text-secondary);padding:7px 10px}._7wS6_G_badgePanel{overflow-wrap:anywhere;max-height:clamp(0px,100dvh - 120px,30rem);padding:0 12px 12px;overflow:auto}._7wS6_G_badgePanel h2{font-size:14px}";
		const tagId$1 = "@aukora/prime-authority-ui/OwnerSurface.module.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId$1) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "@aukora/prime-authority-ui";
			tag.dataset.pluginCss = tagId$1;
			tag.textContent = css$1;
			document.head.appendChild(tag);
		}
		var OwnerSurface_module_css_default = {
			"actions": "_7wS6_G_actions",
			"badge": "_7wS6_G_badge",
			"badgePanel": "_7wS6_G_badgePanel",
			"capabilities": "_7wS6_G_capabilities",
			"card": "_7wS6_G_card",
			"error": "_7wS6_G_error",
			"fields": "_7wS6_G_fields",
			"header": "_7wS6_G_header",
			"menu": "_7wS6_G_menu",
			"owner": "_7wS6_G_owner",
			"surface": "_7wS6_G_surface"
		};
		//#endregion
		//#region lib/types/client/OwnerSurface.js
		function OwnerSurface({ activeSurface, controller }) {
			const state = (0, react.useSyncExternalStore)(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
			const busy = state.phase.endsWith("_pending") || state.approval_action_pending || state.logout_status === "pending";
			const locked = busy || state.phase === "outcome_unknown";
			const view = state.presentation;
			const memoryAction = view?.operation.action_type === "memory.save" || view?.operation.action_type === "memory.forget";
			let memoryReady = !memoryAction;
			if (!memoryReady && view?.memory_review) try {
				validateCaptureReview(view.operation.canonical_parameters, {
					statement: view.memory_review.statement,
					attributed_to: view.memory_review.attributed_to
				});
				memoryReady = view.memory_review.capture_sha256 === view.operation.canonical_parameters.capture_sha256;
				if (view.capture_metadata) validateCaptureMetadata(view.capture_metadata);
			} catch {
				memoryReady = false;
			}
			if (!memoryReady && view?.operation.action_type === "memory.forget" && view.forget_review) try {
				const { record_id, revision, statement, attributed_to, canonical_sha256 } = view.forget_review;
				validateForgetReview(view.operation, {
					record_id,
					revision,
					statement,
					attributed_to
				});
				memoryReady = canonical_sha256 === view.operation.canonical_parameters.canonical_sha256;
			} catch {
				memoryReady = false;
			}
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
									onClick: () => {
										controller.logout();
									},
									children: "Sign out"
								})]
							}),
							state.logout_status !== "idle" && (0, react_jsx_runtime.jsx)("p", {
								role: "status",
								"data-server-logout-status": state.logout_status,
								children: state.logout_status === "confirmed" ? "The host confirmed server logout." : state.logout_status === "pending" ? "Local access removed. Server logout is pending." : "Local access removed. Server logout is unconfirmed."
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
								view.operation.action_type === "memory.save" && (0, react_jsx_runtime.jsxs)("div", {
									"data-memory-capture-review": true,
									children: [(0, react_jsx_runtime.jsx)("h3", { children: "Exact memory statement" }), memoryReady ? (0, react_jsx_runtime.jsxs)(react_jsx_runtime.Fragment, { children: [
										(0, react_jsx_runtime.jsx)("pre", {
											"data-memory-statement": true,
											children: view.memory_review.statement
										}),
										(0, react_jsx_runtime.jsx)("p", { children: "Attribution" }),
										(0, react_jsx_runtime.jsx)("pre", {
											"data-memory-attribution": true,
											children: view.memory_review.attributed_to
										}),
										(0, react_jsx_runtime.jsx)("p", { children: "Capture hash" }),
										(0, react_jsx_runtime.jsx)("pre", {
											"data-memory-capture-hash": true,
											children: view.memory_review.capture_sha256
										}),
										(0, react_jsx_runtime.jsx)("p", { children: "The operation digest below binds this exact statement and attribution. The host verifies the private capture." }),
										(0, react_jsx_runtime.jsx)(MemoryCaptureHints, { statement: view.memory_review.statement }),
										view.capture_metadata ? (0, react_jsx_runtime.jsxs)("dl", {
											"data-fixed-capture-dates": true,
											children: [
												(0, react_jsx_runtime.jsx)("dt", { children: "Source observed at" }),
												(0, react_jsx_runtime.jsx)("dd", { children: (0, react_jsx_runtime.jsx)("time", { children: view.capture_metadata.observed_at }) }),
												(0, react_jsx_runtime.jsx)("dt", { children: "Valid from" }),
												(0, react_jsx_runtime.jsx)("dd", { children: (0, react_jsx_runtime.jsx)("time", { children: view.capture_metadata.valid_from }) })
											]
										}) : (0, react_jsx_runtime.jsx)("p", {
											"data-fixed-capture-dates-unavailable": true,
											children: "The host has not supplied the capture dates."
										})
									] }) : (0, react_jsx_runtime.jsx)("p", {
										role: "alert",
										"data-memory-review-refused": true,
										children: "The exact memory statement and attribution are missing or do not match the capture draft. Approval is unavailable."
									})]
								}),
								view.operation.action_type === "memory.forget" && (0, react_jsx_runtime.jsxs)("div", {
									"data-memory-forget-review": true,
									children: [(0, react_jsx_runtime.jsx)("h3", { children: "Exact original record for logical forget" }), memoryReady ? (0, react_jsx_runtime.jsxs)(react_jsx_runtime.Fragment, { children: [
										(0, react_jsx_runtime.jsx)("p", { children: "Record" }),
										(0, react_jsx_runtime.jsx)("pre", {
											"data-forget-record-id": true,
											children: view.forget_review.record_id
										}),
										(0, react_jsx_runtime.jsx)("p", { children: "Revision" }),
										(0, react_jsx_runtime.jsx)("pre", {
											"data-forget-revision": true,
											children: view.forget_review.revision
										}),
										(0, react_jsx_runtime.jsx)("p", { children: "Original statement" }),
										(0, react_jsx_runtime.jsx)("pre", {
											"data-forget-statement": true,
											children: view.forget_review.statement
										}),
										(0, react_jsx_runtime.jsx)("p", { children: "Original attribution" }),
										(0, react_jsx_runtime.jsx)("pre", {
											"data-forget-attribution": true,
											children: view.forget_review.attributed_to === null ? "null" : view.forget_review.attributed_to
										}),
										(0, react_jsx_runtime.jsx)("p", { children: "Original canonical bytes hash" }),
										(0, react_jsx_runtime.jsx)("pre", {
											"data-forget-canonical-hash": true,
											children: view.forget_review.canonical_sha256
										}),
										(0, react_jsx_runtime.jsx)("p", { children: "Logical forget removes visibility. Canonical payloads, backups, WAL, authority history and physical media are retained." })
									] }) : (0, react_jsx_runtime.jsx)("p", {
										role: "alert",
										"data-forget-review-refused": true,
										children: "The original record and exact literals are missing or changed. Approval is unavailable."
									})]
								}),
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
										disabled: state.phase !== "review_ready" || state.expired || !state.authority_available || !memoryReady || busy || memoryAction && !state.approval_action_available,
										onClick: () => {
											controller.submitApproval();
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
								}),
								memoryAction && !state.approval_action_available && !state.approval_action_result && !state.forget_action_result && (0, react_jsx_runtime.jsx)("p", {
									role: "status",
									"data-memory-action-unavailable": true,
									children: "The memory approval workflow is unavailable."
								})
							] })
						]
					}),
					state.approval_action_result && (0, react_jsx_runtime.jsxs)(_aukora_face_layout_client.Panel, {
						className: OwnerSurface_module_css_default.card,
						"data-memory-workflow-result": true,
						children: [
							(0, react_jsx_runtime.jsx)("h2", { children: "Host memory workflow result" }),
							(0, react_jsx_runtime.jsxs)("dl", {
								className: OwnerSurface_module_css_default.fields,
								children: [
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Approval" }), (0, react_jsx_runtime.jsx)("dd", {
										"data-memory-approval-status": true,
										children: state.approval_action_result.approval
									})] }),
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Save" }), (0, react_jsx_runtime.jsx)("dd", {
										"data-memory-save-status": true,
										children: state.approval_action_result.save
									})] }),
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Index" }), (0, react_jsx_runtime.jsx)("dd", {
										"data-memory-index-status": true,
										children: state.approval_action_result.index.status
									})] }),
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Citation" }), (0, react_jsx_runtime.jsx)("dd", {
										"data-memory-citation-status": true,
										children: state.approval_action_result.citation_status
									})] }),
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Authority settlement" }), (0, react_jsx_runtime.jsx)("dd", {
										"data-memory-settlement-status": true,
										children: state.approval_action_result.authority_settlement ?? "unconfirmed"
									})] }),
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Receipt digest" }), (0, react_jsx_runtime.jsx)("dd", { children: (0, react_jsx_runtime.jsx)("pre", {
										"data-memory-receipt-digest": true,
										children: state.approval_action_result.receipt_digest ?? "unconfirmed"
									}) })] })
								]
							}),
							state.approval_action_result.reconciliation_required && (0, react_jsx_runtime.jsx)("p", {
								role: "alert",
								children: "Reconciliation is required. Do not retry this save."
							}),
							state.approval_action_result.read_error_code && (0, react_jsx_runtime.jsxs)("p", {
								role: "status",
								children: ["Index or citation read unavailable: ", state.approval_action_result.read_error_code]
							}),
							state.approval_action_result.receipt && (0, react_jsx_runtime.jsxs)("details", { children: [(0, react_jsx_runtime.jsx)("summary", { children: "Exact host receipt" }), (0, react_jsx_runtime.jsx)("pre", {
								"data-memory-effect-receipt": true,
								children: JSON.stringify(state.approval_action_result.receipt, null, 2)
							})] }),
							state.approval_action_result.citation && (0, react_jsx_runtime.jsxs)("details", { children: [(0, react_jsx_runtime.jsx)("summary", { children: "Exact citation" }), (0, react_jsx_runtime.jsx)("pre", {
								"data-memory-citation": true,
								children: JSON.stringify(state.approval_action_result.citation, null, 2)
							})] })
						]
					}),
					state.forget_action_result && (0, react_jsx_runtime.jsxs)(_aukora_face_layout_client.Panel, {
						className: OwnerSurface_module_css_default.card,
						"data-memory-forget-result": true,
						children: [
							(0, react_jsx_runtime.jsx)("h2", { children: "Host logical-forget result" }),
							(0, react_jsx_runtime.jsxs)("dl", {
								className: OwnerSurface_module_css_default.fields,
								children: [
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Approval" }), (0, react_jsx_runtime.jsx)("dd", { children: state.forget_action_result.approval })] }),
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Logical forget" }), (0, react_jsx_runtime.jsx)("dd", {
										"data-forget-status": true,
										children: state.forget_action_result.forget
									})] }),
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Authority settlement" }), (0, react_jsx_runtime.jsx)("dd", {
										"data-forget-settlement": true,
										children: state.forget_action_result.authority_settlement ?? "unconfirmed"
									})] }),
									(0, react_jsx_runtime.jsxs)("div", { children: [(0, react_jsx_runtime.jsx)("dt", { children: "Receipt digest" }), (0, react_jsx_runtime.jsx)("dd", { children: (0, react_jsx_runtime.jsx)("pre", { children: state.forget_action_result.receipt_digest ?? "unconfirmed" }) })] })
								]
							}),
							state.forget_action_result.forgotten && (0, react_jsx_runtime.jsx)("p", { children: "Visibility was removed. Canonical payloads, external backups, WAL and physical media were not erased." }),
							state.forget_action_result.reconciliation_required && (0, react_jsx_runtime.jsx)("p", {
								role: "alert",
								children: "Reconciliation is required. Do not retry this forget operation."
							}),
							state.forget_action_result.receipt && (0, react_jsx_runtime.jsxs)("details", { children: [(0, react_jsx_runtime.jsx)("summary", { children: "Exact host forget receipt" }), (0, react_jsx_runtime.jsx)("pre", {
								"data-forget-receipt": true,
								children: JSON.stringify(state.forget_action_result.receipt, null, 2)
							})] })
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
		//#region \0dsh-css:packages/client/aukora-prime-authority/src/client/PrimeProviderEditor.module.css.mjs
		const css = "._87fsza_section{max-width:720px;color:var(--dsw-alias-label-primary);flex-direction:column;gap:12px;display:flex}._87fsza_title{color:var(--dsw-alias-label-primary);margin:0;font-size:16px;font-weight:500;line-height:24px}._87fsza_intro{color:var(--dsw-alias-label-tertiary);margin:0;font-size:14px;line-height:22px}._87fsza_notice{color:var(--dsw-alias-state-warn-label);margin:0;font-size:12px;line-height:18px}._87fsza_savedNotice{color:var(--dsw-alias-state-success-primary);margin:0;font-size:12px;line-height:18px}._87fsza_rows{flex-direction:column;gap:8px;margin:12px 0 0;padding:0;list-style:none;display:flex}._87fsza_rowCard{border:.5px solid var(--dsw-alias-border-l4);border-radius:16px;flex-direction:column;gap:12px;padding:12px 14px;display:flex}._87fsza_rowHead{align-items:center;gap:10px;display:flex}._87fsza_rowIdentity{align-items:center;gap:6px;min-width:0;display:inline-flex}._87fsza_rowName{color:var(--dsw-alias-label-primary);font-size:14px;font-weight:500;line-height:22px}._87fsza_rowTag{border:.5px solid var(--dsw-alias-border-l3);color:var(--dsw-alias-label-secondary);border-radius:4px;flex:none;padding:1px 6px;font-size:11px;line-height:16px}._87fsza_credentialDot{box-sizing:border-box;corner-shape:round;border-radius:50%;flex:none;width:8px;height:8px;display:inline-block}._87fsza_credentialDotConfigured{background:var(--dsw-alias-state-success-primary)}._87fsza_credentialDotMissing{background:var(--dsw-alias-state-error-primary)}._87fsza_rowActions{align-items:center;gap:4px;margin-left:auto;display:inline-flex}._87fsza_primaryButton,._87fsza_secondaryButton,._87fsza_addButton{box-sizing:border-box;height:36px;font:inherit;cursor:pointer;border:none;border-radius:18px;justify-content:center;align-items:center;gap:4px;padding:0 14px;font-size:14px;line-height:22px;display:inline-flex}._87fsza_primaryButton{background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground)}._87fsza_primaryButton:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover)}._87fsza_secondaryButton,._87fsza_addButton{border:.5px solid var(--dsw-alias-border-l3);color:var(--dsw-alias-label-primary);background:0 0}._87fsza_secondaryButton:hover:not(:disabled),._87fsza_addButton:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}._87fsza_secondaryButton:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover-solid)}._87fsza_dangerButton{box-sizing:border-box;height:36px;color:var(--dsw-alias-state-error-primary);font:inherit;cursor:pointer;background:0 0;border:none;border-radius:18px;justify-content:center;align-items:center;padding:0 14px;font-size:14px;line-height:22px;display:inline-flex}._87fsza_dangerButton:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover-danger)}._87fsza_rowActions ._87fsza_secondaryButton,._87fsza_rowActions ._87fsza_dangerButton{border-radius:14px;height:28px;padding:0 10px;font-size:12px;line-height:18px}._87fsza_primaryButton:disabled,._87fsza_secondaryButton:disabled,._87fsza_dangerButton:disabled,._87fsza_addButton:disabled,._87fsza_linkButton:disabled,._87fsza_addModelButton:disabled{opacity:.4;cursor:default}._87fsza_primaryButton:focus-visible,._87fsza_secondaryButton:focus-visible,._87fsza_dangerButton:focus-visible,._87fsza_addButton:focus-visible,._87fsza_linkButton:focus-visible,._87fsza_addModelButton:focus-visible,._87fsza_iconButton:focus-visible,._87fsza_customizedSummary:focus-visible{box-shadow:0 0 0 2px var(--dsw-alias-border-l3);outline:none}._87fsza_editor{background:var(--dsw-alias-bg-module-platform);border-radius:12px;flex-direction:column;gap:14px;padding:14px 16px;display:flex}._87fsza_editorHeader{align-items:baseline;gap:8px;display:flex}._87fsza_editorTitle{color:var(--dsw-alias-label-primary);font-size:14px;font-weight:500;line-height:22px}._87fsza_editorRoute{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px}._87fsza_field{flex-direction:column;gap:6px;display:flex}._87fsza_fieldLabel{color:var(--dsw-alias-label-secondary);align-items:center;gap:10px;font-size:12px;font-weight:500;line-height:18px;display:inline-flex}._87fsza_linkButton{box-sizing:border-box;height:28px;color:var(--dsw-alias-label-tertiary);font:inherit;cursor:pointer;background:0 0;border:none;border-radius:14px;align-items:center;padding:0 10px;font-size:12px;line-height:18px;display:inline-flex}._87fsza_linkButton:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-secondary)}._87fsza_advancedHint{color:var(--dsw-alias-label-tertiary);margin:0;font-size:12px;line-height:18px}._87fsza_editorActions{justify-content:flex-end;gap:8px;display:flex}._87fsza_addBlock{flex-direction:column;gap:12px;display:flex}._87fsza_addActions{flex-wrap:wrap;gap:10px;display:flex}._87fsza_addButton{border:1px dashed var(--dsw-alias-border-l3);border-radius:16px;flex:1 1 0;gap:6px;min-width:180px;height:44px}._87fsza_addCard,._87fsza_setupCard{background:var(--dsw-alias-bg-module-platform);border-radius:12px;flex-direction:column;gap:14px;padding:14px 16px;list-style:none;display:flex}._87fsza_addCard ._87fsza_editor,._87fsza_setupCard ._87fsza_editor{background:0 0;padding:0}._87fsza_customized{border-top:.5px solid var(--dsw-alias-border-l2);padding-top:10px}._87fsza_customizedSummary{cursor:pointer;width:fit-content;color:var(--dsw-alias-label-secondary);border-radius:6px;align-items:center;gap:6px;margin-left:-4px;padding:2px 4px;font-size:12px;font-weight:500;line-height:18px;list-style:none;display:flex}._87fsza_customizedSummary::-webkit-details-marker{display:none}._87fsza_customizedSummary:before{content:\"\";border-bottom:1.5px solid;border-right:1.5px solid;width:5px;height:5px;transition:transform .12s;transform:rotate(-45deg)translate(-1px,-1px)}._87fsza_customized[open]>._87fsza_customizedSummary:before{transform:rotate(45deg)translate(-1px,-1px)}._87fsza_customizedSummary:hover{color:var(--dsw-alias-label-primary)}._87fsza_customizedBody{flex-direction:column;gap:12px;padding-top:12px;display:flex}._87fsza_modelCatalog{border-top:.5px solid var(--dsw-alias-border-l2);flex-direction:column;gap:10px;padding-top:12px;display:flex}._87fsza_modelCatalogHeading{flex-direction:column;gap:2px;display:flex}._87fsza_modelCatalogTitle{color:var(--dsw-alias-label-secondary);font-size:12px;font-weight:500;line-height:18px}._87fsza_modelCatalogMeta,._87fsza_modelEmpty{color:var(--dsw-alias-label-tertiary);margin:0;font-size:12px;line-height:18px}._87fsza_modelList{flex-direction:column;gap:8px;display:flex}._87fsza_modelListHead{justify-content:space-between;align-items:flex-start;gap:12px;display:flex}._87fsza_modelEntry{border:.5px solid var(--dsw-alias-border-l4);border-radius:10px;padding:6px}._87fsza_modelRow{grid-template-columns:minmax(0,1.4fr) minmax(0,1fr) auto auto;align-items:center;gap:6px;display:grid}._87fsza_iconButton{box-sizing:border-box;width:28px;height:28px;color:var(--dsw-alias-label-tertiary);cursor:pointer;background:0 0;border:none;border-radius:6px;justify-content:center;align-items:center;display:inline-flex}._87fsza_iconButton:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}._87fsza_iconButton:disabled{cursor:default;opacity:.4}._87fsza_iconButtonDanger:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary)}._87fsza_modelAdvanced{grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;padding:8px 4px 2px;display:grid}._87fsza_modelField{flex-direction:column;gap:4px;display:flex}._87fsza_modelFieldLabel{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px}._87fsza_modelEmpty{border:1px dashed var(--dsw-alias-border-l3);text-align:center;border-radius:8px;padding:12px}._87fsza_addModelButton{box-sizing:border-box;border:.5px solid var(--dsw-alias-border-l3);height:28px;color:var(--dsw-alias-label-primary);font:inherit;cursor:pointer;background:0 0;border-radius:14px;align-self:flex-start;align-items:center;gap:4px;padding:0 10px;font-size:12px;line-height:18px;display:inline-flex}._87fsza_addModelButton:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}._87fsza_input{box-sizing:border-box;border:.5px solid var(--dsw-alias-border-l4);width:100%;height:32px;font:inherit;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);border-radius:8px;padding:0 10px;font-size:14px;line-height:22px}select._87fsza_input{cursor:pointer;max-width:240px}._87fsza_input:focus{border-color:var(--dsw-alias-brand-primary);outline:none}._87fsza_input::placeholder{color:var(--dsw-alias-label-dimmed)}._87fsza_input:disabled{opacity:.6;cursor:default}._87fsza_selectInput{appearance:none;background-image:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12' fill='none'%3E%3Cpath d='M3 4.5L6 7.5L9 4.5' stroke='%2381858C' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E\");background-position:right 12px center;background-repeat:no-repeat;background-size:12px 12px;padding-right:32px}._87fsza_error{color:var(--dsw-alias-state-error-primary);margin:0;font-size:12px;line-height:18px}._87fsza_deleteDialog{width:min(480px,100%)}._87fsza_deleteConfirm:not(:disabled){border-color:var(--dsw-alias-state-error-primary);color:var(--dsw-alias-state-error-primary)}._87fsza_deleteConfirm:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover-danger)}._87fsza_hiddenLabel{clip:rect(0 0 0 0);white-space:nowrap;width:1px;height:1px;position:absolute;overflow:hidden}@media (prefers-reduced-motion:reduce){._87fsza_customizedSummary:before,._87fsza_switchThumb{transition:none}}._87fsza_fetchDialog{--dsh-scrollbar-thumb:var(--dsw-alias-scrollbar-bg-l2);--dsh-scrollbar-thumb-hover:var(--dsw-alias-scrollbar-hover-l2);max-width:520px}._87fsza_candidateToolbar{align-items:center;gap:8px;margin-bottom:6px;display:flex}._87fsza_candidateSearch{flex:240px;min-width:0}._87fsza_candidateList{flex-direction:column;gap:2px;max-height:320px;margin:0;padding:0;list-style:none;display:flex;overflow-y:auto}._87fsza_candidate{border-radius:6px}._87fsza_candidateLabel{cursor:pointer;align-items:center;gap:8px;padding:6px 8px;display:flex}._87fsza_candidateId{font-family:var(--ds-font-family-code);overflow-wrap:anywhere;flex:auto;font-size:13px}._87fsza_candidateEmpty{color:var(--dsw-alias-label-secondary);text-align:center;margin:24px 0;font-size:13px;line-height:20px}";
		const tagId = "@aukora/prime-authority-ui/PrimeProviderEditor.module.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "@aukora/prime-authority-ui";
			tag.dataset.pluginCss = tagId;
			tag.textContent = css;
			document.head.appendChild(tag);
		}
		var PrimeProviderEditor_module_css_default = {
			"addActions": "_87fsza_addActions",
			"addBlock": "_87fsza_addBlock",
			"addButton": "_87fsza_addButton",
			"addCard": "_87fsza_addCard",
			"addModelButton": "_87fsza_addModelButton",
			"advancedHint": "_87fsza_advancedHint",
			"candidate": "_87fsza_candidate",
			"candidateEmpty": "_87fsza_candidateEmpty",
			"candidateId": "_87fsza_candidateId",
			"candidateLabel": "_87fsza_candidateLabel",
			"candidateList": "_87fsza_candidateList",
			"candidateSearch": "_87fsza_candidateSearch",
			"candidateToolbar": "_87fsza_candidateToolbar",
			"credentialDot": "_87fsza_credentialDot",
			"credentialDotConfigured": "_87fsza_credentialDotConfigured",
			"credentialDotMissing": "_87fsza_credentialDotMissing",
			"customized": "_87fsza_customized",
			"customizedBody": "_87fsza_customizedBody",
			"customizedSummary": "_87fsza_customizedSummary",
			"dangerButton": "_87fsza_dangerButton",
			"deleteConfirm": "_87fsza_deleteConfirm",
			"deleteDialog": "_87fsza_deleteDialog",
			"editor": "_87fsza_editor",
			"editorActions": "_87fsza_editorActions",
			"editorHeader": "_87fsza_editorHeader",
			"editorRoute": "_87fsza_editorRoute",
			"editorTitle": "_87fsza_editorTitle",
			"error": "_87fsza_error",
			"fetchDialog": "_87fsza_fetchDialog",
			"field": "_87fsza_field",
			"fieldLabel": "_87fsza_fieldLabel",
			"hiddenLabel": "_87fsza_hiddenLabel",
			"iconButton": "_87fsza_iconButton",
			"iconButtonDanger": "_87fsza_iconButtonDanger",
			"input": "_87fsza_input",
			"intro": "_87fsza_intro",
			"linkButton": "_87fsza_linkButton",
			"modelAdvanced": "_87fsza_modelAdvanced",
			"modelCatalog": "_87fsza_modelCatalog",
			"modelCatalogHeading": "_87fsza_modelCatalogHeading",
			"modelCatalogMeta": "_87fsza_modelCatalogMeta",
			"modelCatalogTitle": "_87fsza_modelCatalogTitle",
			"modelEmpty": "_87fsza_modelEmpty",
			"modelEntry": "_87fsza_modelEntry",
			"modelField": "_87fsza_modelField",
			"modelFieldLabel": "_87fsza_modelFieldLabel",
			"modelList": "_87fsza_modelList",
			"modelListHead": "_87fsza_modelListHead",
			"modelRow": "_87fsza_modelRow",
			"notice": "_87fsza_notice",
			"primaryButton": "_87fsza_primaryButton",
			"rowActions": "_87fsza_rowActions",
			"rowCard": "_87fsza_rowCard",
			"rowHead": "_87fsza_rowHead",
			"rowIdentity": "_87fsza_rowIdentity",
			"rowName": "_87fsza_rowName",
			"rowTag": "_87fsza_rowTag",
			"rows": "_87fsza_rows",
			"savedNotice": "_87fsza_savedNotice",
			"secondaryButton": "_87fsza_secondaryButton",
			"section": "_87fsza_section",
			"selectInput": "_87fsza_selectInput",
			"setupCard": "_87fsza_setupCard",
			"switchThumb": "_87fsza_switchThumb",
			"title": "_87fsza_title"
		};
		//#endregion
		//#region lib/types/client/PrimeProviderEditor.js
		function ReadOnlyField({ label, value }) {
			return (0, react_jsx_runtime.jsxs)("label", {
				className: PrimeProviderEditor_module_css_default["field"],
				children: [(0, react_jsx_runtime.jsx)("span", {
					className: PrimeProviderEditor_module_css_default["fieldLabel"],
					children: label
				}), (0, react_jsx_runtime.jsx)("input", {
					className: PrimeProviderEditor_module_css_default["input"],
					value,
					readOnly: true,
					"aria-label": label
				})]
			});
		}
		function PrimeProviderEditor({ provider, controller }) {
			const state = (0, react.useSyncExternalStore)(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
			const keyInput = (0, react.useRef)(null);
			const matching = provider.provider === "externalDeepSeek" && provider.settingsNs === "prime-inference" && provider.settingsPath.length === 2 && provider.settingsPath[0] === "providers" && provider.settingsPath[1] === "externalDeepSeek";
			const entryReady = matching && state.entry_status === "ready" && state.owner_status === "loaded";
			(0, react.useEffect)(() => {
				if (matching) controller.load();
			}, [controller, matching]);
			(0, react.useEffect)(() => {
				if (!entryReady && keyInput.current) keyInput.current.value = "";
			}, [entryReady]);
			(0, react.useEffect)(() => {
				const input = keyInput.current;
				return () => {
					if (input) input.value = "";
				};
			}, [matching]);
			if (!matching) return null;
			const row = state.row;
			const ceiling = row.taskSpendCeiling === null ? "Not configured" : `${row.taskSpendCeiling.amount} ${row.taskSpendCeiling.currency}`;
			return (0, react_jsx_runtime.jsxs)("div", {
				className: PrimeProviderEditor_module_css_default["editor"],
				"data-prime-provider-editor": true,
				"data-provider": "externalDeepSeek",
				children: [
					(0, react_jsx_runtime.jsxs)("div", {
						className: PrimeProviderEditor_module_css_default["editorHeader"],
						children: [(0, react_jsx_runtime.jsx)("span", {
							className: PrimeProviderEditor_module_css_default["editorTitle"],
							children: "DeepSeek"
						}), (0, react_jsx_runtime.jsx)("span", {
							className: PrimeProviderEditor_module_css_default["editorRoute"],
							children: "externalDeepSeek"
						})]
					}),
					(0, react_jsx_runtime.jsx)(ReadOnlyField, {
						label: "Endpoint",
						value: row.endpoint
					}),
					(0, react_jsx_runtime.jsxs)("label", {
						className: PrimeProviderEditor_module_css_default["field"],
						children: [
							(0, react_jsx_runtime.jsx)("span", {
								className: PrimeProviderEditor_module_css_default["fieldLabel"],
								children: "Draft model"
							}),
							(0, react_jsx_runtime.jsxs)("select", {
								className: `${PrimeProviderEditor_module_css_default["input"]} ${PrimeProviderEditor_module_css_default["selectInput"]}`,
								"aria-label": "Draft model",
								value: state.model_draft === "deepseek-flash" ? "deepseek-flash" : "",
								onChange: (event) => {
									if (event.target.value === "deepseek-flash") controller.setModel(event.target.value);
								},
								children: [(0, react_jsx_runtime.jsx)("option", {
									value: "",
									disabled: true,
									children: "Choose a model"
								}), (0, react_jsx_runtime.jsx)("option", {
									value: "deepseek-flash",
									children: "DeepSeek V4.1 Flash (deepseek-flash)"
								})]
							}),
							(0, react_jsx_runtime.jsx)("p", {
								className: PrimeProviderEditor_module_css_default["advancedHint"],
								children: "This selection is a local draft. Configuration changes require separate owner approval."
							})
						]
					}),
					(0, react_jsx_runtime.jsx)(ReadOnlyField, {
						label: "Configured model",
						value: row.model || (state.owner_status === "loaded" ? "Not configured" : "Unconfirmed")
					}),
					(0, react_jsx_runtime.jsxs)("details", {
						className: PrimeProviderEditor_module_css_default["customized"],
						children: [(0, react_jsx_runtime.jsx)("summary", {
							className: PrimeProviderEditor_module_css_default["customizedSummary"],
							children: "Current task limits · read-only"
						}), (0, react_jsx_runtime.jsxs)("div", {
							className: PrimeProviderEditor_module_css_default["customizedBody"],
							children: [
								(0, react_jsx_runtime.jsx)(ReadOnlyField, {
									label: "Region",
									value: row.region || "Not configured"
								}),
								(0, react_jsx_runtime.jsx)(ReadOnlyField, {
									label: "Allowed data classes",
									value: row.allowedDataClasses.join(", ") || "None configured"
								}),
								(0, react_jsx_runtime.jsx)(ReadOnlyField, {
									label: "Maximum input tokens",
									value: String(row.maxInputTokens)
								}),
								(0, react_jsx_runtime.jsx)(ReadOnlyField, {
									label: "Maximum output tokens",
									value: String(row.maxOutputTokens)
								}),
								(0, react_jsx_runtime.jsx)(ReadOnlyField, {
									label: "Maximum requests",
									value: String(row.maxRequests)
								}),
								(0, react_jsx_runtime.jsx)(ReadOnlyField, {
									label: "Task spend ceiling",
									value: ceiling
								})
							]
						})]
					}),
					(0, react_jsx_runtime.jsxs)("p", {
						className: PrimeProviderEditor_module_css_default["advancedHint"],
						"data-prime-provider-readiness": true,
						children: [
							"Catalog: ",
							state.catalog_status,
							". Owner status: ",
							state.owner_status,
							". Key entry: ",
							state.entry_status,
							"."
						]
					}),
					(0, react_jsx_runtime.jsxs)("p", {
						className: PrimeProviderEditor_module_css_default["advancedHint"],
						children: [
							"Credential status: ",
							state.owner_status === "loaded" && row.credentialConfigured ? "Owner status reports configured" : "Not confirmed configured",
							"."
						]
					}),
					(0, react_jsx_runtime.jsxs)("form", {
						onSubmit: (event) => {
							event.preventDefault();
							if (entryReady && keyInput.current) controller.submitCredential(keyInput.current);
						},
						children: [(0, react_jsx_runtime.jsxs)("label", {
							className: PrimeProviderEditor_module_css_default["field"],
							children: [(0, react_jsx_runtime.jsx)("span", {
								className: PrimeProviderEditor_module_css_default["fieldLabel"],
								children: "API key · approved owner handoff"
							}), (0, react_jsx_runtime.jsx)("input", {
								ref: keyInput,
								className: PrimeProviderEditor_module_css_default["input"],
								type: "password",
								autoComplete: "off",
								autoCapitalize: "none",
								spellCheck: false,
								"aria-label": "DeepSeek API key",
								disabled: !entryReady
							})]
						}), (0, react_jsx_runtime.jsxs)("div", {
							className: PrimeProviderEditor_module_css_default["editorActions"],
							children: [(0, react_jsx_runtime.jsx)("button", {
								type: "button",
								className: PrimeProviderEditor_module_css_default["secondaryButton"],
								disabled: state.owner_status === "pending" || state.entry_status === "pending",
								onClick: () => {
									controller.refreshOwner();
								},
								children: "Refresh owner status"
							}), (0, react_jsx_runtime.jsx)("button", {
								type: "submit",
								className: PrimeProviderEditor_module_css_default["primaryButton"],
								disabled: !entryReady,
								children: "Store key with approved handoff"
							})]
						})]
					}),
					(0, react_jsx_runtime.jsx)("p", {
						className: PrimeProviderEditor_module_css_default["advancedHint"],
						role: "status",
						"aria-live": "polite",
						"data-prime-provider-reason": true,
						children: state.reason
					})
				]
			});
		}
		//#endregion
		//#region lib/types/adapters/provider-settings.mjs
		const invalid = () => {
			throw new PrimeTransportError("INVALID", "ui:invalid-provider-namespace");
		};
		const closed$1 = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join(",") === [...keys].sort().join(",");
		const fields = [
			"endpoint",
			"model",
			"region",
			"allowedDataClasses",
			"maxInputTokens",
			"maxOutputTokens",
			"maxRequests",
			"enabled",
			"credentialConfigured",
			"taskSpendCeiling"
		];
		Object.freeze({
			provider: "externalDeepSeek",
			displayName: "DeepSeek",
			settingsNs: "prime-inference",
			settingsPath: Object.freeze(["providers", "externalDeepSeek"]),
			declared: false
		});
		function validateProviderNamespace(input, contracts) {
			if (typeof contracts?.canonicalJson !== "function") throw new PrimeTransportError("UNAVAILABLE", "ui:provider-schema-helper-unavailable");
			let value;
			try {
				value = JSON.parse(contracts.canonicalJson(input));
			} catch {
				invalid();
			}
			if (!closed$1(value, ["namespace", "section"]) || value.namespace !== "prime-inference" || !closed$1(value.section, ["providers"]) || !closed$1(value.section.providers, ["externalDeepSeek"])) invalid();
			const row = value.section.providers.externalDeepSeek;
			if (!closed$1(row, fields) || row.endpoint !== "https://api.deepseek.com" || typeof row.model !== "string" || typeof row.region !== "string" || !Array.isArray(row.allowedDataClasses) || row.allowedDataClasses.some((s) => typeof s !== "string" || !s) || [
				"maxInputTokens",
				"maxOutputTokens",
				"maxRequests"
			].some((k) => !Number.isSafeInteger(row[k]) || row[k] < 0) || typeof row.enabled !== "boolean" || typeof row.credentialConfigured !== "boolean") invalid();
			const cost = row.taskSpendCeiling;
			if (cost !== null && (!closed$1(cost, ["currency", "amount"]) || cost.currency !== "USD" || typeof cost.amount !== "string" || !/^(?:0|[1-9]\d*)(?:\.\d{1,8})?$/.test(cost.amount))) invalid();
			return value;
		}
		//#endregion
		//#region lib/types/client/provider-controller.mjs
		const MODEL = "deepseek-flash", ENTRY = "/api/prime/inference/credential-entry";
		const EMPTY = {
			endpoint: "https://api.deepseek.com",
			model: "",
			region: "",
			allowedDataClasses: [],
			maxInputTokens: 0,
			maxOutputTokens: 0,
			maxRequests: 0,
			enabled: false,
			credentialConfigured: false,
			taskSpendCeiling: null
		};
		const frozen = (value) => {
			if (value && typeof value === "object") {
				for (const child of Object.values(value)) frozen(child);
				Object.freeze(value);
			}
			return value;
		};
		const closed = (value, fields) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join(",") === [...fields].sort().join(",");
		const refusal = () => {
			throw new TypeError("Prime provider operation unavailable");
		};
		/** Default source binding exposes the owned PUBLIC catalog only. Owner APIs
		* require H's injected, C-authenticated context and independent worker join. */
		function createPublicProviderApi(contracts, fetcher = globalThis.fetch) {
			return Object.freeze({ async catalog() {
				const response = await fetcher("/api/prime/inference/catalog", {
					method: "GET",
					credentials: "same-origin",
					redirect: "error",
					cache: "no-store"
				});
				if (!response.ok) refusal();
				return contracts.parseStrictJson(await response.text(), {
					maxBytes: 65536,
					maxDepth: 32
				});
			} });
		}
		function createPrimeProviderController({ now = Date.now, fetcher = globalThis.fetch, schedule = setTimeout, unschedule = clearTimeout, browser = () => ({
			origin: globalThis.location?.origin,
			isSecureContext: globalThis.isSecureContext
		}) } = {}) {
			const listeners = /* @__PURE__ */ new Set();
			let binding = null, offOwner, revision = 0, statusRevision = 0, ownerMetadataLoaded = false, owner = null, flight = null, ticket = null, generation = null, disposed = false, expiryTimer;
			const usedApprovals = /* @__PURE__ */ new Set();
			let state = frozen({
				model_draft: MODEL,
				catalog_status: "pending",
				owner_status: "unavailable",
				row: { ...EMPTY },
				entry_status: "unavailable",
				reason: "Owner configuration and secure key entry are unavailable."
			});
			const notify = (patch) => {
				if (disposed) return;
				state = frozen({
					...state,
					...patch
				});
				for (const listener of listeners) listener();
			};
			const current = (entry) => !disposed && binding === entry.binding && revision === entry.revision && owner === entry.owner;
			function ownerReady() {
				const observed = binding?.ownerController?.getSnapshot();
				if (!owner || observed?.owner !== owner || observed.authority_available !== true || observed.expired === true || typeof owner.owner_id !== "string" || !owner.owner_id || !Number.isFinite(Date.parse(owner.expiry)) || Date.parse(owner.expiry) <= now()) refusal();
				return owner;
			}
			function secureEntry() {
				const profile = binding?.entryProfile, support = browser();
				if (!closed(profile, ["origin", "qualified_separate_worker"]) || profile.qualified_separate_worker !== true || typeof profile.origin !== "string" || new URL(profile.origin).protocol !== "https:" || new URL(profile.origin).origin !== profile.origin || support.origin !== profile.origin || support.isSecureContext !== true) refusal();
			}
			function stopExpiry() {
				if (expiryTimer !== void 0) unschedule(expiryTimer);
				expiryTimer = void 0;
			}
			function clearPrivate() {
				revision++;
				statusRevision++;
				ownerMetadataLoaded = false;
				ticket = null;
				generation = null;
				flight = null;
				usedApprovals.clear();
				stopExpiry();
			}
			function rowOf(namespace) {
				return validateProviderNamespace(namespace, binding.contracts).section.providers.externalDeepSeek;
			}
			const api = {
				getSnapshot: () => state,
				subscribe(listener) {
					listeners.add(listener);
					return () => listeners.delete(listener);
				},
				connect(next) {
					offOwner?.();
					clearPrivate();
					binding = next;
					owner = next?.ownerController?.getSnapshot().owner ?? null;
					notify({
						catalog_status: "pending",
						owner_status: "unavailable",
						row: { ...EMPTY },
						entry_status: "unavailable",
						reason: "Loading the nonsecret provider catalog. Secure entry remains unavailable."
					});
					offOwner = next?.ownerController?.subscribe(() => {
						const snapshot = next.ownerController.getSnapshot(), observed = snapshot.owner;
						if (observed === owner && (!owner || snapshot.authority_available === true && snapshot.expired !== true && Date.parse(owner.expiry) > now())) return;
						clearPrivate();
						owner = observed;
						notify({
							owner_status: "unavailable",
							row: { ...EMPTY },
							entry_status: "unavailable",
							reason: "Owner access changed. Configuration and key entry need a fresh owner check."
						});
					});
				},
				setModel(value) {
					if (value !== MODEL) refusal();
					notify({
						model_draft: value,
						reason: "Model choice is a local draft. No configuration was saved and no model request was sent."
					});
				},
				async load() {
					const entry = {
						binding,
						revision,
						owner
					};
					try {
						if (typeof binding?.api?.catalog !== "function") refusal();
						const catalog = await binding.api.catalog();
						if (!current(entry)) return null;
						if (!closed(catalog, [
							"version",
							"providers",
							"namespace"
						]) || catalog.version !== 1 || !Array.isArray(catalog.providers) || catalog.providers.length !== 1) refusal();
						const provider = catalog.providers[0];
						if (!closed(provider, [
							"provider",
							"displayName",
							"settingsNs",
							"settingsPath",
							"declared",
							"active",
							"endpoint",
							"credential_entry",
							"paid_requests_enabled",
							"models",
							"credential_status",
							"pending"
						]) || provider.provider !== "externalDeepSeek" || provider.settingsNs !== "prime-inference" || provider.endpoint !== "https://api.deepseek.com" || !Array.isArray(provider.settingsPath) || provider.settingsPath.join("/") !== "providers/externalDeepSeek" || provider.credential_entry !== "separated_owner_handoff") refusal();
						const row = rowOf(catalog.namespace);
						notify({
							catalog_status: "loaded",
							...ownerMetadataLoaded ? {} : {
								row,
								reason: "DeepSeek V4.1 Flash uses deepseek-flash. Model choice is a local draft; secure owner entry remains unavailable."
							}
						});
						return state;
					} catch {
						if (current(entry)) notify({
							catalog_status: "unavailable",
							reason: "The provider catalog is unavailable. Owner access and key entry are shown separately."
						});
						return null;
					}
				},
				async refreshOwner() {
					const entry = {
						binding,
						revision,
						owner
					};
					const statusRead = ++statusRevision;
					try {
						ownerReady();
						if (typeof binding?.api?.status !== "function") refusal();
						notify({ owner_status: "pending" });
						if (!current(entry) || statusRead !== statusRevision) return null;
						ownerReady();
						const result = await binding.api.status();
						if (!current(entry) || statusRead !== statusRevision) return null;
						ownerReady();
						if (!closed(result, [
							"version",
							"provider",
							"configured",
							"config_digest",
							"profile",
							"credential",
							"paid_requests_enabled",
							"pending",
							"namespace"
						]) || result.version !== 1 || result.provider !== "externalDeepSeek" || typeof result.configured !== "boolean" || typeof result.paid_requests_enabled !== "boolean" || !closed(result.credential, ["configured", "generation"]) || typeof result.credential.configured !== "boolean" || !(result.credential.generation === null || Number.isSafeInteger(result.credential.generation) && result.credential.generation > 0)) refusal();
						const row = rowOf(result.namespace);
						if (row.credentialConfigured !== result.credential.configured || row.enabled !== result.paid_requests_enabled) refusal();
						generation = result.credential.generation ?? 0;
						ownerMetadataLoaded = true;
						notify({
							owner_status: "loaded",
							row,
							...[
								"unknown",
								"pending",
								"ready",
								"configured"
							].includes(state.entry_status) ? {} : {
								entry_status: "review_required",
								reason: "Owner metadata loaded. Key entry requires fresh owner approval and secure credential storage."
							}
						});
						return state;
					} catch {
						if (current(entry) && statusRead === statusRevision) notify({
							owner_status: "unavailable",
							...[
								"unknown",
								"pending",
								"ready",
								"configured"
							].includes(state.entry_status) ? {} : { entry_status: "unavailable" },
							reason: "Owner provider configuration is unavailable. Key entry remains disabled."
						});
						return null;
					}
				},
				/** H supplies the signed proof from the existing exact-operation approval
				* UI. C/worker authenticate and authorize provider+generation independently. */
				prepareCredentialEntry(input) {
					if (flight) return flight;
					if (state.entry_status === "unknown" || state.entry_status === "pending" || state.entry_status === "ready") return Promise.resolve(null);
					const entry = {
						binding,
						revision,
						owner
					};
					flight = Promise.resolve().then(async () => {
						let invoked = false;
						try {
							if (!current(entry)) return null;
							ownerReady();
							secureEntry();
							if (state.owner_status !== "loaded" || !closed(input, ["expected_generation", "approval_proof"]) || input.expected_generation !== generation || !Number.isSafeInteger(generation) || generation < 0 || typeof binding.api.credentialHandoff !== "function") refusal();
							binding.contracts.validateContract("ApprovalProof", input.approval_proof);
							if (input.approval_proof.owner_id !== owner.owner_id || Date.parse(input.approval_proof.expiry) <= now()) refusal();
							const proofRef = input.approval_proof.operation_id + "\0" + input.approval_proof.operation_digest + "\0" + input.approval_proof.nonce;
							if (usedApprovals.has(proofRef) || usedApprovals.size >= 16) refusal();
							const request = binding.contracts.parseStrictJson(binding.contracts.canonicalJson(input));
							notify({
								entry_status: "pending",
								reason: "Waiting for approved single-use key entry. No key was sent."
							});
							if (!current(entry)) return null;
							ownerReady();
							secureEntry();
							usedApprovals.add(proofRef);
							invoked = true;
							const descriptor = await binding.api.credentialHandoff(request);
							if (!current(entry)) return null;
							ownerReady();
							secureEntry();
							if (!closed(descriptor, [
								"provider",
								"method",
								"path",
								"ticket",
								"expires_at"
							]) || descriptor.provider !== "externalDeepSeek" || descriptor.method !== "POST" || descriptor.path !== ENTRY || typeof descriptor.ticket !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(descriptor.ticket) || typeof descriptor.expires_at !== "string" || !Number.isFinite(Date.parse(descriptor.expires_at)) || Date.parse(descriptor.expires_at) <= now() || Date.parse(descriptor.expires_at) > Math.min(now() + 6e4, Date.parse(owner.expiry))) refusal();
							ticket = frozen({
								...descriptor,
								expected_generation: request.expected_generation
							});
							const prepared = ticket;
							stopExpiry();
							expiryTimer = schedule(() => {
								if (current(entry) && ticket === prepared) {
									ticket = null;
									notify({
										entry_status: "unavailable",
										reason: "The one-use credential handoff expired. Key entry is disabled; no key was sent."
									});
								}
							}, Date.parse(prepared.expires_at) - now());
							expiryTimer?.unref?.();
							notify({
								entry_status: "ready",
								reason: "Approved key entry is ready. The key goes directly to secure credential storage."
							});
							return { ready: true };
						} catch {
							if (current(entry)) {
								ticket = null;
								notify({
									entry_status: invoked ? "unknown" : "unavailable",
									reason: invoked ? "The credential handoff result is unconfirmed. No key was sent and no retry was made." : "Secure owner handoff is unavailable. No key was sent."
								});
							}
							return null;
						} finally {
							if (current(entry)) flight = null;
						}
					});
					return flight;
				},
				async submitCredential(input) {
					const entry = {
						binding,
						revision,
						owner
					}, descriptor = ticket;
					let secret, body, dispatched = false;
					try {
						if (state.entry_status === "unknown" || state.entry_status === "pending") return null;
						ownerReady();
						secureEntry();
						if (state.entry_status !== "ready" || !descriptor || Date.parse(descriptor.expires_at) <= now() || typeof input?.value !== "string") refusal();
						secret = input.value;
						if (!secret || secret.length > 4096) refusal();
						ticket = null;
						stopExpiry();
						input.value = "";
						body = binding.contracts.canonicalJson({
							ticket: descriptor.ticket,
							secret
						});
						secret = void 0;
						notify({
							entry_status: "pending",
							reason: "Sending the key to secure credential storage. Its result is unconfirmed."
						});
						if (!current(entry)) return null;
						ownerReady();
						secureEntry();
						dispatched = true;
						const response = await fetcher(ENTRY, {
							method: "POST",
							credentials: "same-origin",
							redirect: "error",
							cache: "no-store",
							headers: { "content-type": "application/json" },
							body
						});
						body = void 0;
						if (!current(entry)) return null;
						ownerReady();
						secureEntry();
						const result = binding.contracts.parseStrictJson(await response.text(), {
							maxBytes: 4096,
							maxDepth: 8
						});
						if (!current(entry)) return null;
						ownerReady();
						if (!response.ok || !closed(result, ["configured", "generation"]) || result.configured !== true || result.generation !== descriptor.expected_generation + 1) refusal();
						generation = result.generation;
						statusRevision++;
						ownerMetadataLoaded = true;
						notify({
							owner_status: "loaded",
							entry_status: "configured",
							row: {
								...state.row,
								credentialConfigured: true
							},
							reason: "Credential storage was acknowledged. Paid inference still requires an approved route and task limits."
						});
						return {
							configured: true,
							generation: result.generation
						};
					} catch {
						if (current(entry)) notify({
							entry_status: dispatched ? "unknown" : "unavailable",
							reason: dispatched ? "Credential storage is unconfirmed. The one-use handoff was consumed; no retry was sent." : "Secure key entry is unavailable."
						});
						return null;
					} finally {
						secret = void 0;
						body = void 0;
						if (input && typeof input.value === "string") input.value = "";
					}
				},
				disconnect() {
					offOwner?.();
					offOwner = void 0;
					clearPrivate();
					binding = null;
					owner = null;
					notify({
						owner_status: "unavailable",
						row: { ...EMPTY },
						entry_status: "unavailable",
						reason: "Owner provider binding unavailable. Key entry disabled."
					});
				},
				dispose() {
					api.disconnect();
					disposed = true;
					listeners.clear();
				}
			};
			return Object.freeze(api);
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
			const providers = createPrimeProviderController();
			let supplied = false;
			let providerSupplied = false;
			let providerContracts;
			const connectPublicProvider = () => {
				if (!providerSupplied && providerContracts) {
					providers.connect({
						ownerController: controller,
						contracts: providerContracts,
						api: createPublicProviderApi(providerContracts)
					});
					providers.load();
				}
			};
			ctx.effect(() => {
				const off = ctx.reflect.provide("primeOwnerUi", controller);
				return () => {
					controller.dispose();
					off();
				};
			}, "prime owner UI controller");
			ctx.effect(() => {
				const off = ctx.reflect.provide("primeProviderUi", providers);
				return () => {
					providers.dispose();
					off();
				};
			}, "prime Models card controller");
			ctx.inject(["primeProviderSettings"], (binding) => {
				providerSupplied = true;
				providers.connect({
					...binding.primeProviderSettings,
					ownerController: controller
				});
				providers.load();
				binding.effect(() => () => {
					providerSupplied = false;
					providers.disconnect();
					connectPublicProvider();
				}, "prime owner provider binding");
			});
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
					if (!disposed) {
						providerContracts = contracts;
						connectPublicProvider();
					}
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
			ctx.slots.inject("settings.models.provider-card", () => ctx.slots.register({
				name: "settings.models.provider-card",
				key: "prime-inference",
				inject: () => ({ controller: providers })
			}, PrimeProviderEditor));
		}
		//#endregion
		exports.CapabilityBadge = CapabilityBadge;
		exports.OwnerSurface = OwnerSurface;
		exports.apply = apply;
		exports.createHttpAuthority = createHttpAuthority;
		exports.createPrimeOwnerController = createPrimeOwnerController;
		exports.createPrimeProviderController = createPrimeProviderController;
		exports.createPublicProviderApi = createPublicProviderApi;
		exports.inject = inject;
		return module.exports;
	}
});

//# sourceMappingURL=client.js.map