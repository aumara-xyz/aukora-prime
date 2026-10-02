// SPDX-License-Identifier: AGPL-3.0-or-later
// Closed required-source union: whole files, literal reviewed titles/counters.
// Frozen selected b336 source bytes; revision attribution is not checkout or runtime attestation.
// No runtime repinning, selectors, candidate PASS inputs or external activation.
export const NODE_VERSION = 'v24.11.1'
export const SOURCE_REVIEW_COMMIT = 'b336753488a2a70adcefd82a95909263dbe26c5a'
const freeze = value => {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child)
    Object.freeze(value)
  }
  return value
}
export const CASES = freeze([
  {
    "id": "contracts-v1",
    "property": "Frozen operation vectors and transport envelopes",
    "entry": "packages/contracts/check.mjs",
    "expectedSha256": "75f3b3119b8e55000986cf59da9e98e09c37a35d7b4f4f56d198727b162c00f2",
    "protocol": "assert-script",
    "timeoutMs": 15000,
    "pins": [
      {
        "path": "packages/contracts/golden-v1.json",
        "sha256": "ffc6655e603b1d01af54304742b73393a510910d34ad942fd0042cdd1f006875"
      }
    ],
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "memory-original-bytes",
    "property": "Historical record bytes and IDs survive original byte forms",
    "entry": "packages/memory/test/codecs-hardening.test.mjs",
    "expectedSha256": "f11e4592b33f80112ceed7b091292d1f513c2577cd38c0102c9cc0c2ea456737",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "synthetic historical byte forms retain envelope IDs, salt, opaque aura and separate byte hashes",
      "synthetic v0 decimals retain their donor profile and v1 refuses numeric decimal reinterpretation",
      "synthetic BOM, CRLF, redundant whitespace and lossy JSON encodings refuse without changing IDs",
      "synthetic same-ID derived metadata cannot contradict its exact creation chain",
      "synthetic chains retain donor compact encoding and refuse byte-only or hash mutations",
      "synthetic redacted export metadata is opaque and admits exact donor settled and accepted literals"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "inference-mock-accounting",
    "property": "Mock-only body, data scope and durable accounting",
    "entry": "packages/inference/check.mjs",
    "expectedSha256": "d20bb25f5152137431575ba96049f31d721669968ad20528e3fe5f66fc22d1b2",
    "protocol": "tap",
    "timeoutMs": 20000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "Lane E disposable mock acceptance: exact body, scope, durable caps, uncertainty and DSH stream"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "ui-static-boundary",
    "property": "Local native assets and static route boundaries",
    "entry": "packages/ui/scripts/check-static.mjs",
    "expectedSha256": "bd7797da793dfafc352250e445f06b8be4c9e17f6fc52005b6a721dc3c0858cf",
    "protocol": "assert-script",
    "timeoutMs": 15000,
    "pins": [
      {
        "path": "packages/ui/baseline-manifest.json",
        "sha256": "a3e519151fce2e2280a1ed921f94f2bf358a96db3f3e6e4d87016eee5b0677c9"
      }
    ],
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "ui-owner-presentation",
    "property": "Injected owner review and signing presentation boundaries",
    "entry": "packages/ui/scripts/check-transport.mjs",
    "expectedSha256": "aa1083486c53fc3bb87e7bfeadc866cf6eaf89d51f1e48ed5a1b35c36e80d801",
    "protocol": "assert-json",
    "timeoutMs": 15000,
    "args": [],
    "counter": {
      "key": "cases",
      "value": 12
    },
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      },
      {
        "path": "packages/contracts/src/runtime.mjs",
        "sha256": "d42ec191f52279b4af33ad23edb1518425817ac89e70a80955d0c0266386be12"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "ops-release-metadata",
    "property": "Release digest, ordinary archive bytes and metadata refusal",
    "entry": "packages/ops/check-digest-controls.mjs",
    "expectedSha256": "f7b8fe1f6b1e80301f3f8a9c52113ea91c04b1c9bb85ee7486adaf9c478e6b5d",
    "protocol": "assert-json",
    "timeoutMs": 15000,
    "requiresPython": true,
    "counter": {
      "key": "checks",
      "value": 14
    },
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "authority-review-renewal",
    "property": "Ordinary authenticated review TTL renewal",
    "entry": "packages/authority/check-admission.mjs",
    "expectedSha256": "54b51ea7401e4c4e01674edec553c0738731a58500b10366dbe27e73ece8a35c",
    "protocol": "assert-script",
    "timeoutMs": 15000,
    "args": [
      "admission-probe",
      "session-renewal"
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "execution-ordinary-binding",
    "property": "Ordinary executor qualification/binding regression",
    "entry": "packages/execution/checks/mechanisms.mjs",
    "expectedSha256": "fcd2a75fd42995da24f040b0ec0838dd129e793e0373aaff9202dd5f6f1228de",
    "protocol": "pass-lines",
    "requiredLabels": [
      "bash_parameters"
    ],
    "args": [
      "bash_parameters"
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": [],
    "timeoutMs": 15000
  },
  {
    "id": "full-pilot-capture",
    "property": "Full source owner-memory suite: pilot-capture",
    "entry": "packages/runtime-bridge/test/pilot-capture.test.mjs",
    "expectedSha256": "ff8be761ea81bc0b0b2787d1535bc77bb58371fe5737e050907a075e462d338d",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "statement-only pilot capture preserves the exact literal and fixes metadata from source time",
      "pilot capture returns detached immutable copies",
      "older pilot callers may provide the exact fixed metadata",
      "pilot capture refuses a caller category override",
      "pilot capture refuses a caller validFrom override",
      "pilot capture refuses a caller observedAt override",
      "pilot capture refuses a caller confidence override",
      "pilot capture refuses a caller sensitivity override",
      "pilot capture refuses links outside its closed input grammar"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "full-workflow-store",
    "property": "Full source owner-memory suite: workflow-store",
    "entry": "packages/runtime-bridge/test/workflow-store.test.mjs",
    "expectedSha256": "27d83a5731e7d2c26a892d3359c3c1603072657b6df350e5120e27705af00cd8",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "workflow references migrate explicitly and survive a new store instance without retaining payloads",
      "owner attempt admission spans tasks and known-unsent closes the retained proposal",
      "active references refuse overflow while recent history is bounded and exact lookup stays available"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "full-owner-memory-workflow",
    "property": "Full source owner-memory suite: owner-memory-workflow",
    "entry": "packages/runtime-bridge/test/owner-memory-workflow.test.mjs",
    "expectedSha256": "f47516004d3433b0f6d2428e5d030c583e78ca4d66dd1857dc2739fbc2c3464f",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "real owner workflow retains the exact paired literal and coalesces approval/save clicks into one D effect",
      "a real committed save with a lost delivered reply remains unknown and cannot be automatically replayed",
      "a real D database interruption after dispatch consumes authority and never grants a save retry",
      "real saved bytes and receipt survive a C settlement delivery interruption; refresh performs only reads",
      "a failed real memory.cite reply preserves the confirmed save receipt and can recover through read-only refresh",
      "a failed real memory.status reply preserves the confirmed save receipt and can recover through read-only refresh",
      "logout while the real approval reply is held prevents a stale-session save dispatch",
      "owner workflow refuses closed-draft owner_id smuggling before proposal or approval",
      "owner workflow refuses closed-draft source smuggling before proposal or approval",
      "owner workflow refuses closed-draft expected_state_version smuggling before proposal or approval",
      "a real source change after review cannot apply the approved draft or authorize a retry",
      "an altered operation_id in a genuine saved receipt cannot become confirmed workflow state",
      "an altered grant_id in a genuine saved receipt cannot become confirmed workflow state",
      "saved and searchable remain independent until an explicit test-only D index drain and read-only refresh",
      "logout before the scheduled proposal microtask makes no old call and releases the proposal flight",
      "logout before the scheduled approval microtask makes no old decision and releases the action flight",
      "a workflow observer logout during save_pending prevents the real save invocation without inventing uncertainty",
      "confirmed real save facts survive logout while status/cite replies are held with settlement completed",
      "confirmed real save facts survive logout while status/cite replies are held with settlement pending",
      "a workflow observer dispose during save_pending prevents the real save invocation without inventing uncertainty",
      "confirmed real save facts survive dispose while status/cite replies are held with settlement completed",
      "confirmed real save facts survive dispose while status/cite replies are held with settlement pending",
      "logout from the index update observer cannot publish the old citation into a cleared owner snapshot",
      "the browser contract exports drive a full real B/C/D owner workflow with the same frozen v1 operation digest",
      "a finished unknown save retains content-free uncertainty through logout and subsequent disposal",
      "a finished confirmed save with pending settlement retains its content-free facts through logout and subsequent disposal",
      "logout from the controller operation notification cannot resurrect the proposed owner capture and permits a fresh proposal"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "full-owner-memory-hook",
    "property": "Full source owner-memory suite: owner-memory-hook",
    "entry": "packages/runtime-bridge/test/owner-memory-hook.test.mjs",
    "expectedSha256": "72a2e74dca0cfef62b3e59db6b4f07fee0fa45f3e86588c0ceee74595eed5aa0",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "external B submitApproval joins the exact owner literal to a genuine C/D saved receipt, citation and pending index",
      "external B hook coalesces duplicate and reentrant owner submissions into one actual C approval and D effect",
      "external B hook preserves unknown after a genuine D save reply is lost and blocks automatic replay",
      "detaching the external B hook while the genuine C approval reply is held prevents any D save",
      "detaching the external B hook while a genuine applied D save reply is held preserves unknown without replay",
      "external B logout before the hook microtask releases its flight and permits fresh login and review",
      "external B detach before the hook microtask releases its flight and permits fresh login and review",
      "disposing the external B controller from the save_pending observer prevents the known unsent D save",
      "external B logout during confirmed saved read replies permits fresh login and review without a mutation block",
      "external B logout from save_pending before invocation permits fresh login and review without a mutation block"
    ],
    "externalSkips": [],
    "hookController": {
      "path": "packages/ui/prime-authority/src/client/controller.mjs",
      "sha256": "b0204bc9068c90bc94dc53dc9d75560c2c7ad52547ccd8ccbd64ea1f27668733"
    },
    "pins": [
      {
        "path": "packages/ui/adapters/transport.mjs",
        "sha256": "9b28b62d2f7d8ec29823096e0d904ca9f3161d52238794a30cbb723c2f81215c"
      },
      {
        "path": "packages/ui/adapters/passkey.mjs",
        "sha256": "ba0da18d1ae90a0b63590cf0d07c69c1edb0ab90a90c9de0d8c455a685a43b9b"
      },
      {
        "path": "packages/ui/adapters/capture-review.mjs",
        "sha256": "d82eda5f8ae0fefa02f182fac80480d82a7c88fd6148beadabde5cd8480472d7"
      },
      {
        "path": "packages/ui/adapters/capture-metadata.mjs",
        "sha256": "819b14e2062d58fd0b341cacd3e1462a51250ee2af16556b66a5f685b92fa365"
      },
      {
        "path": "packages/ui/adapters/forget-review.mjs",
        "sha256": "ea7af48be61f542bedd73e2058babf36505c44ad6a810ed64472765092cc6662"
      },
      {
        "path": "packages/ui/adapters/forget-result.mjs",
        "sha256": "944ef4189f3a9836b0500f22f57449b4e28a73644b4c3b7bd7a6108ede21e6b4"
      },
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      },
      {
        "path": "packages/ui/prime-authority/checks/fixture.mjs",
        "sha256": "9de910efeb78e9c19d823ced453eafc8217838a00337f7df36b84d9e68e62822"
      },
      {
        "path": "packages/runtime-bridge/test/owner-memory-fixture.mjs",
        "sha256": "0f3fd76142bf4fa8e0bd04a2a9c60261eadf7bcc50dc8445639b9b33e9df99fa"
      },
      {
        "path": "packages/ui/adapters/save-recovery.mjs",
        "sha256": "cdd5ad90f6274365a431e2423ecde60c9faea560987dcd666da460c304fee0e9"
      }
    ],
    "args": []
  },
  {
    "id": "full-owner-memory-host",
    "property": "Full source owner-memory suite: owner-memory-host",
    "entry": "packages/runtime-bridge/test/owner-memory-host.test.mjs",
    "expectedSha256": "3a05ed078a9c9ecd03625f2af55c8bbdd280c91ecf1e666b9ea4d8a80703c451",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "current H HTTP factories reject closed Host/Origin and malformed bounded input before dispatch",
      "current H browser performs one fetch and reports lost mutation replies as unknown without replay",
      "current H HTTP disconnect does not abort or replay an already submitted call",
      "current H context derives immutable owner/task/source binding from its configured IPC credential",
      "current B submitApproval and H byte factories carry one real C/D literal save through an explicit test-only boundary",
      "current H HTTP/IPC boundary refuses actual unqualified public and internal workers before C or SQL"
    ],
    "externalSkips": [],
    "hostRoot": true,
    "pins": [
      {
        "path": "harness/owner-memory-browser.mjs",
        "sha256": "2575969db8ffdffd5e5cd937aa0b5dc150bf912798adbadbe9dac6021302c7a5"
      },
      {
        "path": "harness/owner-memory-transport.mjs",
        "sha256": "d091daff12a064b650814d9dea44aa6785308a59e3e6be8d3a1805ee2043a4b9"
      },
      {
        "path": "harness/owner-memory-ipc.mjs",
        "sha256": "2871743e788b6ef840e30f8139ba9a6d70dd681d314f12c0c0dc4edb00a9cbc8"
      },
      {
        "path": "harness/owner-memory-context.mjs",
        "sha256": "d4da90193ecdc0c48bc48b5267fca05e2f0b5e3aeed34ef4ab317fde3109e6d3"
      },
      {
        "path": "packages/contracts/src/runtime.mjs",
        "sha256": "d42ec191f52279b4af33ad23edb1518425817ac89e70a80955d0c0266386be12"
      }
    ],
    "args": []
  },
  {
    "id": "full-owner-memory-facade",
    "property": "Full source owner-memory suite: owner-memory-facade",
    "entry": "packages/runtime-bridge/test/owner-memory-facade.test.mjs",
    "expectedSha256": "8a5e95407487fbd7ad68cede170f14bc135b921d7db770e675e78605370502ba",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      },
      {
        "path": "packages/ui/prime-authority/src/client/controller.mjs",
        "sha256": "b0204bc9068c90bc94dc53dc9d75560c2c7ad52547ccd8ccbd64ea1f27668733"
      },
      {
        "path": "harness/owner-memory-client.mjs",
        "sha256": "5e0d315a02a888f12ca15680d7d1625fff0657c69566c45d61f81ec5b2cafb81"
      },
      {
        "path": "harness/owner-memory-transport.mjs",
        "sha256": "d091daff12a064b650814d9dea44aa6785308a59e3e6be8d3a1805ee2043a4b9"
      },
      {
        "path": "harness/owner-memory-host.mjs",
        "sha256": "a20d847458ee2311faaa925f90be77cd63308b1f07463539f995878287eaf900"
      },
      {
        "path": "packages/runtime-bridge/test/owner-memory-fixture.mjs",
        "sha256": "0f3fd76142bf4fa8e0bd04a2a9c60261eadf7bcc50dc8445639b9b33e9df99fa"
      },
      {
        "path": "packages/runtime-bridge/test/owner-memory-recovery-continuation.mjs",
        "sha256": "a4a4b509bb02e18a155a9875680ddf54f27bcff3b29b8325e11309bb2150128a"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "H client generic hooks save, read, forget and save again with actual C/D",
      "H client logs out durably, signs in again, and saves through the same binding",
      "H same-controller recovered receipt is displayed and permits a new unrelated approved save without repeating the old effect",
      "H new binding recovers an actual lost-save receipt after cold C/D objects without another signature or save",
      "H host without a qualified channel remains unavailable before actual C/D",
      "H new binding recovers a reviewed unsent proposal and requires a fresh review",
      "H pending settlement recovery sends only the actual retained receipt after new login and cold objects",
      "H lost forget reply recovers the genuine tombstone receipt on a new binding without another effect",
      "H lost logout reply ends local access, does not redispatch, and permits an ordinary fresh login"
    ],
    "externalSkips": [],
    "syntheticSourcePin": true
  },
  {
    "id": "full-owner-recovery",
    "property": "Full source owner-memory suite: owner-recovery",
    "entry": "packages/runtime-bridge/test/owner-recovery.test.mjs",
    "expectedSha256": "7c7b1c90c46572f423ed04e80fa95b5e792af4d744a4b1a9ad4958bcaf40d854",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "remount after a lost actual save reply recovers its genuine completed receipt without another effect",
      "a reviewed proposal with no save recovers as known unsent and permits a fresh idempotency key",
      "recovery with restored C settlement delivery resends only the actual committed receipt",
      "a durable dispatched intent without an effect remains unknown after remount and blocks a fresh proposal"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "full-owner-logout",
    "property": "Full source owner-memory suite: owner-logout",
    "entry": "packages/runtime-bridge/test/owner-logout.test.mjs",
    "expectedSha256": "be6b01b578ae241c6543c78732e44f3496f5d56c272ae7bfc6c797b67b691083",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "workflow logout clears the local owner immediately and sends one durable C logout even while its reply is held",
      "an old approved review cannot reserve after actual logout, including after a new ordinary login",
      "logout retains a dispatched D receipt and a new ordinary session recovers factual settlement without repeating the effect",
      "a lost genuine logout reply leaves local access cleared and reports unknown while C durably rejects the old token"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "full-owner-forget",
    "property": "Full source owner-memory suite: owner-forget",
    "entry": "packages/runtime-bridge/test/owner-forget.test.mjs",
    "expectedSha256": "2a4cfa61cb68301bd72100a54d3544d71385a967820213c16d41f126cdda8a79",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "statement-only pilot save followed by an actual owner-approved forget returns the genuine receipt and excludes the logically tombstoned record",
      "a real applied logical forget retains its receipt when C settlement delivery is pending and never repeats the effect",
      "a lost logical-forget reply after the actual effect leaves the caller uncertain and blocks actor replay"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "full-owner-forget-workflow",
    "property": "Full source owner-memory suite: owner-forget-workflow",
    "entry": "packages/runtime-bridge/test/owner-forget-workflow.test.mjs",
    "expectedSha256": "7ab96f36a83e934a582434b279adf4cfd1fb950d74b7f66944424f996468d0be",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "coalesced owner approval forgets once with the exact signed literals and genuine D receipt",
      "a lost actual forget reply recovers after server object remount without another effect or signature",
      "an unsent forget recovers as known unsent and requires a fresh proposal and review"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "full-ui-controller",
    "property": "Full B source owner suite: controller",
    "entry": "packages/ui/prime-authority/checks/controller.mjs",
    "expectedSha256": "04649ae9cd3514e8623e765a95c9d56d422b66fe96f7290f91007f2c630ef8f0",
    "protocol": "assert-json",
    "timeoutMs": 15000,
    "args": [
      "packages/contracts/src/browser.mjs"
    ],
    "counter": {
      "key": "cases",
      "value": 11
    },
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      },
      {
        "path": "packages/ui/prime-authority/checks/fixture.mjs",
        "sha256": "9de910efeb78e9c19d823ced453eafc8217838a00337f7df36b84d9e68e62822"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-ui-approval-action",
    "property": "Full B source owner suite: approval-action",
    "entry": "packages/ui/prime-authority/checks/approval-action.mjs",
    "expectedSha256": "f73c758ceb9f03a3e8931e9aada132d919a11f55fdc97c5df9ea7dbb011d3a20",
    "protocol": "assert-json",
    "timeoutMs": 15000,
    "args": [
      "packages/contracts/src/browser.mjs",
      "packages/runtime-bridge/src"
    ],
    "counter": {
      "key": "cases",
      "value": 20
    },
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      },
      {
        "path": "packages/ui/prime-authority/checks/fixture.mjs",
        "sha256": "9de910efeb78e9c19d823ced453eafc8217838a00337f7df36b84d9e68e62822"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-ui-logout",
    "property": "Full B source owner suite: logout",
    "entry": "packages/ui/prime-authority/checks/logout.mjs",
    "expectedSha256": "6dfcb646d2e3c493c4d9c39a81b70dc9cf38d68d0be0ad05c0b3a409b36e30c5",
    "protocol": "assert-json",
    "timeoutMs": 15000,
    "args": [
      "packages/contracts/src/browser.mjs"
    ],
    "pins": [
      {
        "path": "packages/ui/adapters/transport.mjs",
        "sha256": "9b28b62d2f7d8ec29823096e0d904ca9f3161d52238794a30cbb723c2f81215c"
      },
      {
        "path": "packages/ui/prime-authority/src/client/controller.mjs",
        "sha256": "b0204bc9068c90bc94dc53dc9d75560c2c7ad52547ccd8ccbd64ea1f27668733"
      },
      {
        "path": "packages/ui/prime-authority/checks/fixture.mjs",
        "sha256": "9de910efeb78e9c19d823ced453eafc8217838a00337f7df36b84d9e68e62822"
      },
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      }
    ],
    "counter": {
      "key": "cases",
      "value": 35
    },
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-ui-forget-review",
    "property": "Full B source owner suite: forget-review",
    "entry": "packages/ui/prime-authority/checks/forget-review.mjs",
    "expectedSha256": "01d735fe0f29b7ff6c1300dc2da938a8a57a0dade8e57bae9a28099401770149",
    "protocol": "assert-json",
    "timeoutMs": 15000,
    "args": [],
    "pins": [
      {
        "path": "packages/ui/adapters/forget-review.mjs",
        "sha256": "ea7af48be61f542bedd73e2058babf36505c44ad6a810ed64472765092cc6662"
      }
    ],
    "counter": {
      "key": "assertions",
      "value": 95
    },
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-ui-forget-result",
    "property": "Full B source owner suite: forget-result",
    "entry": "packages/ui/prime-authority/checks/forget-result.mjs",
    "expectedSha256": "007bc67d92df011c32781b8287ce2a31270f38c3c74a31f592caa96b59d45ddb",
    "protocol": "assert-json",
    "timeoutMs": 15000,
    "args": [
      "packages/contracts/src/browser.mjs"
    ],
    "pins": [
      {
        "path": "packages/ui/adapters/forget-result.mjs",
        "sha256": "944ef4189f3a9836b0500f22f57449b4e28a73644b4c3b7bd7a6108ede21e6b4"
      },
      {
        "path": "packages/ui/prime-authority/checks/fixture.mjs",
        "sha256": "9de910efeb78e9c19d823ced453eafc8217838a00337f7df36b84d9e68e62822"
      },
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      }
    ],
    "counter": {
      "key": "cases",
      "value": 102
    },
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-ui-forget-controller",
    "property": "Full B source owner suite: forget-controller",
    "entry": "packages/ui/prime-authority/checks/forget-controller.mjs",
    "expectedSha256": "f112bb6fc58bb6e42c326b05ab5c2eda073a718e63410dc0e7296b149b09cdad",
    "protocol": "assert-json",
    "timeoutMs": 15000,
    "args": [
      "packages/contracts/src/browser.mjs"
    ],
    "pins": [
      {
        "path": "packages/ui/prime-authority/src/client/controller.mjs",
        "sha256": "b0204bc9068c90bc94dc53dc9d75560c2c7ad52547ccd8ccbd64ea1f27668733"
      },
      {
        "path": "packages/ui/prime-authority/checks/fixture.mjs",
        "sha256": "9de910efeb78e9c19d823ced453eafc8217838a00337f7df36b84d9e68e62822"
      },
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      }
    ],
    "counter": {
      "key": "groups",
      "value": 12
    },
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-ui-owner-recovery",
    "property": "Full B genuine receipt-bound controller recovery",
    "entry": "packages/ui/prime-authority/checks/ordinary-recovery.test.mjs",
    "expectedSha256": "52f03aa475cba8bbb9b9d2c6bdf6d0ccdc9702e8a55945878bbd09d70cc35a37",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      },
      {
        "path": "packages/runtime-bridge/test/owner-memory-fixture.mjs",
        "sha256": "0f3fd76142bf4fa8e0bd04a2a9c60261eadf7bcc50dc8445639b9b33e9df99fa"
      },
      {
        "path": "packages/ui/prime-authority/src/client/controller.mjs",
        "sha256": "b0204bc9068c90bc94dc53dc9d75560c2c7ad52547ccd8ccbd64ea1f27668733"
      },
      {
        "path": "packages/runtime-bridge/src/owner-forget-workflow.mjs",
        "sha256": "34120f7e8af0a46781f897de5d4f49355836f23a0e5a04da6505cd001cd1c823"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "same controller ingests a genuine recovered lost-save receipt and resumes a fresh save",
      "same controller clears pending settlement only after the genuine retained receipt completes",
      "a verified completed receipt resolves an expired old review while the owner session remains live",
      "same controller ingests a genuine lost logical-forget receipt and resumes a fresh save"
    ],
    "externalSkips": []
  },
  {
    "id": "full-h-owner-memory-client",
    "property": "Full H owner-memory assembly: client",
    "entry": "harness/check-owner-memory-client.mjs",
    "expectedSha256": "78352d5adaa942a154a316379911050770c9d6e610ce70b07de4d57d310953a3",
    "protocol": "assert-json",
    "timeoutMs": 30000,
    "args": [],
    "counter": {
      "key": "checks",
      "value": 55
    },
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-h-owner-memory-context",
    "property": "Full H owner-memory assembly: context",
    "entry": "harness/check-owner-memory-context.mjs",
    "expectedSha256": "f5fbd6f877ae4eeed31a1cb02e2982150407a83d067c1fe318326a912c63a516",
    "protocol": "assert-json",
    "timeoutMs": 30000,
    "args": [],
    "counter": {
      "key": "checks",
      "value": 35
    },
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-h-owner-memory-transport",
    "property": "Full H owner-memory assembly: transport",
    "entry": "harness/check-owner-memory-transport.mjs",
    "expectedSha256": "0d8dba27a780c0044258f08e2565eefcfb360be4c169982b51614b519e97cc38",
    "protocol": "assert-json",
    "timeoutMs": 30000,
    "args": [],
    "counter": {
      "key": "checks",
      "value": 52
    },
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "full-h-owner-memory-recovery",
    "property": "Full H owner-memory assembly: recovery",
    "entry": "harness/check-owner-memory-recovery.mjs",
    "expectedSha256": "9658be3a547b94bfb3687d236185d15f969a1351bbe03e793ddbe65dc9bebc69",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [
      {
        "path": "packages/contracts/src/browser.mjs",
        "sha256": "645ad722f75db61f99008661af54ced496177f6d90a099c86b0169d08cf0d183"
      },
      {
        "path": "packages/ui/prime-authority/src/client/controller.mjs",
        "sha256": "b0204bc9068c90bc94dc53dc9d75560c2c7ad52547ccd8ccbd64ea1f27668733"
      },
      {
        "path": "harness/owner-memory-client.mjs",
        "sha256": "5e0d315a02a888f12ca15680d7d1625fff0657c69566c45d61f81ec5b2cafb81"
      },
      {
        "path": "harness/owner-memory-transport.mjs",
        "sha256": "d091daff12a064b650814d9dea44aa6785308a59e3e6be8d3a1805ee2043a4b9"
      },
      {
        "path": "packages/runtime-bridge/test/owner-memory-fixture.mjs",
        "sha256": "0f3fd76142bf4fa8e0bd04a2a9c60261eadf7bcc50dc8445639b9b33e9df99fa"
      },
      {
        "path": "packages/runtime-bridge/test/owner-memory-recovery-continuation.mjs",
        "sha256": "a4a4b509bb02e18a155a9875680ddf54f27bcff3b29b8325e11309bb2150128a"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "H recovered actual save updates the same B controller and permits one unrelated new save",
      "H awaits B reconciliation and passes the exact workflow snapshot without rewriting it",
      "H recovered actual forget updates the same B controller without repeating forget",
      "H unknown recovery keeps the retained action fenced and refuses a new save",
      "H propagates a rejected reconciliation hook without retrying approval or effect",
      "H rejects a controller without its reconciliation method before attachment"
    ],
    "externalSkips": []
  },
  {
    "id": "full-expanded-review-join",
    "property": "Full raw Bridge expanded capture, genuine approval/save and refused input",
    "entry": "packages/runtime-bridge/test/expanded-review-join.test.mjs",
    "expectedSha256": "2aee95c3112fce3af80139c501023d672794001c834a4ed7dbadb2a24160ccd4",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "raw bridge expanded capture binds four independent review fields, seven parameters and actual P-256 approval to a genuine saved receipt and exact retry",
      "ordinary NFD and refused-format new statements or selected source quotes fail before SQL, intent or authority consumption"
    ],
    "externalSkips": []
  },
  {
    "id": "full-invocation-forget-join",
    "property": "Full native B scoped forget invocation through actual C/D",
    "entry": "packages/runtime-bridge/test/invocation-forget-join.test.mjs",
    "expectedSha256": "425877cab8c300fc9c053f05b93524c15887269fc4ee5eec65aa43f680ab1b96",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "pinned B private forget invocation coalesces submissions and rejects concurrent public approval before one genuine logical forget"
    ],
    "externalSkips": []
  },
  {
    "id": "full-owner-capacity",
    "property": "Full actual owner-session save capacity above sixteen",
    "entry": "packages/runtime-bridge/test/owner-capacity.test.mjs",
    "expectedSha256": "7267aee211374fbfd70957222cb3881beb8fe21ee139b6ee48d53292da6db86e",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "one owner session completes 17 genuine saves and repeats its latest completion without another effect"
    ],
    "externalSkips": []
  },
  {
    "id": "full-owner-save-retry",
    "property": "Full exact saved receipt retry and pending settlement refusal",
    "entry": "packages/runtime-bridge/test/owner-save-retry.test.mjs",
    "expectedSha256": "0d279027325222de6d47f6fa5bd7a5368e216a4e15d1ec111772fc0f2ceb12ba",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "an exact successful save retry returns the same genuine receipt before advanced heads, including after server restart",
      "retry of a genuinely saved but unsettled operation refuses until actual receipt recovery, then returns the original effect"
    ],
    "externalSkips": []
  },
  {
    "id": "full-pre-reservation-unknown",
    "property": "Full factual unresolved pre-reservation refusal fence (W1 still blocked)",
    "entry": "packages/runtime-bridge/test/pre-reservation-unknown.test.mjs",
    "expectedSha256": "bb7f3974352e61ea5364c63458e238a088c7c80c000e2ea99abe3f3638f214bb",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "a real pre-reservation refusal leaves an attempted journal unresolved despite no C consumption or D intent"
    ],
    "externalSkips": []
  },
  {
    "id": "full-ui-capture-review",
    "property": "Full B expanded capture policy and exact independent review",
    "entry": "packages/ui/prime-authority/checks/capture-review.test.mjs",
    "expectedSha256": "4116df5b7e4a2d582a02de44cfb30ba56f0f1b6773b420fe322eb78a3789d193",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "expanded NEW-capture draft preserves exact four fields and independent metadata",
      "missing and changed metadata or quote refuse before challenge and signer",
      "NEW-capture text policy rejects defined controls, fillers and non-NFC without replacing input",
      "NFC languages, confusable letters and joiners remain exact permitted NEW-capture text",
      "historical forget review retains exact original NFD bytes and script text"
    ],
    "externalSkips": []
  },
  {
    "id": "full-ui-expanded-transport",
    "property": "Full B expanded transport and saved-content consistency",
    "entry": "packages/ui/prime-authority/checks/expanded-transport.test.mjs",
    "expectedSha256": "6dd0bb3c72d63b53be39c7d7222a9d37fa9d6ddc20ea24774c9e23d4d5c9d816",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "expanded independent draft is mandatory and all four fields bind before authority review",
      "optional old metadata sibling cannot replace or disagree with independent reviewed metadata",
      "expanded review snapshot is detached before challenge wait and survives caller mutation through signing",
      "saved content equals every reviewed metadata value and exact selected source evidence without byte rewriting"
    ],
    "externalSkips": []
  },
  {
    "id": "full-ui-ordinary-hook",
    "property": "Full B native approval invocation race through actual C/D",
    "entry": "packages/ui/prime-authority/checks/ordinary-hook.test.mjs",
    "expectedSha256": "8432e1dd0b9ea365fc6b18f0183d8a52c0e4e363f6ba99dce289b15076274fd3",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "pins": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "ordinary native raw approve cannot preempt a synchronously reserved hook",
      "ordinary native raw approve cannot steal a held genuine hook approval proof"
    ],
    "externalSkips": []
  },
  {
    "id": "memory-control-retention-advance",
    "property": "Whole memory source assertions: control-retention-advance",
    "entry": "packages/memory/test/control-retention-advance.test.mjs",
    "expectedSha256": "76b1a8f8f07304b8be9dad99963623e3e84909ece0b447acc1093ea67d8efb19",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "exact state and valid supersets retain all old control rows and return no authority",
      "retained purge, idempotency, tombstone, redaction and fence rows cannot disappear or change",
      "head domains and control scopes remain; valid control changes require changed heads",
      "unresolved historical intents stay exact when completed or retained alongside new operations",
      "completed payload rows clear only to a fence with the exact old replay bindings",
      "previous completed effects and existing content-free fences remain exact in later supersets"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "memory-control-retention-integration",
    "property": "Whole memory source assertions: control-retention-integration",
    "entry": "packages/memory/test/control-retention-integration.test.mjs",
    "expectedSha256": "7f8015d3c3890fbb87668ddbcfb0cbfe39f0ba51910d5ee312fc2405372142bf",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "constructor defaults to explicitly unavailable retained control state",
      "default restore preparation fails closed before storage for the exact current host",
      "arbitrary control retention object is rejected before its callback can run",
      "legacy restore provider must be a function rather than a boolean",
      "legacy function and branded retained control reader cannot be configured together"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "memory-control-retention",
    "property": "Whole memory source assertions: control-retention",
    "entry": "packages/memory/test/control-retention.test.mjs",
    "expectedSha256": "13b0c66dd704555a5e7e78b7e6f2dc8e3c8ca43b7dbbf47049f323aa4e9c4680",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "unconfigured reader is branded and fails closed; publisher and arbitrary callbacks are unbranded",
      "empty bootstrap durably publishes a closed owner-bound checkpoint and reader returns that full envelope",
      "bootstrap refuses heads or control rows and leaves no authoritative pointer",
      "publication requires exact checkpoint CAS, retains durable rows, and binds a nondecreasing current epoch",
      "role identity and protected preexisting canonical directory are enforced on every call",
      "current and generation files reject links, permission changes and noncanonical serialization",
      "generation digest and closed pointer binding refuse changes without importing or normalizing data",
      "existing lock remains owned by its creator and an uncertain pointer commit does not auto retry",
      "durable pending markers block reads across publisher instances until a matching retained operation is published",
      "v2 marker precedes preparation; exact scoped observation preserves the predecessor until actual final publication",
      "v2 preparation and final publication require the exact committed intent and preserve unresolved replay state",
      "v1 markers cannot grant v2 scoped observation or bypass the prepared mutation stage",
      "v2 final pointer uncertainty leaves the marker; fresh factual completion requires the exact existing final bytes"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "memory-control-state",
    "property": "Whole memory source assertions: control-state",
    "entry": "packages/memory/test/control-state.test.mjs",
    "expectedSha256": "67f4d4b2614e8dbcf5f8dff602e154e59c21f3e4be7bbf1f94339844d86975b4",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "versioned complete empty control state is explicit; heads-only and snapshot objects refuse",
      "control anchor preserves exact original bytes and retained requests for purged records",
      "maker deterministically orders table primary keys without normalizing stored bytes",
      "owner subject, owner identity, row binding and bundle digests fail closed independently",
      "byte digests, canonical base64 and duplicate primary keys are checked even under a recomputed bundle digest",
      "purge, redaction, tombstone and control vocabularies are closed and referentially bound",
      "unresolved intents and completed effects preserve exact request, operation and grant bytes",
      "historical operation owner binding survives a recomputed operation and outer digest",
      "request parameters and grant identity must join the durable operation",
      "effects require exact intent bytes and a closed matching result receipt",
      "content-free fences remain portable while blocking collisions with retained intents or grants",
      "untrusted accessors, proxies, extra fields and cycles refuse without running getters"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "memory-memory",
    "property": "Whole memory source assertions: memory",
    "entry": "packages/memory/test/memory.test.mjs",
    "expectedSha256": "b4388ffb8ec2f0c65a288d865fcbe50fc87b0efd235797c8415ab9f25a44a50c",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "synthetic durable capture, honest ACKs, owner filters, restart, import and Prime-only cold restore",
      "Diamond separate-process consumer checks synthetic signed evidence and retains its numeric/profile limits",
      "preserved decimal v0, safe-integer v1, UNLINKED, pre-split chains and quarantine never mint new IDs",
      "authorized save settlement/restart, omission mutations, redacted restore and explicit active-table purge",
      "literal capture review refuses coercion and invisible controls without changing the independent draft",
      "three concurrent identical approved saves coalesce exactly once; signed literal tampering refuses before reserve",
      "unsafe or non-NFC new statement and selected quote refuse before SQL or authority consumption",
      "approved logical forget forbids new or replayed full backups; exact per-record purge retains unrelated memory",
      "purge refuses shared evidence or unresolved payload intents before reserving a grant",
      "restore uses independent current anchors and preflights local forks before consumption",
      "cold restore retains owner-bound idempotency, committed receipts and unresolved intents without dispatch retry",
      "atomic retained participant orders reservation, dispatch and settlement; cold read works while restore is disabled",
      "atomic retained profile refuses each missing retained authority method before marker or legacy reservation",
      "atomic retention keeps reserve-reply uncertainty fenced without effect retry",
      "atomic retention keeps prepared-commit uncertainty fenced without effect retry",
      "atomic retention keeps prepared-reply uncertainty fenced without effect retry",
      "atomic retention keeps dispatch-reply uncertainty fenced without effect retry",
      "atomic retention keeps effect-commit uncertainty fenced without effect retry",
      "atomic retention keeps publication-before uncertainty fenced without effect retry",
      "atomic retention keeps publication-reply uncertainty fenced without effect retry",
      "atomic retention keeps truthy-beginMutation uncertainty fenced without effect retry",
      "atomic retention keeps truthy-retainPrepared uncertainty fenced without effect retry",
      "atomic retention keeps truthy-publishMutation uncertainty fenced without effect retry",
      "independent purge control anchor blocks old data in an empty store and retains content-free replay fences",
      "new capture defaults refuse invisible policy changes before reserve and approved forget exposes its actual settlement"
    ],
    "externalSkips": [
      {
        "title": "PostgreSQL acceptance on an explicitly supplied disposable database",
        "reason": "UNPERFORMED: no disposable PostgreSQL runtime supplied"
      }
    ],
    "args": [],
    "pins": []
  },
  {
    "id": "memory-operator-postgres",
    "property": "Whole memory source assertions: operator-postgres",
    "entry": "packages/memory/test/operator-postgres.test.mjs",
    "expectedSha256": "6ebe5b5820d34452dec1accfef518d0780ef491e29f867bfabb20bc3f4d1a2ca",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "operator configuration permits only the explicitly supplied synthetic socket profile",
      "operator help and argument refusals happen before any driver or PostgreSQL use",
      "plan produces a closed source-only state and exact operator schema plan without pg",
      "schema lifecycle plans grant only exact operator-owned schemas and require scoped operator drop",
      "prepare refuses absent, unplanned, unknown, or retargeted state before pg",
      "prepare refuses a changed schema lifecycle plan before any pg driver use",
      "cleanup-plan refuses unverified or unplanned state before pg; no runner drop command exists"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "memory-pilot-capture",
    "property": "Whole memory source assertions: pilot-capture",
    "entry": "packages/memory/test/pilot-capture.test.mjs",
    "expectedSha256": "61d15df2b80d7fd1fb5b9f82130c6f8cf788d4fd949606c1ed44bb63c563ddf3",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "new pilot metadata uses documented fixed defaults and does not rewrite input or host",
      "pilot metadata rejects hidden extraction policy changes and malformed closures",
      "pilot host cannot override scope, evidence, body, origin, or source provenance shape",
      "reviewed attribution stays explicit and new NFC Unicode spelling remains exact",
      "capture review binds the exact six metadata fields and evidence quote to a retained draft",
      "capture metadata is a closed literal profile with canonical date and UTC seconds",
      "review refuses hidden draft getters and non-string digest or head values without coercion",
      "new statement and evidence quote refuse unsafe formatting, filler, separators, and malformed Unicode without rewriting",
      "presentation warnings identify exact UTF-16 positions and code points without altering text",
      "presentation hints remain exact for historical text while new capture enforces NFC without blocking languages"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "memory-worker-postgres-fixture",
    "property": "Whole memory source assertions: worker-postgres-fixture",
    "entry": "packages/memory/test/worker-postgres-fixture.test.mjs",
    "expectedSha256": "d94059eb1f7bee6b9310cf576316dcdd78a3c133b0846c8a029ff2487d2c5e83",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "worker planning has two distinct synthetic identities and no keys, proofs, or IPC secrets",
      "worker schema plan keeps generic operator marker and exact scoped role privileges",
      "worker fixture validates closed scalar shape and exact config, schemas, owners, and plan binding",
      "worker factories refuse TCP, passwords, external target, and unplanned schema before pg",
      "worker factories require matching real/effective memory UID and refuse PG environment before pg",
      "save expectation accepts strict immutable bindings for either fixture owner without verifying C",
      "save expectation refuses coercible digests, unclosed content, invalid owner, and mismatched receipt settlement",
      "worker verification refuses a caller-supplied fake pool before driver or query",
      "pure worker create/drop plans retain exact generic operator schema and marker closure",
      "capture helper matches documented decimal-bearing golden preimage for both distinct owners",
      "capture hashes bind extraction, source fields, exact event bytes, and idempotency independently",
      "capture helper refuses wrong identities, nonfixed profiles, changed source hashes, malformed literals, and accessors"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-deployed-fixture",
    "property": "Whole runtime-bridge source assertions: deployed-fixture",
    "entry": "packages/runtime-bridge/test/deployed-fixture.test.mjs",
    "expectedSha256": "4c7fed8e66956e761725e94d8c4d6f051857fda6c0a278f286a46e5a3b736da6",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "fixture actor/controller completes actual C/D save and all retained phases with cold C and SQLite stores; no deployed acceptance",
      "bootstrap builders bind only the fixed synthetic profile and closed owner channel associations",
      "controller refuses changed D capture, idempotency, task, target, heads and attribution before signing",
      "controller recomputes C challenge/options and binds the entire reviewed proposal and proof template before releasing an assertion",
      "controller refuses a malformed login version even when caller recomputes its WebAuthn challenge",
      "controller refuses changed completion, receipt and control evidence and preserves the retained expectation on restart",
      "a failed durable counter write releases no assertion and does not complete the signing phase"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-deployed-lifecycle",
    "property": "Whole runtime-bridge source assertions: deployed-lifecycle",
    "entry": "packages/runtime-bridge/test/deployed-lifecycle.test.mjs",
    "expectedSha256": "046278a1eddb8b27d34b26ae1a43cee3abb5947049b8083be6a2855567a1ac56",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "phase lock reads current counters and admission before durably allowing one launch",
      "uncertain disable marker prevents signing even when private key state remains present",
      "SSH launch is pinned to protected app actor, exact host and strict existing authentication",
      "protected SSH approval has a closed controller, host and path grammar",
      "spawn errors are handled and stalled local SSH child exit is bounded with escalation"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-deployed-pipes",
    "property": "Whole runtime-bridge source assertions: deployed-pipes",
    "entry": "packages/runtime-bridge/test/deployed-pipes.test.mjs",
    "expectedSha256": "2d91ef86d5fd07d6a17cb7730e2c7d23a8ddbd627fb3ed4572357dcbc3f57265",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "strict LF peer exchanges detached object payloads and consecutive sequences",
      "closed frames reject duplicate fields, trailing garbage, pollution keys, controls and invalid UTF-8",
      "oversize partial input and encoded output are refused before further allocation or output",
      "request replay, skipped sequence, overlapping requests and wrong respond sequence close the peer",
      "responses require one matching pending request; local concurrent calls never resend",
      "read, request, partial frame and delivered-request deadlines are absolute; EOF never resends",
      "bounded frame count, simultaneous reads and stalled response writes cannot retain resources forever"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-deployed-startup",
    "property": "Whole runtime-bridge source assertions: deployed-startup",
    "entry": "packages/runtime-bridge/test/deployed-startup.test.mjs",
    "expectedSha256": "2e54ea454ec6f49ebd6d3a729aba73795e8273f5ba27e44043188b99456482ee",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "generated fixture IDs satisfy the unchanged private and app transport grammar",
      "both real server constructors refuse legacy colon IDs before binding; corrected fixture IDs authenticate",
      "startup diagnostics support IPC error_code and built-in TypeErrors using finite tokens",
      "startup diagnostics suppress raw secret/path/message/cause/stack fields and accessor values"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-f-execution",
    "property": "Whole runtime-bridge assertion groups: f-execution",
    "entry": "packages/runtime-bridge/test/f-execution.test.mjs",
    "expectedSha256": "a96993417afe21cf25ee3804ce14a8a3b8498ea862fbfe5b9c0cfd35dbf21e75",
    "protocol": "pass-lines",
    "timeoutMs": 30000,
    "requiredLabels": [
      "real approved C reservation is claimed once by F and settles C COMPLETED",
      "altered operation and changed grant are refused before mocked SDK creation",
      "grant replay across the same and fresh F ledger never launches twice",
      "lost RPC trailers remain C OUTCOME_UNKNOWN across C/F restart without relaunch",
      "lost C settlement reply is reconciled idempotently without a second dispatch"
    ],
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "bridge-ipc",
    "property": "Whole runtime-bridge assertion groups: ipc",
    "entry": "packages/runtime-bridge/test/ipc.test.mjs",
    "expectedSha256": "b2e4446ff304d0a9e0c76dbf8cefa2658207f90fc2157f560087131db14a7bdd",
    "protocol": "pass-lines",
    "timeoutMs": 30000,
    "requiredLabels": [
      "actual child process and private socket",
      "proposer and read-only method fences precede handler effects",
      "role conveys no owner identity and service rejects claimed context",
      "wrong host secret cannot authenticate",
      "authenticated input tamper and sequence replay close channel",
      "authentication from another connection nonce cannot replay",
      "strict duplicate-key parser and oversized frame close channel",
      "connection count and unauthenticated lifetime are bounded",
      "unauthenticated partial-frame trickle cannot extend handshake deadline",
      "inflight and output are bounded, mutation timeout retains uncertainty",
      "lost mutation reply is unknown and client never retries",
      "existing socket is not removed or replaced"
    ],
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "bridge-memory-join",
    "property": "Whole runtime-bridge source assertions: memory-join",
    "entry": "packages/runtime-bridge/test/memory-join.test.mjs",
    "expectedSha256": "57d886665cb47ef3b5576a926e1a77dea1a3653c7a60f867eaae2941358c011a",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "real C passkey + D save/index/cite/restart via existing injected B transport; SQLite fixture is not PostgreSQL acceptance",
      "real C/D post-dispatch interruption stays consumed and reconciles receipts without saving twice"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-private-ipc",
    "property": "Whole runtime-bridge assertion groups: private-ipc",
    "entry": "packages/runtime-bridge/test/private-ipc.test.mjs",
    "expectedSha256": "723bd76d31066a77d887c14be7568c7516eb4b991f73127ece7f2a8d18b30383",
    "protocol": "pass-lines",
    "timeoutMs": 30000,
    "requiredLabels": [
      "private authority method set is exact and disjoint from public API",
      "app public-role secret cannot authenticate to authority service plane",
      "memory effect credential reaches fixed methods across real child process",
      "public client cannot interpret private role even with deliberately shared test credential",
      "provisioned socket policy is explicit and wrong or missing policy refuses"
    ],
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "bridge-public-memory-worker",
    "property": "Whole runtime-bridge source assertions: public-memory-worker",
    "entry": "packages/runtime-bridge/test/public-memory-worker.test.mjs",
    "expectedSha256": "2a1920581e0b80a5e25fd68d412f1ed64e290e74c4100afe07c23121e32f01ab",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "public memory factory gates every authenticated IPC method on rejected qualification; synthetic SQL only",
      "internal memory factory capability omits the public dispatch marker",
      "public memory verifier and dispatch mode are closed constructor inputs before pool creation"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-public-negative",
    "property": "Whole runtime-bridge source assertions: public-negative",
    "entry": "packages/runtime-bridge/test/public-negative.test.mjs",
    "expectedSha256": "9b8c8af3a6a503bb2d1e2c83eed2b76d110a2a6fdc1d53505c77682062afa2f4",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "public method grammar exposes no raw capture, tombstone, import, reservation or dispatch path; synthetic SQLite only",
      "missing and forged C owner sessions cannot read, propose, approve or save through public ingress",
      "129 unauthenticated proposals do not consume admission; authenticated proposer has no owner mutation power",
      "guest owner/task/provider/state or raw record bytes cannot enter the trusted public proposal binding"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-ui-adapter-lifecycle",
    "property": "Whole runtime-bridge source assertions: ui-adapter-lifecycle",
    "entry": "packages/runtime-bridge/test/ui-adapter-lifecycle.test.mjs",
    "expectedSha256": "51733fd246f444ce8e1f658f59a2664d93e6f03aa24cba24d6e37077a81490e3",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "a real successful login reply arriving after logout cannot restore the adapter token",
      "an older real login reply cannot replace the token from a newer completed login",
      "an old decline token cannot mutate a real proposal after logout",
      "a delayed real proposal cannot retain a capture after logout",
      "a delayed real review cannot be completed after logout",
      "an old decline token cannot mutate a real proposal after a new login",
      "a delayed real proposal cannot retain a capture after a new login",
      "a delayed real review cannot be completed after a new login",
      "16 pending real proposal replies reserve adapter capacity and a decline releases a slot",
      "16 pending real reviews of one live proposal reserve capacity and delivery releases their reservations"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "bridge-worker",
    "property": "Whole runtime-bridge source assertions: worker",
    "entry": "packages/runtime-bridge/test/worker.test.mjs",
    "expectedSha256": "11084b481193ea0740600e3466198e9719ec4cd4945d691194757b433279a2df",
    "protocol": "tap",
    "timeoutMs": 120000,
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "worker and synthetic client refuse readable secret-bearing config before importing it",
      "actual separate C/D worker processes preserve real passkey + locked observation + save/settle/cited restart; no PG or UID proof"
    ],
    "externalSkips": [],
    "args": [],
    "pins": []
  },
  {
    "id": "execution-protocol",
    "property": "Whole mocked executor source assertions: protocol",
    "entry": "packages/execution/checks/protocol.mjs",
    "expectedSha256": "de3406ff67c746e1bc83f7fbd360111d39e88e4c2d3b51c54c4fb0e22bb2acd1",
    "protocol": "pass-lines",
    "timeoutMs": 30000,
    "requiredLabels": [
      "typed exit 1 output and final trailers are drained before owned absence",
      "local immutable Docker image ID works and mutable image tags refuse",
      "typed exit survives trailing SdkError with completion uncertainty",
      "stdout text cannot forge typed success and no exit never becomes exit 1",
      "exact broker refusal and unqualified runtime do not create",
      "dispose during broker await and asynchronous qualification cannot dispatch",
      "caller mutation cannot replace command or grant during awaited broker confirmation",
      "abort and wall timeout require remote cleanup independent of canceled RPC",
      "unknown create with empty inventory blocks new work; late owned creation reconciles",
      "restart keeps partial output/fence and retries only observed owned cleanup",
      "actual child death after typed exit keeps durable output and fences restart",
      "identity replacement refuses deletion and retained uncertainty",
      "cross-process lease excludes live owner and OS releases it on child death",
      "DSH foreground seam resolves exit 1 and refuses infrastructure/background/G1"
    ],
    "summaryLine": "PASS disposable protocol check (mocked gateway; real local SQLite/process lease only)",
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "execution-controls",
    "property": "Whole mocked executor source assertions: controls",
    "entry": "packages/execution/checks/controls.mjs",
    "expectedSha256": "f13d0777911cd35c03a73b8955dac7958c8d2d6bf8e4c4d8fce186582fabe38e",
    "protocol": "pass-lines",
    "timeoutMs": 30000,
    "requiredLabels": [
      "digest",
      "grant",
      "expiry",
      "target",
      "bounds",
      "lease",
      "expiry_after_claim",
      "admission",
      "qualification",
      "accepted_proof",
      "gateway_recovery",
      "damaged_ledger",
      "uncertainty_fence",
      "lost_settlement",
      "reconcile_delivery",
      "lost_ledger",
      "late_abort",
      "prelaunch_cancel",
      "started_abort"
    ],
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "execution-joined",
    "property": "Whole mocked executor source assertions: joined",
    "entry": "packages/execution/checks/joined.mjs",
    "expectedSha256": "124b744b26a5f3059ea857cdafc1a08f061fa7e327bb69e960314c6c4676fca3",
    "protocol": "pass-lines",
    "timeoutMs": 30000,
    "requiredLabels": [
      "ordinary owner approval reaches real consumed kernel preparation and matching request/receipt digests",
      "altered operation or consumed grant cannot cross actual C dispatch into mocked SDK creation",
      "actual one-use dispatch and exit 1 settlement survive a fresh F ledger without a second launch",
      "lost durable settlement reply is replayed idempotently after C/F restart without launching again",
      "lost claim reply keeps the real consumed dispatch fenced and settles uncertainty without any launch",
      "typed exit with lost RPC trailers remains actual C OUTCOME_UNKNOWN after confirmed cleanup and reconciliation",
      "confirmed cleanup promotes drained typed completion through actual C reconciliation without exec replay",
      "cancellation after creation but before exec settles actual C CANCELLED only after observed owned absence",
      "recorded cancellation after launch retains consumed grant and unknown outcome; late cancellation preserves completion"
    ],
    "summaryLine": "{\"status\":\"PASS\",\"checks\":9,\"scope\":\"actual C approval/kernel/store and F lifecycle/settlement; mocked SDK only\",\"limits\":[\"no real gateway or guest\",\"no runtime enforcement qualification\",\"same-UID disposable state\",\"in-process synthetic owner-key only; no enrollment or signing keys passed to F\"]}",
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "execution-joined-complete-null",
    "property": "Mandatory complete/null conservative C/F settlement group",
    "entry": "packages/execution/checks/joined.mjs",
    "expectedSha256": "124b744b26a5f3059ea857cdafc1a08f061fa7e327bb69e960314c6c4676fca3",
    "protocol": "pass-lines",
    "timeoutMs": 30000,
    "requiredLabels": [
      "full wire 124 drains RPC while exact command exit remains unknown; typed 0/1 facts stay distinct",
      "wire 124 with lost final trailers retains raw evidence and transport_failed distinct from complete RPC",
      "recorded cancellation with full wire 124 cannot settle CANCELLED even after complete RPC and owned absence",
      "full wire 124 cleanup reconciliation stays unknown with stable receipt/request/grant/fences and acknowledged changed digest",
      "lost full wire 124 settlement reply drains identical idempotent C/F restart delivery and rejects fresh-ledger claim replay",
      "actual C rejects nonconservative complete/null shapes and changed settlement bindings without altering durable evidence"
    ],
    "summaryLine": "{\"status\":\"PASS\",\"checks\":6,\"group\":\"complete-null\",\"scope\":\"actual C approval/kernel/store and F lifecycle/settlement; mocked SDK only\",\"limits\":[\"no real gateway or guest\",\"no runtime enforcement qualification\",\"same-UID disposable state\",\"in-process synthetic owner-key only; no enrollment or signing keys passed to F\"]}",
    "args": [
      "complete-null"
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ],
    "pins": []
  },
  {
    "id": "authority-core-only",
    "property": "Whole ordinary authority core; admission excluded explicitly",
    "entry": "packages/authority/check.mjs",
    "expectedSha256": "a745a3b8ab6b8ebb182a6322577b10ec845f0af027120cc7dbd15d41a7666cfe",
    "protocol": "assert-json",
    "timeoutMs": 60000,
    "args": [
      "core-only"
    ],
    "counter": {
      "key": "checks",
      "value": 125
    },
    "pins": [
      {
        "path": "packages/authority/check-kernel-guards.mjs",
        "sha256": "c8833abb285fd9cbd4ea6bcc545b36a996f139a18c05a18dafa0c13bde2e1e3d"
      },
      {
        "path": "packages/authority/check-session.mjs",
        "sha256": "f407feaf4fe9228e900742d3d9310a073f9a71d11b204d672b27606b2c279cc9"
      },
      {
        "path": "packages/authority/check-retention.mjs",
        "sha256": "8cd2f3683ec794f273eaddf8d1f78deb501fe800abc6aaa9ed41bc81baba3770"
      }
    ],
    "nodeArgs": [
      "--max-old-space-size=512"
    ]
  },
  {
    "id": "memory-control-retention-coordinator",
    "property": "Control retention coordinator validates reader, publisher, context and operation bindings",
    "entry": "packages/memory/test/control-retention-coordinator.test.mjs",
    "expectedSha256": "495967904b97806c095458fd0355dbdf0b9750b5389c9f3458e3692eadd9226a",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "only an actual branded file reader can qualify a retention coordinator",
      "factory rejects Boolean publisher methods and missing structured publication methods",
      "coordinator is branded and frozen with the exact supplied reader and closed immutable status",
      "factory rejects configuration and method accessors without executing them",
      "fabricated contexts cannot observe, stage or publish retained state",
      "operation and request binding errors refuse before the genuine reader or publisher is reached",
      "guest accessors, proxies, extra host keys and Boolean digests never become retained authority"
    ],
    "externalSkips": [],
    "pins": [
      {
        "path": "packages/memory/genesis/plugins/aukora-kira/lib/record.mjs",
        "sha256": "2c83153256638fe908334953186de28b52254870aecfbb36b48313aa1d8c1c4a"
      },
      {
        "path": "packages/memory/src/codecs.mjs",
        "sha256": "aa1aa3c2e654a879bb5aa86beb5a1040fdfc62ebc38f59e6b594972526650bec"
      },
      {
        "path": "packages/memory/src/control-retention.mjs",
        "sha256": "5d0f283d451a06a48e40d21b2311c2c7c43257de1f4c68ba571601f8b05ef9d5"
      },
      {
        "path": "packages/memory/src/control-retention-coordinator.mjs",
        "sha256": "f11063525752ca088db4d4e3a6217760ff3d5b5c8bf57bad4d9314fd4c805d3a"
      }
    ]
  },
  {
    "id": "memory-owner-serialization",
    "property": "Whole current owner serialization constructor and scope fixtures",
    "entry": "packages/memory/test/owner-serialization.test.mjs",
    "expectedSha256": "7c89c42f71ef428dde64136b955d6e0e9314879dddef6e4ba0a1cff26fa31e64",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "dedicated owner client spans asynchronous work and both transactions, then becomes inactive",
      "same-owner nested work reuses the held client and foreign or wrong-epoch scopes refuse",
      "private participant explicitly inspects the genuine active scope outside its ALS context only",
      "truthy or lost lock and changed backend observations refuse and destroy only the owned client",
      "failed work keeps its exact refusal when confirmed cleanup succeeds",
      "unconfirmed unlock or invalid acquisition destroys the dedicated client without retry",
      "host and constructor accept only exact inert required fields before acquiring a client"
    ],
    "externalSkips": [],
    "pins": [
      {
        "path": "packages/memory/src/owner-serialization.mjs",
        "sha256": "9c4e0974154b9fa921206a087d19c0d37e34982dc7ef49e4e47957e7342b4fa5"
      },
      {
        "path": "packages/memory/src/codecs.mjs",
        "sha256": "aa1aa3c2e654a879bb5aa86beb5a1040fdfc62ebc38f59e6b594972526650bec"
      }
    ]
  },
  {
    "id": "memory-retained-memory-participant",
    "property": "Whole current retained memory participant constructor and scope fixtures",
    "entry": "packages/memory/test/retained-memory-participant.test.mjs",
    "expectedSha256": "f7c95e0aceaa0521d05fa1797d2af7c8459e2e735d77ca41e951834e55d61210",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "private participant and controller are source-branded and closed; fabricated capability callbacks fail",
      "operation registration lives only within the actual owned SQL scope; completion invalidates it",
      "closed source input rejects owner/epoch/request mismatches before a SQL scope exists",
      "guest accessors and proxies never execute while registering an immutable operation",
      "phase methods reject unknown/changed operation and closed-shape bypass without publication",
      "lost owner-session cleanup retains exact operation/request bindings and forbids automatic retry"
    ],
    "externalSkips": [],
    "pins": [
      {
        "path": "packages/memory/genesis/plugins/aukora-kira/lib/record.mjs",
        "sha256": "2c83153256638fe908334953186de28b52254870aecfbb36b48313aa1d8c1c4a"
      },
      {
        "path": "packages/memory/src/codecs.mjs",
        "sha256": "aa1aa3c2e654a879bb5aa86beb5a1040fdfc62ebc38f59e6b594972526650bec"
      },
      {
        "path": "packages/memory/src/owner-serialization.mjs",
        "sha256": "9c4e0974154b9fa921206a087d19c0d37e34982dc7ef49e4e47957e7342b4fa5"
      },
      {
        "path": "packages/memory/src/control-retention.mjs",
        "sha256": "5d0f283d451a06a48e40d21b2311c2c7c43257de1f4c68ba571601f8b05ef9d5"
      },
      {
        "path": "packages/memory/src/control-retention-coordinator.mjs",
        "sha256": "f11063525752ca088db4d4e3a6217760ff3d5b5c8bf57bad4d9314fd4c805d3a"
      },
      {
        "path": "packages/memory/src/retained-memory-participant.mjs",
        "sha256": "68e30bd1e2467213597316017a62f30cbff7cca98ec298eada98e86d172d0e9b"
      }
    ]
  },
  {
    "id": "bridge-worker-observation-scope",
    "property": "Authority worker retains exact observation scope until synchronous or asynchronous settlement",
    "entry": "packages/runtime-bridge/test/worker-observation-scope.test.mjs",
    "expectedSha256": "8e6829a6e1aad3fd1d5f2450580b9883a2ff815c1fb1bdf6c5c899b1ac513214",
    "protocol": "tap",
    "timeoutMs": 120000,
    "args": [],
    "nodeArgs": [
      "--max-old-space-size=512",
      "--test",
      "--test-isolation=none",
      "--test-reporter=tap"
    ],
    "requiredTitles": [
      "C recheck after a microtask retains the exact scoped observation",
      "observation survives delayed C call, remains detached/exact, and refuses overlap",
      "pending rejection clears observation only after settlement, and later call is admitted",
      "synchronous completion and throw both release the scope without leaking it",
      "pending non-live C call fences later scope installation",
      "private ACL, default unmounted refusal, and closed observation checks remain intact"
    ],
    "externalSkips": [],
    "pins": [
      {
        "path": "packages/contracts/src/runtime.mjs",
        "sha256": "d42ec191f52279b4af33ad23edb1518425817ac89e70a80955d0c0266386be12"
      },
      {
        "path": "packages/runtime-bridge/src/registry.mjs",
        "sha256": "5ffc21e2c074dec11a83721d56b9cfb6322ae5ae72c8974400dd8419a8c6a349"
      },
      {
        "path": "packages/runtime-bridge/src/ipc.mjs",
        "sha256": "43a81557f127f4402e40c27193f5f5aa3bdc11fec76974de474901e17823c0b7"
      },
      {
        "path": "packages/runtime-bridge/src/worker.mjs",
        "sha256": "709e3374d433e2fcf59d4657891b71613b20ffdd22176a3accb02389a1632a3d"
      }
    ]
  }
])

export const HISTORY = freeze([
  {
    "id": "pg-storage-record",
    "status": "HISTORICAL_ONLY",
    "reported_result": "PASS",
    "scope": "Operator-reported synthetic PG prepare/restart/verify/cleanup; toy authority storage-only",
    "source_record_id": "historical-owner-operator-relay",
    "provenance": "OWNER_RELAY_ONLY",
    "receipt_file": null,
    "receipt_sha256": null,
    "current_verification": "UNPERFORMED",
    "authority_or_product_qualification": "UNPERFORMED"
  },
  {
    "id": "uid-parent-record",
    "status": "HISTORICAL_ONLY",
    "reported_result": "SETUP_COMPLETED",
    "scope": "H-reported protected-parent/UID setup at parents8c20",
    "reported_uids": {
      "app": 997,
      "authority": 995,
      "memory": 994,
      "postgres": 113
    },
    "source_record_id": "historical-owner-operator-relay",
    "provenance": "OWNER_RELAY_ONLY",
    "receipt_file": null,
    "receipt_sha256": null,
    "current_verification": "UNPERFORMED",
    "acl_or_cross_uid_qualification": "UNPERFORMED"
  }
])

export const UNPERFORMED = freeze([
  {
    "id": "owner-ceremony",
    "status": "UNPERFORMED",
    "reason": "KEYLESS_SOURCE_PROFILE"
  },
  {
    "id": "live-pg",
    "status": "UNPERFORMED",
    "reason": "HISTORICAL_RECORD_ONLY_NO_CONNECTION"
  },
  {
    "id": "current-cross-uid",
    "status": "UNPERFORMED",
    "reason": "NO_HOST_PERMISSION_OBSERVATION"
  },
  {
    "id": "w1-writer-observation",
    "status": "UNPERFORMED",
    "reason": "AUTHORITATIVE_C_D_WRITER_OBSERVATION_NOT_QUALIFIED"
  },
  {
    "id": "qualified-guest",
    "status": "UNPERFORMED",
    "reason": "NO_GUEST_OR_HELD_OPENSHELL_FIXTURE"
  },
  {
    "id": "paid-inference",
    "status": "UNPERFORMED",
    "reason": "NO_CREDENTIALS_OR_EXTERNAL_REQUEST"
  },
  {
    "id": "composed-pixels",
    "status": "UNPERFORMED",
    "reason": "NO_GUI_OR_RUNNING_APP_TARGET"
  },
  {
    "id": "extended-authority-save",
    "status": "UNPERFORMED",
    "reason": "EXTENDED_SUITE_ONLY_NO_265_SAVE_RUN"
  },
  {
    "id": "inference-total-budget-delivery",
    "status": "UNPERFORMED",
    "reason": "CURRENT_NAMED_GATE_ABSENT_DEFERRAL_INTENT_NOT_CONFIRMED"
  }
])
