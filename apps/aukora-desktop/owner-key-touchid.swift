// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only AppKit preview: no biometric checks/prompts, Keychain lookup, signing, enrollment or secret export.
import AppKit
import CoreFoundation
import CryptoKit

private let requestDomain = Data("aukora:owner-key:scoped-binding:v1\0".utf8)
private let authorizationDomain = Data("aukora:owner-authorization:v1\0".utf8)
private let custodyUnavailableReason = "owner-key:secure-custody-join-unavailable"
private let fields = ["action", "audience", "epoch", "expires_at", "issued_at", "nonce", "owner_root_id",
    "owner_subject", "previous_binding_digest", "previous_nostr_pubkey_hex", "request_id", "scope",
    "scoped_nostr_pubkey_hex", "version"]
private let authorizationFields = ["after_sha256", "before_sha256", "challenge", "expires_at_ms", "gate",
    "issued_at_ms", "kind", "operation", "owner_epoch", "owner_root_id", "owner_subject", "proposal_id",
    "target", "version"]
private enum Refusal: Error { case request, expired, enrollmentRequired, custodyMismatch }
private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
private func hex64(_ value: Any?) -> Bool {
    guard let value = value as? String else { return false }
    let bytes = value.utf8
    return bytes.count == 64 && bytes.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
private func number(_ value: Any?) -> Double? {
    guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
    let d = n.doubleValue
    return d.isFinite && d >= 0 && d <= 9007199254740991 && d.rounded(.towardZero) == d ? d : nil
}
private func uuidV4(_ value: Any?) -> Bool {
    guard let value = value as? String else { return false }
    let bytes = Array(value.utf8)
    guard bytes.count == 36, bytes[14] == 52, [56, 57, 97, 98].contains(bytes[19]) else { return false }
    return bytes.enumerated().allSatisfy { index, byte in
        [8, 13, 18, 23].contains(index) ? byte == 45 : (48...57).contains(byte) || (97...102).contains(byte)
    }
}

private struct Action {
    let object: [String: Any]
    let wire: Data
    let digest: Data
    init(_ text: String) throws {
        let bytes = Data(text.utf8)
        guard bytes.count <= 4096,
              let r = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(r.keys) == Set(fields),
              try JSONSerialization.data(withJSONObject: r, options: [.sortedKeys, .withoutEscapingSlashes]) == bytes,
              number(r["version"]) == 1,
              ["bind-scoped-nostr", "rotate-scoped-nostr"].contains(r["action"] as? String ?? ""),
              ["aukora:records", "aukora:aura", "aukora:recall"].contains(r["audience"] as? String ?? ""),
              ["owner-recipient", "aura-author"].contains(r["scope"] as? String ?? ""),
              let subject = r["owner_subject"] as? String,
              subject.hasPrefix("aukora:1:"), hex64(String(subject.dropFirst("aukora:1:".count))),
              ["nonce", "owner_root_id", "request_id", "scoped_nostr_pubkey_hex"].allSatisfy({ hex64(r[$0]) }),
              let epoch = number(r["epoch"]), epoch >= 1,
              let issued = number(r["issued_at"]), let expiry = number(r["expires_at"]),
              expiry > issued, expiry - issued <= 120 else { throw Refusal.request }
        if r["action"] as? String == "bind-scoped-nostr" {
            guard epoch == 1, r["previous_binding_digest"] is NSNull,
                  r["previous_nostr_pubkey_hex"] is NSNull else { throw Refusal.request }
        } else {
            guard epoch >= 2, hex64(r["previous_binding_digest"]), hex64(r["previous_nostr_pubkey_hex"]),
                  r["previous_nostr_pubkey_hex"] as? String != r["scoped_nostr_pubkey_hex"] as? String
            else { throw Refusal.request }
        }
        object = r; wire = bytes; digest = Data(SHA256.hash(data: requestDomain + bytes))
        try checkTime()
    }
    func checkTime() throws {
        let now = floor(Date().timeIntervalSince1970)
        guard let issued = number(object["issued_at"]), let expiry = number(object["expires_at"]),
              issued <= now, now < expiry else { throw Refusal.expired }
    }
    var facts: String {
        "\(object["action"]!)\nService: \(object["audience"]!)\nScope: \(object["scope"]!)\n" +
        "Owner: \(object["owner_subject"]!)\nOwner root: \(object["owner_root_id"]!)\nFrom: \(object["previous_nostr_pubkey_hex"] is NSNull ? "none" : String(describing: object["previous_nostr_pubkey_hex"]!))\n" +
        "To: \(object["scoped_nostr_pubkey_hex"]!)\nEpoch: \(object["epoch"]!)\n" +
        "Expires: \(object["expires_at"]!)\nRequest digest: \(hex(digest))"
    }
}

// This separate domain and closed 14-field body intrinsically request ONE allowed-once change or revert.
// Target checks mirror the public wire format only; the trusted gate must enforce its actual allowlist.
private struct Authorization {
    let object: [String: Any]
    let wire: Data
    let digest: Data
    init(_ text: String) throws {
        let bytes = Data(text.utf8)
        guard bytes.count <= 4096,
              let a = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(a.keys) == Set(authorizationFields),
              try JSONSerialization.data(withJSONObject: a, options: [.sortedKeys, .withoutEscapingSlashes]) == bytes,
              number(a["version"]) == 1, a["kind"] as? String == "aukora-owner-authorization/v1",
              ["change", "revert"].contains(a["operation"] as? String ?? ""),
              ["after_sha256", "challenge", "gate", "owner_root_id"].allSatisfy({ hex64(a[$0]) }),
              a["before_sha256"] as? String == "absent" || hex64(a["before_sha256"]),
              a["before_sha256"] as? String != a["after_sha256"] as? String,
              let epoch = number(a["owner_epoch"]), epoch >= 1,
              let issued = number(a["issued_at_ms"]), let expiry = number(a["expires_at_ms"]),
              expiry > issued, expiry - issued <= 120000,
              let subject = a["owner_subject"] as? String,
              subject.hasPrefix("aukora:1:"), hex64(String(subject.dropFirst("aukora:1:".count))),
              uuidV4(a["proposal_id"]), let target = a["target"] as? String,
              !target.isEmpty, target.utf8.count <= 200,
              target.utf8.allSatisfy({ (32...126).contains($0) }), !target.contains("\\")
        else { throw Refusal.request }
        let parts = target.components(separatedBy: "/")
        guard parts.count >= 3, parts.first == "plugins", !parts.contains(where: { ["", ".", ".."].contains($0) })
        else { throw Refusal.request }
        object = a; wire = bytes; digest = Data(SHA256.hash(data: authorizationDomain + bytes))
        try checkTime()
    }
    func checkTime() throws {
        let now = floor(Date().timeIntervalSince1970 * 1000)
        guard let issued = number(object["issued_at_ms"]), let expiry = number(object["expires_at_ms"]),
              issued <= now, now < expiry else { throw Refusal.expired }
    }
    var facts: String {
        "Requested authorization: ONE allowed-once \(object["operation"]!)\nTarget: \(object["target"]!)\n" +
        "Before SHA-256: \(object["before_sha256"]!)\nAfter SHA-256: \(object["after_sha256"]!)\n" +
        "Gate full SPKI SHA-256: \(object["gate"]!)\nProposal: \(object["proposal_id"]!)\n" +
        "Challenge: \(object["challenge"]!)\nIssued at (ms): \(object["issued_at_ms"]!)\nExpires at (ms): \(object["expires_at_ms"]!)\n" +
        "Owner: \(object["owner_subject"]!)\nOwner root: \(object["owner_root_id"]!)\nOwner epoch: \(object["owner_epoch"]!)\n" +
        "Kind: \(object["kind"]!)\nVersion: \(object["version"]!)\nAuthorization digest: \(hex(digest))"
    }
}

// The host must supply this public pin independently of the request, from separately approved enrollment.
// Public-point validation and the root identifier establish neither signed-host custody nor the key's stored ACL.
struct OwnerRootEnrollmentPin {
    let publicKeyX963: Data
    init(publicKeyX963: Data) throws {
        guard publicKeyX963.count == 65, publicKeyX963.first == 4 else { throw Refusal.enrollmentRequired }
        do { _ = try P256.Signing.PublicKey(x963Representation: publicKeyX963) }
        catch { throw Refusal.enrollmentRequired }
        self.publicKeyX963 = publicKeyX963
    }
    var spki: Data {
        Data([0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
              0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]) + publicKeyX963
    }
    var id: String { hex(Data(SHA256.hash(data: spki))) }
}

// Native activation is UNPERFORMED. There is no established signed-host requirement, entitled Data Protection
// keychain access group, or independently verified enrollment policy for the existing owner root.
// A public pin and fixed application tag identify a key; they do not establish exclusive caller custody.
// CFEqual against a newly constructed SecAccessControl is not documented attestation of the stored policy.
// A future separately approved custody join must verify the signed host and exact Data Protection group,
// refuse absent/mismatched key attributes, and authorize the actual enrolled ACL for .useKeySign.
// A generic biometric policy does not establish that key-operation join. No caller boolean, supplied Team ID,
// access-group string, legacy lookup, or software authorization can enable signing in this component.
// Until that join exists, refusal is unconditional and precedes every biometric or Keychain operation.

/// Displays immutable request facts and an independently supplied public pin match; never grants approval.
@MainActor final class OwnerKeyApprovalViewController: NSViewController {
    private let action: Action
    private let pin: OwnerRootEnrollmentPin
    private let presentedFacts: String
    private var completion: (([String: Any]) -> Void)?
    private var finished = false
    private let approve = NSButton(title: "Request approval", target: nil, action: nil)
    private let nativeStatus = NSTextField(wrappingLabelWithString:
        "Native status: UNPERFORMED\n" + custodyUnavailableReason)
    init(canonicalRequest: String, enrollmentPin: OwnerRootEnrollmentPin, completion: @escaping ([String: Any]) -> Void) throws {
        let parsed = try Action(canonicalRequest)
        guard parsed.object["owner_root_id"] as? String == enrollmentPin.id else { throw Refusal.custodyMismatch }
        action = parsed; pin = enrollmentPin; presentedFacts = parsed.facts; self.completion = completion
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { return nil }
    override func loadView() {
        let facts = NSTextField(wrappingLabelWithString: presentedFacts)
        facts.isSelectable = true
        nativeStatus.isSelectable = true
        approve.target = self; approve.action = #selector(approveAction)
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelAction))
        let stack = NSStackView(views: [nativeStatus, facts, approve, cancel]); stack.orientation = .vertical
        stack.alignment = .leading; stack.spacing = 12; stack.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        view = stack
    }
    private func finish(_ result: [String: Any]) {
        guard !finished else { return }; finished = true
        let callback = completion; completion = nil; approve.isEnabled = false; callback?(result)
    }
    @objc private func cancelAction() {
        finish(["status": "cancelled", "activation": "UNPERFORMED", "grants_authority": false])
    }
    @objc private func approveAction() {
        finish(["status": "unavailable", "reason": custodyUnavailableReason,
            "activation": "UNPERFORMED", "grants_authority": false])
    }
    override func viewDidDisappear() { super.viewDidDisappear(); if !finished { cancelAction() } }
}

// Preview only: the protected host must supply independently validated gate review content, diff and timing.
// The original public gate review had no review_issued_at_ms; its created field was proposal creation,
// not challenge issuance. The actual H v3 issuance field and caller contract require independent integration.
// A local clock cannot supply missing review timing, gate identity, owner epoch or authorization expectations.
// Supplied public expectations compare immutable bytes. They do not establish signed-host custody or a key ACL,
// authenticate a gate receipt, consume a challenge, or authorize effects. Native activation remains UNPERFORMED.
@MainActor final class OwnerAuthorizationApprovalViewController: NSViewController {
    private let authorization: Authorization
    private let pin: OwnerRootEnrollmentPin
    private let reviewedContent: String
    private let reviewedDiff: String
    private let presentedFacts: String
    private var completion: (([String: Any]) -> Void)?
    private var finished = false
    private let approve = NSButton(title: "Request approval", target: nil, action: nil)
    private let nativeStatus = NSTextField(wrappingLabelWithString:
        "Native status: UNPERFORMED\n" + custodyUnavailableReason)
    init(canonicalAuthorization: String, reviewedContent: String, reviewedDiff: String,
         enrollmentPin: OwnerRootEnrollmentPin,
         expectedOwnerEpoch: UInt64, expectedGateSPKISHA256: String, expectedAuthorizationDigest: String,
         completion: @escaping ([String: Any]) -> Void) throws {
        let parsed = try Authorization(canonicalAuthorization)
        guard reviewedContent.utf8.allSatisfy({ (32...126).contains($0) }),
              reviewedDiff.utf8.allSatisfy({ $0 == 9 || $0 == 10 || (32...126).contains($0) }),
              reviewedContent.utf8.count + reviewedDiff.utf8.count <= 12000,
              parsed.object["after_sha256"] as? String == hex(Data(SHA256.hash(data: Data(reviewedContent.utf8))))
        else { throw Refusal.request }
        guard parsed.object["owner_root_id"] as? String == enrollmentPin.id,
              expectedOwnerEpoch >= 1, expectedOwnerEpoch <= 9007199254740991,
              number(parsed.object["owner_epoch"]) == Double(expectedOwnerEpoch),
              hex64(expectedGateSPKISHA256), parsed.object["gate"] as? String == expectedGateSPKISHA256,
              hex64(expectedAuthorizationDigest), hex(parsed.digest) == expectedAuthorizationDigest
        else { throw Refusal.custodyMismatch }
        authorization = parsed; pin = enrollmentPin
        self.reviewedContent = reviewedContent; self.reviewedDiff = reviewedDiff
        presentedFacts = parsed.facts + "\n\nFULL REVIEWED CONTENT\n" + reviewedContent +
            "\n\nFULL REVIEWED DIFF\n" + reviewedDiff
        self.completion = completion
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { return nil }
    override func loadView() {
        let facts = NSTextView(frame: NSRect(x: 0, y: 0, width: 640, height: 360))
        facts.string = presentedFacts; facts.isEditable = false; facts.isSelectable = true
        facts.isRichText = false; facts.autoresizingMask = [.width]
        facts.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        facts.minSize = NSSize(width: 0, height: 360)
        facts.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        facts.isHorizontallyResizable = false; facts.isVerticallyResizable = true
        facts.textContainer?.containerSize = NSSize(width: 640, height: CGFloat.greatestFiniteMagnitude)
        facts.textContainer?.widthTracksTextView = true
        let fullReview = NSScrollView()
        fullReview.hasVerticalScroller = true; fullReview.documentView = facts
        nativeStatus.isSelectable = true
        approve.target = self; approve.action = #selector(approveAction)
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelAction))
        let stack = NSStackView(views: [nativeStatus, fullReview, approve, cancel]); stack.orientation = .vertical
        stack.alignment = .leading; stack.spacing = 12; stack.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        fullReview.translatesAutoresizingMaskIntoConstraints = false
        fullReview.widthAnchor.constraint(equalToConstant: 640).isActive = true
        fullReview.heightAnchor.constraint(equalToConstant: 360).isActive = true
        view = stack
    }
    private func finish(_ result: [String: Any]) {
        guard !finished else { return }; finished = true
        let callback = completion; completion = nil; approve.isEnabled = false; callback?(result)
    }
    @objc private func cancelAction() {
        finish(["status": "cancelled", "activation": "UNPERFORMED", "grants_authority": false])
    }
    @objc private func approveAction() {
        finish(["status": "unavailable", "reason": custodyUnavailableReason,
            "activation": "UNPERFORMED", "grants_authority": false])
    }
    override func viewDidDisappear() { super.viewDidDisappear(); if !finished { cancelAction() } }
}
