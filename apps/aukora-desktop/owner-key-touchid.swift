// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only AppKit preview: no biometric checks/prompts, Keychain lookup, signing, enrollment or secret export.
import AppKit
import CoreFoundation
import CryptoKit

private let requestDomain = Data("aukora:owner-key:scoped-binding:v1\0".utf8)
private let custodyUnavailableReason = "owner-key:secure-custody-join-unavailable"
private let fields = ["action", "audience", "epoch", "expires_at", "issued_at", "nonce", "owner_root_id",
    "owner_subject", "previous_binding_digest", "previous_nostr_pubkey_hex", "request_id", "scope",
    "scoped_nostr_pubkey_hex", "version"]
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
