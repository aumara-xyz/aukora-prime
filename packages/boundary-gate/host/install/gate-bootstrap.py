#!/usr/bin/python3
"""Root-custodied pre-Node gate launcher. AGPL-3.0-or-later.

Install this reviewed file extensionless at BOOTSTRAP and invoke fixed Python
with -I -S. Production has no path, UID, manifest, or fixture overrides.
"""

import hashlib
import json
import math
import os
import re
import stat
import sys
import unicodedata

BOOTSTRAP = "/usr/local/lib/aukora-boundary/gate-bootstrap"
PYTHON = "/usr/bin/python3"
NODE = "/opt/aukora-node/bin/node"
PACKAGE = "/opt/aukora-boundary-gate"
ENTRY = "bin/gate.mjs"
OPERATOR_ENTRIES = {"floor": "bin/release-floor.mjs", "approval": "bin/plugin-set-approval.mjs"}
MANIFEST = "/etc/aukora-boundary-gate/gate-package-manifest.json"
SIGNER_EPOCHS = "/etc/aukora-boundary-gate/signer-epochs.json"
EXTERNAL_FILES = (SIGNER_EPOCHS,)
LAUNCHER_ROOT = "/opt/aukora-genesis/src"
# Six approved checkout inputs only. Selected-release admission and all other
# checkout/release bytes are outside this named pre-Node profile.
LAUNCHER_SOURCE_PINS = {
    "scripts/launch-dsh.py": "5501bdc1a57dfe11799e94c3194ae3c1844fe1968060fe5229be86553e0d3d1b",
    "scripts/genesis-check.mjs": "238ad43612280b79d0d0303480cb1a999bcf3b413fe18c97ebd9e0aedae3b303",
    "scripts/lib/artifact-integrity.mjs": "39e2f64643ceb2e0d93fabd14467ebaf5efd6de0e0a70f76cf19ce69825b5a41",
    "scripts/lib/release-strip.mjs": "1a687a82424b84420497edbdc5e6c13cb14e065fe4d262f0e859e9e85264b641",
    "scripts/artifacts-coverage.json": "4b652f8963fe5ed4ebe9436621c709d217cd08e97ff7986f14900efba6f9c592",
    "upstream-dsh.json": "4e328cc246b4c3f0e05172e5a806812e2767eb320f1c30a4811c09f085d24c7c",
}
AURA_ROOT = "/opt/aukora-aura"
AURA_ENTRY = "packages/boundary-gate/host/aura/entry.mjs"
AURA_CONFIG = "/etc/aukora-boundary-gate/aura-context.json"
AURA_MAX_CONFIG = 1024 * 1024
# Exact D9f5ec12 source inventory dd9e19cb...7818a277; public source pins only.
AURA_SOURCE_PINS = {
    "LICENSE": "8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef",
    "package.json": "b56266f47e9edc97e309a754828d44be3139e854f784cb7c6ea1cb83d90c1875",
    "packages/boundary-gate/host/aura/context.mjs": "76d37a6bd058796ca3d1b54cf199e348057ce5f7bd01a838ed2e57536512c51c",
    "packages/boundary-gate/host/aura/entry.mjs": "86fd96473231f3d0d16e2c132f096c46b129463821671450459a4f6a31176116",
    "packages/boundary-gate/host/aura/records-provider.mjs": "38c9e814a1ace122ece09b2ff866b043590c7dbc1f63ef8e05d8df769bd42277",
    "packages/boundary-gate/package.json": "2af5fa61cc375ceba79b213185877b1aa687f17844b7cadb733f356217d038dc",
    "packages/contracts/package.json": "0c42b75f1352cc0def2ceeb11009ef999003b5916211a0f5a37ad21bcf2800cb",
    "packages/contracts/src/json.mjs": "068aa14d3be101413cb028dc5f39e442130b4eeb87c40e18209ddce3ffce4639",
    "plugins/aukora-nostr/lib/canonical-json.mjs": "068aa14d3be101413cb028dc5f39e442130b4eeb87c40e18209ddce3ffce4639",
    "plugins/aukora-nostr/lib/event.mjs": "b32d5df36cfcf91385ce2fb0e22198bea759a110734808ba3c577d8da7ec19db",
    "plugins/aukora-nostr/lib/identity.mjs": "55c939d6cb56ceb3903a7f1e4b3c2f0f52d720ed63cd4d8f8f67743446ef3b5c",
    "plugins/aukora-nostr/lib/nip44.mjs": "16035f0eb548af8a5d4f822a42458417b37ef24b3c933ad4715fde01aafff1c6",
    "plugins/aukora-nostr/lib/records.mjs": "bdbb208cdb17ca35b5b32f8a2a72a45ac5d1061304644e9026dea5cf2f4c7218",
    "plugins/aukora-nostr/lib/vendor/noble-ciphers/_arx.js": "2fc64a1d8379549ab64a9dabdd18032175df71fb638da643dc060bbf339c12f4",
    "plugins/aukora-nostr/lib/vendor/noble-ciphers/_poly1305.js": "1a01e558e8cbd5bcff144416c05fe1b870d12535185aa35dda7d287f1da036f1",
    "plugins/aukora-nostr/lib/vendor/noble-ciphers/chacha.js": "66d7c7d6dd9187a96f52aa2054534bac02a076b2e6e397e8e8fa8f2c17b74870",
    "plugins/aukora-nostr/lib/vendor/noble-ciphers/licenses/noble-ciphers.LICENSE": "f36671a5487c9c5050efacb58011c37c24c55a889803cb036cf9d9a6347c1e2d",
    "plugins/aukora-nostr/lib/vendor/noble-ciphers/upstream-noble-ciphers.json": "cf930497196874fa92b07eb80bf0ca147692b7ec243ec846e9d7b08e7fa7ce41",
    "plugins/aukora-nostr/lib/vendor/noble-ciphers/utils.js": "e6b93ca8d3f07568c3f1eceb1c6cb6b0ba7bbce0641958116c7b0d115ff0fa34",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/curve.js": "153bf617c6b1d266b6591ba42e46460ca4276010a788adff203976698fe6dbbf",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/der.js": "7f80d698611b131368ecf732b8740bb97f72cd42fef77c4b0bb923e2e2d44159",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/edwards.js": "0e40ef7e09c6b4a9e8ee82b75b9ea4d7f0b7e4bc61007de053d8f2c870466229",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/fft.js": "40d2659f2e630ea1d499cde2e4a166a572a35d2191c6a589c672ac92f463ea06",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/frost.js": "378691b2197a6e4968246f655a752894be20b1642b3bfe78d1082c3916d74b73",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/hash-to-curve.js": "c4794a593c0e6b448593c293c91afa40c4a5d9d9a9b50a27df0e5ff7acdf486a",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/modular.js": "3fd76af533a3c544a4f39f51e39a48e2d118ce5a28accdaf2aecc2b5f838fd71",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/montgomery.js": "987df16e8d8bb9fb584b5b1d603162d820141a3101634463137b91c4293530b3",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/oprf.js": "58835db56426849c3e4b8af70eb7c55b2b6cd1afdfdefb8d8ade9655901d95f0",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/abstract/weierstrass.js": "9b83dfcd4cd529ac2e896dcf903a9b0442a32df42bd3f41d3993ff079251510c",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/ed25519.js": "f48bb4f67497d6d276e2a4cc8e07c20338557cabaf7ce3ce5e97901ef4379336",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/misc.js": "4721fa2d9713f6533e13eed3b7cd01c5033e2f9c22f56ad269cad8204af11443",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/nist.js": "04f2f3fd4f4fe68265446acd7142a98cc72db575560c7543115e508c96c086a9",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/secp256k1.js": "d484fee92603850b5c9f81470c41a30f4ea5b0ca4a8e6348568aa7bba1c84b8e",
    "plugins/aukora-nostr/lib/vendor/noble-curves/curves/utils.js": "8693d78c178b5c43abe2b5889a7710f920697089c0556f4b5035e5c250229828",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/_blake.js": "cabbff61d1f373bac45594ad758df7c42e176464ddbb94b44f5533fa977a4f56",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/_md.js": "ba1517585e56ad61924a4842239d894c7812facded6482ec55cdb828567dc422",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/_u64.js": "b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/blake1.js": "da1d08b4d0702ad4f185a796df8fce3fec2855de53b02190eba3bd8555677b5c",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/blake2.js": "ffc4b84cb0ebb1b84cfcaba9c39ae03b07338e459733e96df129b278f7adc48b",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/hmac.js": "fec9f8f3aeda785ea2de91cc4c059d54ef98196261c026c43f48341007ae52c9",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/legacy.js": "690553a41af2fdd1e32ff6b534ba8508e95f1861c09c2d62fe762b6b501e09be",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/sha2.js": "471746bba6ec4c6238ca41358d1d3b40b6ff31cf3363f0b4d550c649c1a8e83b",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/sha3.js": "9a81e1edb24eae27b335533220167609cfb58008c5690e140ce478acdc669f32",
    "plugins/aukora-nostr/lib/vendor/noble-curves/hashes/utils.js": "1ba3b1fe434318418c256236798e5afff5b4cc41773d3e3d320e4e7484beb6cb",
    "plugins/aukora-nostr/lib/vendor/noble-curves/licenses/noble-curves.LICENSE": "4f221aee6e072336700c408c68ab3b96a3fc09f6aebe6f48f1bd99e5ef13faec",
    "plugins/aukora-nostr/lib/vendor/noble-curves/licenses/noble-hashes.LICENSE": "4f221aee6e072336700c408c68ab3b96a3fc09f6aebe6f48f1bd99e5ef13faec",
    "plugins/aukora-nostr/lib/vendor/noble-curves/upstream-noble-curves.json": "d4fdcea4ad244b0220acedb6d10d0a35113ecb6b0d62bc43efac90497fd7f601",
    "plugins/aukora-nostr/package.json": "99c0fde000e9ec27ffff09112195f6e73f839d809579ac5f11e473a331ead5be",
    "scripts/aura/collect-gate.mjs": "ff8f81f61a26e42b5bab5c9e0b7cbac7c72a2c3f84349b426ffb9ee87ca4fe7f",
    "scripts/aura/gate-snapshot.mjs": "2d8dc543b90880e671f91d5c714e2adbd372c42ece14c8430f17fc85647bbd53",
    "scripts/aura/verify-collected.mjs": "4030920a8e2b653c4623b59e3ce27c3a3ef137a4e8e6b7ff33a7aa297e7580bc",
}
OWNER_KEY_ROOT = "/opt/owner-key"
OWNER_KEY_FILES = frozenset({
    "PROVENANCE.json", "README.md", "TRUSTED-PATH.json", "package.json",
    "checks/authorization.test.mjs", "checks/gate-caller.test.mjs", "checks/mutant-loader.mjs",
    "checks/mutants.mjs", "checks/owner-key.test.mjs",
    "src/authorization.mjs", "src/index.mjs",
})
OWNER_KEY_SOURCE_PINS = {
    "src/authorization.mjs": "6f463e6aa0ac41c2ed68d7c8a863b33b3129a7f431317f6660f8accc7f93ae28",
    "src/index.mjs": "5416ff95400109c65ed8e8d3fb9c94ec218c46c1039e6cc703a781781ccb467d",
}
MAX_FILE = 8 * 1024 * 1024
MAX_FILES = 4096
MAX_TOTAL = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def protected_metadata(metadata, directory=False):
    """Pure metadata validator; source fixtures supply synthetic root metadata."""
    require(metadata.st_uid == 0, "protected-owner")
    require(metadata.st_mode & 0o022 == 0, "protected-mode")
    require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode), "protected-type")
    if not directory:
        require(metadata.st_nlink == 1, "protected-hardlink")


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def canonical_absolute(path):
    return (isinstance(path, str) and path.startswith("/") and not path.startswith("//")
            and os.path.normpath(path) == path and "\x00" not in path)


def protected_directory(path):
    require(canonical_absolute(path), "protected-path")
    before = os.lstat(path)
    protected_metadata(before, directory=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        protected_metadata(opened, directory=True)
        require(identity(before) == identity(opened), "protected-open-identity")
    finally:
        os.close(fd)


def protected_ancestors(path):
    require(canonical_absolute(path), "protected-path")
    protected_directory("/")
    parent = os.path.dirname(path)
    current = ""
    for part in parent.split("/")[1:]:
        current += "/" + part
        protected_directory(current)


def protected_open(path):
    protected_ancestors(path)
    before = os.lstat(path)
    protected_metadata(before)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        protected_metadata(opened)
        require(identity(before) == identity(opened), "protected-open-identity")
        return fd, opened
    except BaseException:
        os.close(fd)
        raise


def protected_read(path, limit=MAX_FILE):
    fd, opened = protected_open(path)
    try:
        require(opened.st_size <= limit, "protected-size")
        pieces, count = [], 0
        while True:
            piece = os.read(fd, min(65536, limit + 1 - count))
            if not piece:
                break
            pieces.append(piece)
            count += len(piece)
            require(count <= limit, "protected-size")
        require(identity(opened) == identity(os.fstat(fd)), "protected-read-identity")
        require(count == opened.st_size, "protected-short-read")
        return b"".join(pieces)
    finally:
        os.close(fd)


def no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "json-duplicate-key")
        value[key] = item
    return value


def closed_json(data):
    def invalid_constant(_value):
        raise Refused("json-number")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                          parse_constant=invalid_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as error:
        raise Refused("json-format") from error


def relative_name(name):
    return (isinstance(name, str) and bool(name) and not name.startswith("/")
            and "\\" not in name and all(ord(c) >= 32 and ord(c) != 127 for c in name)
            and all(part not in ("", ".", "..") for part in name.split("/")))


def hash_mapping(value, absolute=False):
    require(isinstance(value, dict) and 0 < len(value) <= MAX_FILES, "manifest-files")
    for name, digest in value.items():
        require(canonical_absolute(name) if absolute else relative_name(name), "manifest-path")
        require(isinstance(digest, str) and SHA256.fullmatch(digest), "manifest-sha256")
    return value


def closure_name(name):
    # Fixed source profiles do not accept URL syntax, aliases or non-ASCII names.
    return (isinstance(name, str)
            and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*", name) is not None)


def profile_files(value):
    files = hash_mapping(value)
    require(all(closure_name(name) for name in files), "profile-path")
    return files


def validate_owner_key_profile(value):
    require(isinstance(value, dict) and set(value) == {"root", "files"}
            and value["root"] == OWNER_KEY_ROOT, "owner-key-profile")
    files = profile_files(value["files"])
    require(set(files) == OWNER_KEY_FILES, "owner-key-inventory")
    require(all(files[name] == digest for name, digest in OWNER_KEY_SOURCE_PINS.items()), "owner-key-source-pin")
    return value


def validate_aura_profile(value):
    require(isinstance(value, dict) and set(value) == {"root", "entry", "files", "configuration"}
            and value["root"] == AURA_ROOT and value["entry"] == AURA_ENTRY, "aura-profile")
    files = profile_files(value["files"])
    require(set(files) == set(AURA_SOURCE_PINS), "aura-source-inventory")
    require(files == AURA_SOURCE_PINS, "aura-source-pin")
    configuration = value["configuration"]
    require(isinstance(configuration, dict) and set(configuration) == {"path", "sha256"}
            and configuration["path"] == AURA_CONFIG
            and isinstance(configuration["sha256"], str) and SHA256.fullmatch(configuration["sha256"]), "aura-configuration-pin")
    return value


def validate_launcher_profile(value):
    require(isinstance(value, dict) and set(value) == {"root", "files"}
            and value["root"] == LAUNCHER_ROOT, "launcher-profile")
    files = profile_files(value["files"])
    require(set(files) == set(LAUNCHER_SOURCE_PINS), "launcher-inventory")
    require(files == LAUNCHER_SOURCE_PINS, "launcher-source-pin")
    return value


def parse_profiles(value):
    require(isinstance(value, dict) and set(value) <= {"owner_key", "aura", "launcher"}, "manifest-profiles")
    require("launcher" in value, "launcher-profile-unconfigured")
    validate_launcher_profile(value["launcher"])
    require("aura" not in value or "owner_key" in value, "aura-owner-key-profile")
    if "owner_key" in value:
        validate_owner_key_profile(value["owner_key"])
    if "aura" in value:
        validate_aura_profile(value["aura"])
    return value


def parse_manifest(data):
    value = closed_json(data)
    require(isinstance(value, dict) and type(value.get("version")) is int
            and value["version"] in (1, 2), "manifest-format")
    keys = {"version", "kind", "package", "entry", "files", "external_files"}
    if value["version"] == 2:
        keys.add("profiles")
    require(set(value) == keys and value["kind"] == "aukora-gate-package/v" + str(value["version"])
            and value["package"] == PACKAGE
            and value["entry"] == ENTRY, "manifest-format")
    files = hash_mapping(value["files"])
    require({ENTRY, "package.json", *OPERATOR_ENTRIES.values()} <= set(files), "manifest-required-source")
    external = hash_mapping(value["external_files"], absolute=True)
    require(set(external) == set(EXTERNAL_FILES), "manifest-external-files")
    if value["version"] == 2:
        parse_profiles(value["profiles"])
    return value


def package_inventory(root):
    """Closed regular-file inventory; all symlinks, hardlinks and specials refuse."""
    protected_ancestors(root)
    names = []
    def walk(directory, prefix):
        protected_directory(directory)
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                name = prefix + entry.name
                require(relative_name(name), "package-path")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    protected_metadata(metadata, directory=True)
                    walk(entry.path, name + "/")
                else:
                    protected_metadata(metadata)
                    names.append(name)
                    require(len(names) <= MAX_FILES, "package-count")
    walk(root, "")
    return names


def verify_package(root, files):
    """Path-parametrized algorithm used by source fixtures; production fixes root."""
    require(set(package_inventory(root)) == set(files), "package-inventory")
    total = 0
    for name in sorted(files):
        require(relative_name(name), "manifest-path")
        data = protected_read(root + "/" + name)
        total += len(data)
        require(total <= MAX_TOTAL, "package-size")
        require(hashlib.sha256(data).hexdigest() == files[name], "package-hash:" + name)


def validate_signer_epochs(data):
    require(len(data) <= 16384, "signer-epochs-format")
    value = closed_json(data)
    require(isinstance(value, dict) and set(value) == {"version", "kind", "epochs"}
            and type(value["version"]) is int and value["version"] == 1
            and value["kind"] == "aukora-signer-epochs/v1"
            and isinstance(value["epochs"], list) and 0 < len(value["epochs"]) <= 64, "signer-epochs-format")
    previous, hashes = 0, set()
    for row in value["epochs"]:
        require(isinstance(row, dict) and set(row) == {"epoch", "gate_pubkey_sha256"}, "signer-epochs-format")
        epoch, digest = row["epoch"], row["gate_pubkey_sha256"]
        require(type(epoch) is int and epoch == previous + 1 and epoch <= 9007199254740991
                and isinstance(digest, str) and SHA256.fullmatch(digest) and digest not in hashes, "signer-epochs-format")
        previous = epoch
        hashes.add(digest)
    return value


def serve_arguments(arguments):
    if arguments and arguments[0] == "aura":
        raise Refused("aura-context-unconfigured")
    require(arguments and arguments[0] == "serve", "launch-action")
    fixed = {"--home": "/home/aukora-gate", "--run": "/run/aukora-gate",
             "--target-root": "/var/lib/aukora-boundary/targets", "--releases-root": "/opt/aukora-genesis"}
    seen, index = set(), 1
    while index < len(arguments):
        name = arguments[index]
        require(name not in seen, "launch-duplicate")
        seen.add(name)
        if name == "--owner-page":
            index += 1
            continue
        require(name in fixed or name in ("--port", "--gid", "--time-zone"), "launch-option")
        require(index + 1 < len(arguments), "launch-value")
        value = arguments[index + 1]
        if name in fixed:
            require(value == fixed[name], "launch-fixed-path")
        elif name in ("--port", "--gid"):
            require(re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None, "launch-number")
            require(1 <= int(value) <= 65535 if name == "--port" else 1 <= int(value) <= 4294967294, "launch-number")
        else:
            require(len(value) <= 128 and (value == "UTC" or re.fullmatch(r"[A-Za-z_]+(?:/[A-Za-z0-9_+-]+){1,3}", value) is not None), "launch-time-zone")
        index += 2
    require({"--home", "--run", "--target-root", "--gid"} <= seen, "launch-required")
    return list(arguments)


def operator_arguments(arguments):
    role, action = arguments[0], arguments[1] if len(arguments) > 1 else None
    options = {
        ("floor", "show"): {"--floor"},
        ("floor", "check"): {"--floor", "--release-dir", "--approval-state-root"},
        ("floor", "migrate-clock-floor"): {"--floor", "--release-dir", "--approval-state-root"},
        ("approval", "show"): {"--release-dir", "--operation"},
        ("approval", "raise"): {"--release-dir", "--operation", "--run", "--floor"},
        ("approval", "install"): {"--release-dir", "--operation", "--run", "--floor", "--out", "--target-root", "--repin"},
    }
    options[("approval", "migrate-clock-floor")] = options[("approval", "install")]
    options[("approval", "recover-cache")] = options[("approval", "install")]
    require((role, action) in options, "launch-action")
    seen, index = set(), 2
    fixed = {"--floor": "/etc/aukora-approvals/release-floor.json", "--run": "/run/aukora-gate",
             "--target-root": "/var/lib/aukora-boundary/targets"}
    patterns = {"--release-dir": r"/opt/aukora-genesis/release-[0-9a-f]{7}",
                "--approval-state-root": r"/etc/aukora-approvals/[0-9a-f]{40}(?:[0-9a-f]{24})?/state",
                "--out": r"/etc/aukora-approvals/[0-9a-f]{40}(?:[0-9a-f]{24})?/state/gate-state",
                "--operation": r"[0-9a-f]{64}"}
    while index < len(arguments):
        name = arguments[index]
        require(name in options[(role, action)], "launch-option")
        require(name not in seen, "launch-duplicate")
        seen.add(name)
        if name == "--repin":
            index += 1
            continue
        require(index + 1 < len(arguments), "launch-value")
        value = arguments[index + 1]
        require(value == fixed[name] if name in fixed else re.fullmatch(patterns[name], value) is not None, "launch-fixed-path")
        index += 2
    required = set()
    if role == "approval" or action != "show":
        required.add("--release-dir")
    if role == "floor" and action != "show":
        required.add("--approval-state-root")
    if role == "approval" and action in ("install", "migrate-clock-floor", "recover-cache"):
        required.add("--out")
    require(required <= seen, "launch-required")
    return OPERATOR_ENTRIES[role], list(arguments[1:])


def launch_arguments(arguments):
    require(bool(arguments), "launch-action")
    if arguments[0] in ("check-package", "check-runtime"):
        require(len(arguments) == 1, "launch-option")
        return None, ["check-runtime"] if arguments[0] == "check-runtime" else []
    if arguments[0] in OPERATOR_ENTRIES:
        return operator_arguments(arguments)
    if arguments[0] == "aura":
        require(len(arguments) >= 2 and arguments[1] in ("collect", "verify"), "launch-action")
        require(len(arguments) == 2, "launch-option")
        return AURA_ROOT + "/" + AURA_ENTRY, [arguments[1]]
    return ENTRY, serve_arguments(arguments)


def node_environment(environment):
    # Inherited configuration and loader settings never become gate inputs.
    for name in environment:
        normalized = re.sub(r"[^a-z]", "", name.lower())
        require("unsafepreview" not in normalized, "unsafe-preview-environment")
    return {"PATH": "/opt/aukora-node/bin:/usr/bin:/bin", "HOME": "/home/aukora-gate",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def refuse_preview_fields(value):
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", key.lower())
            require("unsafepreview" not in normalized, "unsafe-preview-config")
            refuse_preview_fields(item)
    elif isinstance(value, list):
        for item in value:
            refuse_preview_fields(item)


def validate_aura_context(data):
    require(len(data) <= AURA_MAX_CONFIG, "aura-configuration-size")
    value = closed_json(data)
    refuse_preview_fields(value)
    require(isinstance(value, dict) and set(value) == {"version", "kind", "owner_subject", "store_dir",
            "source", "nostr", "anchors", "python_executable"}
            and type(value["version"]) is int and value["version"] == 1
            and value["kind"] == "aukora-aura-context/v1"
            and aura_text(value["owner_subject"], 73)
            and re.fullmatch(r"aukora:1:[0-9a-f]{64}", value["owner_subject"])
            and aura_data_path(value["store_dir"]) and value["python_executable"] == PYTHON, "aura-configuration-format")
    source, nostr = value["source"], value["nostr"]
    require(isinstance(source, dict) and set(source) == {"db_path", "source_id", "public_key_pem", "key_sha256",
            "max_rows", "max_bytes", "max_record_bytes"}
            and aura_data_path(source["db_path"]) and aura_text(source["source_id"], 128)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", source["source_id"])
            and aura_hex(source["key_sha256"])
            and aura_text(source["public_key_pem"], 16384)
            and re.fullmatch(r"-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?", source["public_key_pem"])
            and aura_bound(source["max_rows"], 50000) and aura_bound(source["max_bytes"], 16 * 1024 * 1024)
            and aura_bound(source["max_record_bytes"], 48 * 1024), "aura-source-format")
    require(isinstance(nostr, dict) and set(nostr) == {"binding", "controller_key_hex", "author_pubkey_hex",
            "owner_pubkey_hex", "author_secret_path"}
            and all(aura_hex(nostr[name]) for name in ("controller_key_hex", "author_pubkey_hex", "owner_pubkey_hex"))
            and aura_data_path(nostr["author_secret_path"]), "aura-nostr-format")
    validate_aura_binding(nostr["binding"], value["owner_subject"], nostr["author_pubkey_hex"])
    anchors = value["anchors"]
    require(isinstance(anchors, list) and len(anchors) <= 4096, "aura-anchors-format")
    previous = 0
    for row in anchors:
        require(isinstance(row, dict) and set(row) == {"seq", "head", "gate_fp", "entry_at", "anchored_at"}
                and aura_bound(row["seq"], 9007199254740991) and row["seq"] > previous
                and aura_hex(row["head"]) and row["gate_fp"] == source["key_sha256"][:16]
                and aura_text(row["entry_at"], 128) and aura_text(row["anchored_at"], 128), "aura-anchors-format")
        previous = row["seq"]
    paths = (value["store_dir"], source["db_path"], nostr["author_secret_path"])
    immutable = (PACKAGE, AURA_ROOT, OWNER_KEY_ROOT, LAUNCHER_ROOT, os.path.dirname(BOOTSTRAP), os.path.dirname(NODE))
    fixed_files = {BOOTSTRAP, NODE, MANIFEST, SIGNER_EPOCHS, AURA_CONFIG}
    for path in paths:
        require(path not in fixed_files and all(os.path.commonpath([path, root]) not in (path, root) for root in immutable), "aura-data-source-overlap")
    require(len(set(paths)) == 3 and source["db_path"] + "-wal" != nostr["author_secret_path"]
            and source["db_path"] + "-shm" != nostr["author_secret_path"], "aura-data-overlap")
    require(all(os.path.commonpath([value["store_dir"], path]) != value["store_dir"]
                for path in (source["db_path"], source["db_path"] + "-wal", source["db_path"] + "-shm", nostr["author_secret_path"])), "aura-data-overlap")
    return value


def aura_text(value, maximum):
    if not isinstance(value, str) or not 0 < len(value) <= maximum:
        return False
    try:
        value.encode("utf-8", "strict")
        return True
    except UnicodeError:
        return False


def aura_hex(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def aura_bound(value, maximum):
    return type(value) is int and 0 < value <= maximum


def aura_data_path(value):
    return (aura_text(value, 4096) and canonical_absolute(value)
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def bounded_binding_json(value, depth=0):
    require(depth <= 32, "aura-binding-format")
    if isinstance(value, str):
        require(aura_text(value, 65536) or value == "", "aura-binding-format")
        require(not any(unicodedata.category(char) in ("Cc", "Zl", "Zp")
                        or 0x202a <= ord(char) <= 0x202e or 0x2066 <= ord(char) <= 0x2069 for char in value), "aura-binding-format")
    elif isinstance(value, dict):
        for key, item in value.items():
            bounded_binding_json(key, depth + 1)
            bounded_binding_json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            bounded_binding_json(item, depth + 1)
    elif type(value) in (int, float):
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        require(finite, "aura-binding-format")
    else:
        require(value is None or type(value) is bool, "aura-binding-format")


def validate_aura_binding(binding, owner_subject, author_pubkey):
    # B's document metadata is open, while its signed statement has an exact
    # current or legacy key set. Preserve that distinction; signature/npub/key
    # cryptography and B's signature-before-shape diagnostics remain D policy.
    require(isinstance(binding, dict) and {"domain", "statement", "signature"} <= set(binding), "aura-binding-format")
    bounded_binding_json(binding)
    require(len(json.dumps(binding, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= 65536, "aura-binding-size")
    statement = binding["statement"]
    keys = {"createdAt", "handle", "nostrPubkeyHex", "npub", "subject"}
    if isinstance(statement, dict) and "safetyVersion" in statement:
        keys.add("safetyVersion")
    require(binding["domain"] == "aukora:nostr-identity-binding:v1"
            and isinstance(statement, dict) and set(statement) == keys
            and statement["subject"] == owner_subject and statement["nostrPubkeyHex"] == author_pubkey
            and aura_text(statement["handle"], 65536) and aura_text(statement["npub"], 65536)
            and isinstance(statement["createdAt"], str)
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", statement["createdAt"])
            and ("safetyVersion" not in statement or aura_bound(statement["safetyVersion"], 9007199254740991))
            and isinstance(binding["signature"], str) and re.fullmatch(r"[0-9a-fA-F]{128}", binding["signature"]), "aura-binding-format")


def aura_data_ancestors(path):
    # These are mutable authenticated source/private-store paths. Their existing
    # owner may differ from root or the collector; no UID or access is invented.
    current = "/"
    for part in [""] + os.path.dirname(path).split("/")[1:]:
        if part:
            current = current.rstrip("/") + "/" + part
        before = os.lstat(current)
        aura_directory_metadata(before)
        fd = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require(identity(before) == identity(os.fstat(fd)), "aura-data-identity")
        finally:
            os.close(fd)


def aura_directory_metadata(metadata):
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o022 == 0, "aura-data-directory")


def verify_aura_custody(value):
    secret = value["nostr"]["author_secret_path"]
    fd, metadata = protected_open(secret)
    try:
        require(metadata.st_mode & 0o077 == 0 and metadata.st_size in (64, 65), "aura-secret-metadata")
        require(identity(metadata) == identity(os.fstat(fd)), "aura-secret-identity")
        # Deliberately no read/hash of the private scoped signer.
    finally:
        os.close(fd)
    for path, directory in ((value["store_dir"], True), (value["source"]["db_path"], False)):
        aura_data_ancestors(path)
        before = os.lstat(path)
        require(stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode), "aura-data-type")
        require(before.st_mode & (0o077 if directory else 0o022) == 0, "aura-data-mode")
        require(before.st_uid == os.getuid() if directory else before.st_nlink == 1, "aura-data-owner-or-link")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(path, flags)
        try:
            require(identity(before) == identity(os.fstat(fd)), "aura-data-identity")
        finally:
            os.close(fd)


def verify_aura_profile(profile):
    validate_aura_profile(profile)
    verify_package(AURA_ROOT, profile["files"])
    data = protected_read(AURA_CONFIG, limit=AURA_MAX_CONFIG)
    require(hashlib.sha256(data).hexdigest() == profile["configuration"]["sha256"], "aura-configuration-hash")
    value = validate_aura_context(data)
    verify_aura_custody(value)
    return value


def verify_source_profiles(manifest):
    profiles = manifest.get("profiles", {})
    if manifest["version"] == 2:
        profile = validate_launcher_profile(profiles.get("launcher"))
        for name in sorted(profile["files"]):
            data = protected_read(LAUNCHER_ROOT + "/" + name)
            require(hashlib.sha256(data).hexdigest() == profile["files"][name], "launcher-hash:" + name)
    if "owner_key" in profiles:
        profile = validate_owner_key_profile(profiles["owner_key"])
        verify_package(OWNER_KEY_ROOT, profile["files"])
    if "aura" in profiles:
        verify_aura_profile(profiles["aura"])


def require_node_profile(manifest, entry):
    # v1 remains a custody-only check-package format in this new source. The
    # gate now statically imports owner-key; no legacy Node fallback is safe.
    require(manifest["version"] == 2 and "owner_key" in manifest["profiles"], "owner-key-profile-unconfigured")
    if entry == AURA_ROOT + "/" + AURA_ENTRY:
        require("aura" in manifest["profiles"], "aura-context-unconfigured")


def verify_external_files(pins):
    external = {}
    for path in EXTERNAL_FILES:
        data = protected_read(path, limit=16384)
        require(hashlib.sha256(data).hexdigest() == pins[path], "external-hash")
        external[path] = data
    validate_signer_epochs(external[SIGNER_EPOCHS])
    return external


def verify_installation():
    # This function only uses named operator paths. No candidate code is imported.
    require(os.path.abspath(__file__) == BOOTSTRAP, "bootstrap-entrypoint")
    protected_read(BOOTSTRAP)
    # Distro Python may be a root-managed interpreter symlink. The interpreter,
    # stdlib, system loader and protected service launch are external anchors.
    protected_ancestors(PYTHON)
    fd, _metadata = protected_open(NODE)
    os.close(fd)
    manifest = parse_manifest(protected_read(MANIFEST, limit=2 * 1024 * 1024))
    verify_package(PACKAGE, manifest["files"])
    verify_external_files(manifest["external_files"])
    verify_source_profiles(manifest)
    return manifest


def main():
    try:
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1, "python-isolation")
        entry, arguments = launch_arguments(sys.argv[1:])
        environment = node_environment(os.environ)
        manifest = verify_installation()
        if entry is None:
            if arguments == ["check-runtime"]:
                # Fixed service preflight, with no code dispatch. A unit may
                # continue to its fixed Node command only after this succeeds.
                require_node_profile(manifest, "bin/selfcheck.mjs")
                print("RUNTIME_VERIFIED")
            else:
                print("PACKAGE_VERIFIED")
            return 0
        require_node_profile(manifest, entry)
        os.chdir("/")
        installed_entry = entry if entry == AURA_ROOT + "/" + AURA_ENTRY else PACKAGE + "/" + entry
        os.execve(NODE, [NODE, installed_entry] + arguments, environment)
    except (Refused, OSError) as error:
        code = str(error) if isinstance(error, Refused) else "protected-io"
        print("REFUSED: " + code, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
