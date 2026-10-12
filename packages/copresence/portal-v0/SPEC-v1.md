# SPEC-v1: Co-presence Point-and-Bloom Protocol Specification

**Status:** Frozen Specification for Implementation (Opus 5.5 One-Shot Target)  
**Date:** 2026-10-09  
**Repository:** `aumara-xyz/aukora-contact`  
**Location:** `copresence-portal-v0/SPEC-v1.md`  
**Reference Simulator:** `copresence-portal-v0/toy/sim.py` (5/5 positive & negative scenarios passed)  
**Independent Verifier:** `copresence-portal-v0/verify.mjs` (Node 22 standalone)

---

## 1. Architectural Philosophy & UX Law

1. **Point and Bloom**: No "Start Ceremony", no "Initiator" vs "Responder" buttons, no manual mode selection. Two devices point cameras at each other; both screens bloom the identical 110-cell ternary Pentora pattern within 3–4 seconds.
2. **Zero Visible Loading States**: No loading spinners, no "Connecting..." text, no progress bars. The Pentora grid is rendered immediately at $t=0$. Hardware phases are signaled solely via an ambient 3px corner phase beacon dot.
3. **Strict In-Ceremony Quiescence**: Strictly zero `fetch()` and zero `WebSocket` network traffic during the handshake. All cryptographic proofs occur exclusively across the optical line-of-sight channel. Nostr relay broadcasting is strictly post-ceremony, manual opt-in only.
4. **Honest Labeling (§17)**: Client-reported coordinates are never labeled as measured. Receipts emit `CONSISTENT_CLAIMED` (`position_source: SELF_REPORTED_UNVERIFIABLE`). Confidence percentages are omitted on self-reported inputs.

---

## 2. State Machine Specification

```
                  ┌──────────────┐
                  │     FACE     │ (Passive rotating identity beacon)
                  └──────┬───────┘
                         │ Camera detects peer's valid FACE/SEENYOU frame
                         ▼
                  ┌──────────────┐
                  │   SEENYOU    │ (Names target peer public key)
                  └──────┬───────┘
                         │ Peer confirms target; Tiebreak resolves roles
                         ├──────────────────────────────┐
                         │ Higher pk: Responder B       │ Lower pk: Initiator A
                         ▼                              ▼
                  ┌──────────────┐               ┌──────────────┐
                  │  HANDSHAKE   │               │   SEENYOU    │ (Awaiting HANDSHAKE)
                  │  (signs C)   │               └──────┬───────┘
                  └──────┬───────┘                      │ Sees HANDSHAKE frame
                         │ Emits sig_B                  │ Signs C (sig_A), mints R
                         └──────────────┬───────────────┘
                                        ▼
                                 ┌──────────────┐
                                 │    BLOOM     │ (Shared 110-cell pattern bloom)
                                 └──────────────┘
```

### State 1: `FACE` (Passive Beacon)
- **Display**: Emits rotating QR frame with ephemeral identity:
  ```json
  {
    "v": 1,
    "type": "FACE",
    "pk": "<device_p256_pubkey_130_hex>",
    "nonce": "<stable_session_nonce_16_hex>",
    "t": 1791538000,
    "i": 1,
    "geo": { "lat": 37.774929, "lon": -122.419416, "acc": 8.0 }
  }
  ```
  Frame signed by device's P-256 private key: `{"F": f, "sig_F": "<raw_p1363_128_hex>"}`.
- **Rotation**: Frame rotates every $1000\text{ ms}$ (increments `i`, updates `t`, re-signs).
- **Scanner Duty**: 2 fps idle decode loop.
- **Transition**: On detecting peer's `FACE` or `SEENYOU` frame with valid `sig_F` and $|now - t| \le 5\text{s}$, transitions to `SEENYOU`.

### State 2: `SEENYOU` (Target Naming)
- **Display**: Emits frame targeting peer's public key:
  ```json
  {
    "v": 1,
    "type": "SEENYOU",
    "my_pk": "<my_pk>",
    "target_pk": "<peer_pk>",
    "my_nonce": "<my_session_nonce>",
    "peer_nonce": "<peer_session_nonce>",
    "t": 1791538001,
    "i": 2,
    "geo": { ... }
  }
  ```
- **Scanner Duty**: Ramps to 10 fps continuous decode loop.
- **Transition & Tiebreak Rule**:
  When camera reads peer's `SEENYOU` frame targeting this device:
  - If `my_pk < peer_pk` (lexicographical hex comparison):
    - Assigned **Initiator A**. Remains in `SEENYOU` awaiting `HANDSHAKE` frame.
  - If `my_pk > peer_pk`:
    - Assigned **Responder B**. Immediately computes Receipt Core $C$, signs $C$ ($sig_B$), and transitions to `HANDSHAKE`.

### State 3: `HANDSHAKE` (Cryptographic Core Binding)
- **Action (Responder B)**:
  Computes byte-exact core:
  $$C = \text{SHA-256}(\text{"copresence.v0"} \parallel 0x00 \parallel pk_A \parallel pk_B \parallel nonce_A \parallel nonce_B \parallel \text{BE64}(t_B))$$
  Signs $C$ under $pk_B$ to produce $sig_B$.
- **Display (Responder B)**:
  Emits `HANDSHAKE` frame:
  ```json
  {
    "v": 1,
    "type": "HANDSHAKE",
    "pk_A": "<pk_A>",
    "pk_B": "<pk_B>",
    "nonce_A": "<nonce_A>",
    "nonce_B": "<nonce_B>",
    "t_A": 1791538000,
    "t_B": 1791538002,
    "sig_B": "<sig_B>",
    "t": 1791538002,
    "i": 3,
    "geo": { ... }
  }
  ```
- **Action (Initiator A)**:
  On decoding `HANDSHAKE`, recomputes $C$, verifies $sig_B$, signs $C$ ($sig_A$), and mints Receipt $R$.
  Transitions to `BLOOM`, emitting a `BLOOM` confirmation frame:
  `{"v": 1, "type": "BLOOM", "pk": "<pk_A>", "sig_A": "<sig_A>", "t": now, "i": 4}`.

### State 4: `BLOOM` (Shared Convergence)
- **Action**:
  Both devices cease camera operations (`videoStream.getTracks().forEach(t => t.stop())`) and extinguish QR rotation.
  Renders the 110-cell ternary Pentora grid derived from $C$.
  Displays 8-character blue hex digest (`dHex.substring(0, 8)`).
  Evaluates Sentinel security model over claimed telemetry.
  Offers post-ceremony manual opt-in Nostr broadcast and JSON export.

---

## 3. Detailed Resolutions of the Five Open Questions

### Q1: Frame Rotation Rate vs. Live-Camera Lock
- **Decision**: **Freeze 1000 ms rotation with self-contained frames (QR Version 13–14, ~320 bytes). Reject the 500 ms preamble approach.**
- **Quantitative Proof**:
  - Scan loop executes at 10 fps (100 ms decode cadence).
  - A 1000 ms frame window provides **10 decode opportunities**.
  - In v0 testing, median camera scan-lock was measured at 240 ms.
  - With single-frame decode success $p \approx 0.65$ under hand motion, the probability of lock per cycle is:
    $$P(\text{lock}) = 1 - (1 - 0.65)^{10} = 1 - 0.35^{10} \approx 99.997\%$$
  - At 30 cm viewing distance on a 70 mm screen, QR v14 modules measure $0.96\text{ mm}$ ($\sim 7$ pixels on 1080p preview), well above the Nyquist decoding limit ($\ge 2.5$ pixels/module).
  - *Why reject preambles*: A 500 ms preamble architecture splits frames into 2 speeds, creating an unrecoverable desynchronization state if a device misses the preamble frame. 1000 ms self-contained frames guarantee that any single captured frame contains complete cryptographic context.

### Q2: Symmetric-Start Collision Tiebreak
- **Decision**: **Lexicographical comparison of uncompressed P-256 public keys.**
- **Formal Rule**:
  $$\text{Role} = \begin{cases} \text{INITIATOR\_A} & \text{if } pk_{\text{self}} < pk_{\text{peer}} \\ \text{RESPONDER\_B} & \text{if } pk_{\text{self}} > pk_{\text{peer}} \end{cases}$$
- **Deadlock-Free Proof**:
  - $pk_A \ne pk_B$ with probability $1 - 2^{-256}$.
  - The ordering is strict, total, and identical on both devices.
  - Devices with higher public keys always transition to `HANDSHAKE` and emit $sig_B$; devices with lower keys always await `HANDSHAKE` and emit $sig_A$.
  - Simulated across all interleavings in `toy/sim.py` (Scenario 3): resolves collision in $\le 2.0\text{ seconds}$ with zero deadlocks.

### Q3: Multi-Device Rooms
- **Decision**: **Strictly pairwise blooms only for v1.**
- **Exclusion Algorithm**:
  1. Devices in `FACE` lock on the first peer frame meeting optical prominence criteria (central focus $\ge 40\%$ canvas area).
  2. Once locked on $target\_pk$, the device transitions to `SEENYOU(target_pk)` and sets an exclusion filter:
     $$\text{DROP if } (f.type == \text{"SEENYOU"} \land f.target\_pk \ne my\_pk) \lor (f.type == \text{"HANDSHAKE"} \land f.pk\_A \ne my\_pk)$$
  3. Third-party bystander devices ignore frames not addressed to their public key, preventing state pollution.

### Q4: Battery & Render Loop Duty Cycle
- **Duty Cycle Specification**:
  - `FACE` (Idle Search): Camera active, decode throttled to **2 fps** (500 ms sleep). Power: $\sim 420\text{ mW}$ ($< 5\%$ CPU).
  - `SEENYOU` / `HANDSHAKE` (Active Alignment): Decode ramps to **10 fps** (100 ms cadence). Power: $\sim 780\text{ mW}$ ($25\%$ CPU).
  - `BLOOM` (Terminal State): Camera hardware powered down completely (`track.stop()`), decode loop terminated. Power: $< 80\text{ mW}$ ($< 1\%$ CPU).
- **Battery Impact**:
  Average ceremony duration is $3.5\text{ seconds}$.
  $$\text{Energy per ceremony} = 780\text{ mW} \times 3.5\text{s} \approx 2.73\text{ Joules} \approx 0.00076\text{ Wh}$$
  On a standard 4,000 mAh (15.2 Wh) smartphone battery, each ceremony consumes **0.005%** of battery capacity. Continuous idle search consumes $2.76\%$ battery per hour.

### Q5: Decomposition of "Always Loading" (No Visible Loading Law)
- **Phase Breakdown**:
  1. *Bundle/DOM Load*: $< 15\text{ ms}$ (cached).
  2. *IndexedDB P-256 Key Retrieval*: $< 15\text{ ms}$ (generation: $70\text{ ms}$).
  3. *Camera Permission & Warmup*: $200 - 450\text{ ms}$ once granted.
  4. *Geolocation Acquisition*: $1500 - 4000\text{ ms}$. **LAW: Geolocation is strictly asynchronous and non-blocking**. Ceremony boots immediately; GPS latches when available.
- **Ambient Phase Dot Spec**:
  A 3px circle embedded in the top-right border of the Pentora face visualizes phase state without any spinners or text:
  - `Slate (#334155)`: Initializing Crypto/IDB.
  - `Amber (#f59e0b)`: Camera Active, Searching.
  - `Cyan (#38bdf8)`: Peer Locked (`SEENYOU`).
  - `Emerald (#10b981)`: Bloom Reached.
- **Console Phase Trace**:
  `[PORTAL_PHASE] t=12ms IDB_KEY_READY | t=240ms CAMERA_READY | t=2100ms PEER_LOCKED | t=3200ms BLOOM_MINTED`.

---

## 4. Frozen Invariants (Unchanged & Binding)

### Cryptographic Core C
$$C = \text{SHA-256}(\text{"copresence.v0"} \parallel 0x00 \parallel pk_A \parallel pk_B \parallel nonce_A \parallel nonce_B \parallel \text{BE64}(t_B))$$
- Keys: P-256 uncompressed 65-byte hex (`04...`, 130 chars).
- Signatures: IEEE P1363 raw $r \parallel s$, 64-byte hex (128 chars).
- Nonces: 8 bytes random hex (16 chars), stable per session.
- Window: $0 \le t_B - t_A \le 10\text{s}$.

### Sentinel Security Model & Vocabulary
- **`CONSISTENT_CLAIMED`**: Emitted when coordinates are within bounds.
  `position_source: "SELF_REPORTED_UNVERIFIABLE"`.
  *Confidence percentage is strictly omitted.*
- **`SUSPICIOUS`**: Emitted if:
  - Distance exceeds $acc_A + acc_B + 50\text{m}$.
  - Transit latency $> 380\text{ms}$ (video relay F1) or $< 25\text{ms}$ (synthetic bypass).
  - Accuracy $acc \le 0$ or $acc < 1.0\text{m}$ (synthetic perfection).
  - Clock skew $t_B - t_A < 0$ or $> 7.5\text{s}$.

### Geolocation Privacy Defaults
- Nostr event tags default to **Coarse (~100m)** rounding:
  `["geo_coarse", "37.775,-122.419"]`, `["geo_privacy", "coarse_100m"]`.
- Option to redact completely or opt into exact coordinates.

### Verbatim "Does Not Prove" List
A valid receipt $R$ proves only that whoever controlled each ephemeral key completed the optical exchange within the time window. It does NOT prove:
1. That two different humans were present;
2. That any human was present;
3. That the devices belong to anyone in particular;
4. That the pairing was not relayed by a determined attacker with a fast video link;
5. Anything about location beyond line-of-sight between screen and camera;
6. Anything after the moment of the ceremony.

---

## 5. Specification Changelog (Draft 1 -> SPEC-v1)

| Change | Rationale |
|---|---|
| **Session Nonce Stability** | Draft 1 rotated nonces per frame tick, causing signature mismatch across ticks. SPEC-v1 locks `session_nonce` per ceremony while rotating frame indices $i$ and timestamps $t$. |
| **Lexicographical Tiebreak** | Formalized lower $pk$ as Initiator A and higher $pk$ as Responder B to eliminate symmetric-start deadlock. |
| **1000 ms Rotation Frozen** | Proved 10 decode opportunities at 10 fps provides $99.99\%$ single-cycle lock; rejected preamble complexity. |
| **Coarse Location Tagging Default** | Prevents public relay location tracking while attesting venue-level proximity. |
| **Duty Cycle Throttling (2 fps / 10 fps)** | Reduces battery drain to $0.005\%$ per ceremony and prevents mobile thermal throttling. |
| **Non-blocking Geolocation** | Prevents Peter's "always loading" bug by booting immediately without GPS stalls. |

---

## 6. Audio Rendezvous Layer (v1.1 Specification)

### 6.1 Physical Channel Principles
1. **Independent Physical Carrier**: Optical channels verify electromagnetic line-of-sight ($c \approx 3 \times 10^8\text{ m/s}$). Acoustic channels verify local air pressure wave propagation ($v \approx 343\text{ m/s}$). Compounding optical and acoustic channels forces an attacker to defeat two physically disjoint media simultaneously.
2. **Ultrasonic Inaudibility**: The data chirp operates in the $18.0\text{ kHz} - 21.0\text{ kHz}$ band, inaudible to adults and well above normal human speech ($< 4\text{ kHz}$).
3. **Propagation Timing**: At typical direct screen-to-screen distance ($15 - 50\text{ cm}$), acoustic transit time is $0.44\text{ ms} - 1.46\text{ ms}$. With standard browser Web Audio API / OS buffer latency ($10 - 40\text{ ms}$), total local transit delay measures $15\text{ ms} - 80\text{ ms}$.

### 6.2 Protocol Exchange
- **Initiator A**: During `SEENYOU` $\to$ `HANDSHAKE`, emits a 2.0-second ultrasonic chirp sequence encoding a 16-byte random acoustic nonce (`audio_nonce`, 32 hex chars) using frequency-shift keying (FSK) or orthogonal chirp spread spectrum.
- **Responder B**: Microphone captures ambient audio, detects ultrasonic energy, demodulates the chirp, and validates `audio_nonce`.
- **Receipt Extension (Optional `audio` field)**:
  ```json
  "audio": {
    "nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "delay_ms": 24.5,
    "matched": true
  }
  ```
- **Sentinel Enforcement**:
  - `audio_delay_ms > 150.0 ms`: Anomaly `SUSPICIOUS_ACOUSTIC_RELAY_DELAY` (remote VoIP/WebRTC relay link detected).
  - `audio_delay_ms < 5.0 ms`: Anomaly `SUSPICIOUS_ACOUSTIC_DELAY_IMPOSSIBLE` (sub-buffer synthetic spoofing).
  - `matched == false`: Anomaly `ACOUSTIC_NONCE_MISMATCH`.
  - `matched == true` and $5\text{ms} \le \text{delay} \le 150\text{ms}$: Strengthens `CONSISTENT_CLAIMED` (`acoustic_channel: "VERIFIED_LOCAL"`).
  - **Fail-Open Law**: If audio hardware permission is denied or audio is absent, the field is simply omitted (`acoustic_channel: "NOT_PERFORMED"`). Receipts without audio remain fully valid under v0/v1 rules.

### 6.3 Ritual Bloom Feedback
- Upon reaching `BLOOM`, both devices emit a brief harmonized chord (e.g. root fifth resolving to octave, $440\text{ Hz} \to 660\text{ Hz} \to 880\text{ Hz}$) through the device speakers.
- **Zero-Action Law**: Ambient audio feedback only; no manual buttons or user interaction required.

