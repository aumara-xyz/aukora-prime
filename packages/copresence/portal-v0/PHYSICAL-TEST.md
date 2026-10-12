# Point-and-Bloom — physical test record

Page version: `portal-v1.5.0`, live at `https://pentora-portal.vercel.app/` (byte-identical to `portal/index.html`).

## What has been run on real devices

| When | Version | Devices | Result | Label |
|---|---|---|---|---|
| 2026-10-10 | v1.0.0 (light only) | MacBook, Chrome + iPhone, Safari | Bloomed on both, same code `1469 283E` | `[RAN]` by the owner, 1 attempt |
| 2026-10-10 | v1.1.0 (light + sound + motion) | same | Bloomed on both, code `B382 0A4E` | `[RAN]` 1 attempt; sound and motion rows not yet read back, so `[NOT VERIFIED]` for those two senses |

Not run: phone to phone, Android, more than one attempt per version, the 20-attempt record, and the approval flow (v1.5.0) on any real device.

The first run had the phone in airplane mode with Wi-Fi still on, so it does not show the handshake working with no network.

## How to run an attempt

1. Open `https://pentora-portal.vercel.app/` on both devices. Allow camera and microphone.
2. Tap or click once on each page. On iPhone, allow motion when asked.
3. Volume up on both.
4. Hold one screen toward the other's camera, about 30 cm apart, and rock the phone slowly (tilt it side to side). Fast circles blur the code.
5. Wait for the star and the code (about 4 s with sound, about 2 s without). Read both codes aloud; they must match.
6. Tap the star. The sheet shows what each sense did.

The page makes no sound until the two devices have locked onto each other.

## How to run an approval attempt (v1.5.0)

1. The computer's page is opened for one text (`…/#approve=<text>`); it shows `approve: <text>` above its code.
2. Open the plain page on the phone and point it at the computer's screen. A card appears on the phone with the same text.
3. Read it. Tap **approve** (or **not now**). Nothing happens between the two devices until that tap.
4. Hold the screens toward each other as usual. Both bloom; the computer saves `copresence-approval-….json`.
5. On the computer's details sheet, **other device signed the words** should read `yes`. On the phone's, **you approved** shows the text.

## What to read back

On each device, after a bloom, the details sheet has:

- **verify** — should read `valid`.
- **sound** — `ECHO_CONFIRMED` means the other device returned a random code this device only sent as sound.
- **sound detail** — bursts sent, band heard, how strongly a tone stood out (dB, high band / low band), microphone and audio state. This line says why a sound check did not complete.
- **motion** — `SEEN_AND_CLAIMED` means the other device's motion sensor reported movement in the same moments this camera saw its code move. A device without a motion sensor (a laptop) cannot be attested, so the phone's sheet reads `NOT_PERFORMED` when its peer is a laptop.

For a counted run: tap a star → **save test log** on each device, then

```bash
node copresence-portal-v0/tests/score-export.mjs <computer-export.json> <phone-export.json>
```

## RESULTS

(paste `score-export.mjs` output and the two details screenshots here)

## Rehearsal gates (no phones) — `[RAN]` 2026-10-11, this machine, v1.5.0

Run from `copresence-portal-v0/`. They exercise the shipped bytes of `portal/index.html`. None involves a real lens, speaker, microphone, motion sensor or two real clocks.

| Gate | Command | Result |
|---|---|---|
| 1. Conformance, written independently from `sim.py` / `verify.mjs` | `node --test tests/gate1-core.test.mjs` | 62 of 62 |
| 1b. Publish path, location privacy, network guard, CSP stamp | `node --test tests/gate1b-publish.test.mjs` | 8 of 8 |
| 1c. Signed sense fields, blind sound-code decoder (both bands), `inspect()` | `node --test tests/gate1c-senses.test.mjs` | 9 of 9 |
| 1d. Approval: text pieces on the wire, the approver's signature over the text, one session and one asker only | `node --test tests/gate1d-approval.test.mjs` | 7 of 7 |
| 2. Optical loop through real QR encode → blur/noise → jsQR, lossy channel | `node --test tests/gate2-optical.test.mjs` | 9 of 9 |
| 3. Two real page instances in headless Chrome, light only | `node tests/gate3-twin.mjs --runs=8` | passed, all receipts `verify.mjs` exit 0 |
| 3. Same, one instance's speaker fed to the other's microphone, synthetic motion, phone decoder path, simulated 720p camera | `node tests/gate3-twin.mjs --runs=10 --audio --motion --nobd --cam=1280x720 --fill=0.55 --blur=0.8` | 10 of 10 bloomed; sound `ECHO_CONFIRMED` on 20 of 20 receipts; motion `SEEN_AND_CLAIMED` on the 10 receipts whose peer had a sensor; median 3.8 s |
| 3. Approval: the phone-shaped instance shows the asked text, a scripted click is ignored, a browser-level click approves; with sound and motion | `node tests/gate3-twin.mjs --runs=8 --audio --motion --nobd --cam=1280x720 --fill=0.55 --blur=0.8 --approve='refine #<64 hex> 0193: tighten the review prompt (3 edits)'` | 8 of 8 bloomed, 8 real taps; the gate skill accepted 8 of 8 for the exact text and refused a different text; sound `ECHO_CONFIRMED` on 16 of 16 |
| Gate skill (Python), including unsigned, wrong-words, lifted-signature, swapped-plan and replay refusals | `uv run --with pytest pytest copresence-portal-v0/prime-skill/copresence-gate/tests -q` (from the repo root) | 27 of 27 |
| Prime Agent refine gate (patched source) | `cargo test -p pa-core --lib refine_gate` | 2 of 2 |

After any edit to `portal/index.html`: `node tests/stamp-csp.mjs`.

## Known limits

- The receipt shows two keys exchanged light (and, when confirmed, sound and motion) within a time window. It does not show a human was present.
- A fast video relay can still pass the light check. The sound echo is not timed.
- The 4-byte spoken code can be ground by a live relay.
- Location is what each device reports about itself.
- One person with several devices can bloom with themselves.
- Sound and motion entries in a receipt are the minting device's own record. The peer's signed echo frame is kept as evidence, but a third party cannot confirm from it that the code was sent only as sound. A commitment to the code in the sender's own signed frames would close that; it is not built.
- The motion check compares the peer's own signed claim of movement with what this camera saw. A peer that always claims movement passes whenever its code is seen moving for any reason other than this device's own motion.
- An approval shows that the approving device displayed the text and its key signed it after a tap the browser reported as real. It does not show who tapped, or that the asking computer then did what the text says.
- On iPhone, sound may play quietly or through the earpiece while the microphone is open; `sound detail` shows what was measured.
