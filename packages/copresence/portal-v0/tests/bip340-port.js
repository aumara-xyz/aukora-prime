// BIP-340 Schnorr signatures (secp256k1) + Nostr NIP-01 event serialization.
// Plain browser script: BigInt arithmetic, no libraries, no imports, no Node APIs.
// `sha256` is injected everywhere: async (Uint8Array) => Uint8Array(32), e.g.
//   async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b))
// NOT constant-time (BigInt). Meant for throwaway per-publish keys, not long-lived secrets.
// Globals defined: b340 (internals), schnorrPubkey, schnorrSign, schnorrVerify, nostrSerialize.

const b340 = (() => {
  const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn; // field prime
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n; // group order
  // Generator in Jacobian coordinates [X, Y, Z] (affine x = X/Z^2, y = Y/Z^3). Infinity is null.
  const G = [
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    1n,
  ];

  const mod = (a, m = P) => { const r = a % m; return r < 0n ? r + m : r; };
  const pow = (b, e, m = P) => {
    let r = 1n;
    for (b = mod(b, m); e > 0n; e >>= 1n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; }
    return r;
  };

  // Jacobian doubling / addition on y^2 = x^3 + 7 (curve coefficient a = 0).
  // A non-null result always has Z != 0: both functions return null for the infinite cases.
  const dbl = (p) => {
    if (!p || p[1] === 0n) return null;
    const [X, Y, Z] = p;
    const YY = mod(Y * Y), S = mod(4n * X * YY), M = mod(3n * X * X);
    const X3 = mod(M * M - 2n * S);
    return [X3, mod(M * (S - X3) - 8n * YY * YY), mod(2n * Y * Z)];
  };
  const add = (p, q) => {
    if (!p) return q;
    if (!q) return p;
    const [X1, Y1, Z1] = p, [X2, Y2, Z2] = q;
    const Z1Z1 = mod(Z1 * Z1), Z2Z2 = mod(Z2 * Z2);
    const U1 = mod(X1 * Z2Z2), U2 = mod(X2 * Z1Z1);
    const S1 = mod(Y1 * Z2 * Z2Z2), S2 = mod(Y2 * Z1 * Z1Z1);
    if (U1 === U2) return S1 === S2 ? dbl(p) : null; // same x: P + P, or P + (-P)
    const H = mod(U2 - U1), R = mod(S2 - S1);
    const HH = mod(H * H), HHH = mod(H * HH), V = mod(U1 * HH);
    const X3 = mod(R * R - HHH - 2n * V);
    return [X3, mod(R * (V - X3) - S1 * HHH), mod(H * Z1 * Z2)];
  };
  const mul = (p, k) => { // double-and-add, least significant bit first; k >= 0
    let r = null;
    for (; k > 0n; k >>= 1n) { if (k & 1n) r = add(r, p); p = dbl(p); }
    return r;
  };
  const affine = (p) => { // -> [x, y] or null
    if (!p) return null;
    const zi = pow(p[2], P - 2n), zi2 = mod(zi * zi);
    return [mod(p[0] * zi2), mod(p[1] * zi2 * zi)];
  };
  const liftX = (x) => { // the curve point with this x and even y, or null
    if (x >= P) return null;
    const c = mod(x * x * x + 7n), y = pow(c, (P + 1n) / 4n);
    if (mod(y * y) !== c) return null;
    return [x, y & 1n ? P - y : y, 1n];
  };

  const need = (b, len, name) => { // Uint8Array check; len === null accepts any length
    if (Object.prototype.toString.call(b) !== "[object Uint8Array]" || (len !== null && b.length !== len))
      throw new TypeError(name + " must be a Uint8Array" + (len === null ? "" : " of " + len + " bytes"));
    return b;
  };
  const toInt = (b) => { let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; };
  const to32 = (v) => {
    const out = new Uint8Array(32);
    for (let i = 31; i >= 0; i--, v >>= 8n) out[i] = Number(v & 0xffn);
    return out;
  };
  const cat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const hash = async (sha256, data) => { // a bare crypto.subtle.digest (ArrayBuffer) is accepted too
    const out = await sha256(data);
    return need(out instanceof ArrayBuffer ? new Uint8Array(out) : out, 32, "sha256 output");
  };
  const tagged = async (sha256, tag, ...parts) => { // BIP-340 tagged hash (tags are ASCII)
    const t = await hash(sha256, Uint8Array.from(tag, (c) => c.charCodeAt(0)));
    return hash(sha256, cat(t, t, ...parts));
  };
  const secret = (sk) => {
    const d = toInt(need(sk, 32, "secret key"));
    if (d === 0n || d >= N) throw new RangeError("secret key must be in 1..n-1");
    return d;
  };

  return { P, N, G, mod, pow, dbl, add, mul, affine, liftX, need, toInt, to32, cat, tagged, secret };
})();

// -> Uint8Array(32) x-only public key. Rejects if sk32 is not 32 bytes encoding 1..n-1.
async function schnorrPubkey(sk32, sha256) {
  return b340.to32(b340.affine(b340.mul(b340.G, b340.secret(sk32)))[0]);
}

// -> Uint8Array(64) signature (BIP-340 default signing). aux32 must be 32 fresh random bytes.
// msg32 is the 32-byte Nostr event id; any length is accepted, as BIP-340 allows.
// The signature is verified before it is returned; a failure rejects instead of returning it.
async function schnorrSign(msg32, sk32, aux32, sha256) {
  const { N, G, mod, mul, affine, need, toInt, to32, tagged } = b340;
  const m = need(msg32, null, "message"), a = need(aux32, 32, "aux_rand");
  const d0 = b340.secret(sk32);
  const [px, py] = affine(mul(G, d0));
  const d = py & 1n ? N - d0 : d0; // secret for the even-y public key
  const pk = to32(px);
  const mask = await tagged(sha256, "BIP0340/aux", a);
  const t = to32(d).map((v, i) => v ^ mask[i]);
  const k0 = mod(toInt(await tagged(sha256, "BIP0340/nonce", t, pk, m)), N);
  if (k0 === 0n) throw new Error("BIP-340 nonce derivation produced zero");
  const [rx, ry] = affine(mul(G, k0));
  const k = ry & 1n ? N - k0 : k0;
  const r = to32(rx);
  const e = mod(toInt(await tagged(sha256, "BIP0340/challenge", r, pk, m)), N);
  const sig = b340.cat(r, to32(mod(k + e * d, N)));
  if (!(await schnorrVerify(m, pk, sig, sha256))) throw new Error("BIP-340 signature failed self-verification");
  return sig;
}

// -> boolean. Never throws or rejects: malformed input (or a failing sha256) is simply false.
async function schnorrVerify(msg32, pk32, sig64, sha256) {
  try {
    const { P, N, G, mod, mul, add, affine, liftX, need, toInt, tagged } = b340;
    const m = need(msg32, null, "message"), pk = need(pk32, 32, "public key"), sig = need(sig64, 64, "signature");
    const rBytes = sig.subarray(0, 32);
    const pt = liftX(toInt(pk)), r = toInt(rBytes), s = toInt(sig.subarray(32));
    if (!pt || r >= P || s >= N) return false;
    const e = mod(toInt(await tagged(sha256, "BIP0340/challenge", rBytes, pk, m)), N);
    const R = affine(add(mul(G, s), mul(pt, mod(-e, N)))); // s*G - e*P
    return R !== null && (R[1] & 1n) === 0n && R[0] === r;
  } catch (_) {
    return false;
  }
}

// -> the NIP-01 serialization whose UTF-8 SHA-256 is the event id:
//    JSON.stringify([0, pubkey, created_at, kind, tags, content])
// Throws on a malformed event rather than serializing something that hashes to a useless id.
function nostrSerialize(evt) {
  const { pubkey, created_at, kind, tags, content } = evt;
  const uint = (v) => Number.isSafeInteger(v) && v >= 0;
  if (typeof pubkey !== "string" || !/^[0-9a-f]{64}$/.test(pubkey)) throw new TypeError("pubkey must be 64 lowercase hex characters");
  if (!uint(created_at)) throw new TypeError("created_at must be a non-negative integer (unix seconds)");
  if (!uint(kind) || kind > 65535) throw new TypeError("kind must be an integer in 0..65535");
  if (!Array.isArray(tags) || !tags.every((t) => Array.isArray(t) && t.every((s) => typeof s === "string")))
    throw new TypeError("tags must be an array of arrays of strings");
  if (typeof content !== "string") throw new TypeError("content must be a string");
  return JSON.stringify([0, pubkey, created_at, kind, tags, content]);
}
