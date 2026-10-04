// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable, public synthetic fixtures only. No persistent key generation.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHmac, createCipheriv, createDecipheriv } from 'node:crypto';
import { ml_dsa65 } from '../../../packages/authority/upstream/vendor/authority/deps/@noble/post-quantum@0.6.1/ml-dsa.js';
import { KitchenSink_ml_kem768_x25519 as kem } from '../../../packages/authority/upstream/vendor/authority/deps/@noble/post-quantum@0.6.1/hybrid.js';
import { ed25519, x25519 } from '../../../packages/authority/upstream/vendor/authority/deps/@noble/curves@2.2.0/ed25519.js';
import { shake256 } from '../../../packages/authority/upstream/vendor/authority/deps/@noble/hashes@2.2.0/sha3.js';
import * as signatures from '../signatures.mjs';
import * as wrapping from '../key-wrap.mjs';

const vectors = JSON.parse(await readFile(new URL('./vectors.json', import.meta.url), 'utf8'));
const fromHex = hex => Uint8Array.from(Buffer.from(hex, 'hex'));
const toHex = bytes => Buffer.from(bytes).toString('hex');
const text = value => Buffer.from(value, 'utf8');
const flip = hex => `${(Number.parseInt(hex.slice(0, 2), 16) ^ 1).toString(16).padStart(2, '0')}${hex.slice(2)}`;
const groups = [];
async function check(name, run) {
  await run();
  groups.push(name);
  console.log(`PASS ${name}`);
}
const v = vectors.kitchen_sink.fields;
const fixtureKeypair = kem.keygen(fromHex(v.seed));
const fixtureEncapsulation = kem.encapsulate(fromHex(v.pk), fromHex(v.randomness));

await check('published KitchenSink draft-03 KAT: public key, encapsulation, combined secret, decapsulation', () => {
  assert.equal(toHex(fixtureKeypair.secretKey), v.sk);
  assert.equal(toHex(fixtureKeypair.publicKey), v.pk);
  assert.equal(toHex(fixtureEncapsulation.cipherText), v.ct);
  assert.equal(toHex(fixtureEncapsulation.sharedSecret), v.ss);
  assert.equal(toHex(kem.decapsulate(fromHex(v.ct), fromHex(v.sk))), v.ss);
});

await check('published NIST ML-DSA-65 verification cases 33 valid and 31 invalid', () => {
  for (const test of vectors.nist_ml_dsa65.tests) {
    assert.equal(ml_dsa65.verify(fromHex(test.signature), fromHex(test.message), fromHex(test.pk), {
      context: fromHex(test.context),
    }), test.expected, `NIST tcId ${test.tcId}`);
  }
});

// RFC 8032 section 7.1 TEST 1; the seed below is a published fixture, not a secret.
const edSeed = fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
await check('published RFC 8032 Ed25519 empty-message KAT', () => {
  assert.equal(toHex(ed25519.getPublicKey(edSeed)), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  assert.equal(toHex(ed25519.sign(new Uint8Array(), edSeed)),
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'
    + 'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
});

const mlPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x42));
const edPair = { secretKey: edSeed, publicKey: ed25519.getPublicKey(edSeed) };
const keys = { mlDsa65: mlPair, ed25519: edPair };
const pubs = { mlDsa65: mlPair.publicKey, ed25519: edPair.publicKey };
const digest = '1234567890abcdef'.repeat(4);
const message = text(digest);
const bundle = signatures.hybridSign(digest, keys);
const badPq = { ...bundle, mlDsa65: flip(bundle.mlDsa65) };

await check('donor-format interoperability: fixed ML context, bare Ed message, deterministic signing', () => {
  assert.deepEqual(Object.keys(bundle), ['schema', 'algorithm', 'message', 'mlDsa65', 'ed25519']);
  assert.equal(bundle.mlDsa65, toHex(ml_dsa65.sign(message, mlPair.secretKey, {
    context: text('aukora-membrane-receipt-v1'), extraEntropy: false,
  })));
  assert.equal(bundle.ed25519, toHex(ed25519.sign(message, edPair.secretKey)));
  assert.equal(signatures.hybridVerify(bundle, digest, pubs), true);
  assert.deepEqual(signatures.hybridSign(digest, keys), bundle);
  assert.equal(toHex(edSeed), '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
});

await check('each signature half, digest and ML context are mandatory', () => {
  assert.equal(signatures.hybridVerify(badPq, digest, pubs), false);
  assert.equal(signatures.hybridVerify({ ...bundle, ed25519: flip(bundle.ed25519) }, digest, pubs), false);
  for (const half of ['mlDsa65', 'ed25519']) {
    const missing = { ...bundle };
    delete missing[half];
    assert.equal(signatures.hybridVerify(missing, digest, pubs), false);
    assert.throws(() => signatures.hybridSign(digest, { [half]: keys[half] }));
  }
  const wrongContext = toHex(ml_dsa65.sign(message, mlPair.secretKey, {
    context: text('other-receipt-context'), extraEntropy: false,
  }));
  assert.equal(signatures.hybridVerify({ ...bundle, mlDsa65: wrongContext }, digest, pubs), false);
  assert.equal(signatures.hybridVerify(bundle, 'f'.repeat(64), pubs), false);
  assert.equal(signatures.hybridVerify(bundle, `${digest}\n`, pubs), false);
  assert.throws(() => signatures.hybridSign(`${digest}\n`, keys));
  assert.throws(() => signatures.hybridSign(digest, {
    ...keys, ed25519: { ...edPair, publicKey: new Uint8Array(32) },
  }));
});

await check('closed signature records reject accessors, symbols, hidden fields and malformed bytes', () => {
  for (const change of [{ schema: 'other' }, { algorithm: 'ed25519' }, { extra: true }, { mlDsa65: '00' }]) {
    assert.equal(signatures.hybridVerify({ ...bundle, ...change }, digest, pubs), false);
  }
  let getterCalls = 0;
  const accessor = { ...bundle };
  Object.defineProperty(accessor, 'message', { enumerable: true, get() { getterCalls++; return digest; } });
  assert.equal(signatures.hybridVerify(accessor, digest, pubs), false);
  assert.equal(getterCalls, 0);
  assert.equal(signatures.hybridVerify({ ...bundle, [Symbol('extra')]: true }, digest, pubs), false);
  const hidden = { ...bundle };
  Object.defineProperty(hidden, 'message', { value: digest, enumerable: false });
  assert.equal(signatures.hybridVerify(hidden, digest, pubs), false);
  const spoofedPublic = new Uint8Array(64);
  Object.defineProperty(spoofedPublic, 'length', { value: 32 });
  assert.equal(signatures.hybridVerify(bundle, digest, { ...pubs, ed25519: spoofedPublic }), false);
  assert.equal(signatures.hybridVerify(bundle, digest, { ...pubs, ed25519: new Proxy(edPair.publicKey, {}) }), false);
});

// Independent backend/reference: Node HMAC implements RFC 9180 labeled HKDF;
// Node/OpenSSL AES-256-GCM checks the complete wrapper, not a self roundtrip.
// The full KitchenSink shared secret comes from the published KEM KAT above.
const suite = Buffer.from('48504b45bc4800010002', 'hex');
const hpkeVersion = text('HPKE-v1');
const empty = Buffer.alloc(0);
function extract(salt, ikm) {
  return createHmac('sha256', salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
}
function expand(prk, info, length) {
  const blocks = [];
  let previous = empty;
  for (let counter = 1; blocks.length * 32 < length; counter++) {
    previous = createHmac('sha256', prk).update(Buffer.concat([previous, info, Buffer.from([counter])])).digest();
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
}
function referenceSchedule(sharedSecret, info) {
  const labeledExtract = (salt, label, ikm = empty) => extract(salt, Buffer.concat([hpkeVersion, suite, text(label), ikm]));
  const labeledExpand = (prk, label, context, length) => expand(prk,
    Buffer.concat([Buffer.from([length >>> 8, length & 255]), hpkeVersion, suite, text(label), context]), length);
  const context = Buffer.concat([Buffer.from([0]), labeledExtract(empty, 'psk_id_hash'), labeledExtract(empty, 'info_hash', info)]);
  const secret = labeledExtract(sharedSecret, 'secret');
  return { key: labeledExpand(secret, 'key', context, 32), nonce: labeledExpand(secret, 'base_nonce', context, 12) };
}
const dataKey = new Uint8Array(32).fill(0x6a);
const context = text('public-fixture:recipient:revision:purpose:v1');
const wrapOptions = { recipientPublicKey: fromHex(v.pk), context, randomness: fromHex(v.randomness) };
const unwrapOptions = { recipientPrivateKey: fromHex(v.sk), recipientPublicKey: fromHex(v.pk), expectedContext: context };
const info = Buffer.concat([text('aukora-prime.pq-hybrid.key-wrap.v1\0'), Buffer.from(v.pk, 'hex'), Buffer.from(v.ct, 'hex'), context]);
const schedule = referenceSchedule(Buffer.from(v.ss, 'hex'), info);
const cipher = createCipheriv('aes-256-gcm', schedule.key, schedule.nonce);
cipher.setAAD(info);
const expectedCiphertext = Buffer.concat([cipher.update(dataKey), cipher.final(), cipher.getAuthTag()]);
const envelope = wrapping.wrapKey(dataKey, wrapOptions);

function fullWrapperReference(candidate) {
  assert.equal(candidate.encapsulation, v.ct);
  assert.equal(candidate.wrapped_key, expectedCiphertext.toString('hex'));
}
await check('hybrid wrap matches independent RFC 9180 HKDF and Node AES-GCM reference', () => {
  fullWrapperReference(envelope);
  assert.equal(envelope.context, toHex(context));
  assert.deepEqual(wrapping.unwrapKey(envelope, unwrapOptions), dataKey);
  assert.deepEqual(dataKey, new Uint8Array(32).fill(0x6a));
  assert.equal(toHex(wrapOptions.randomness), v.randomness);
  assert.equal(toHex(unwrapOptions.recipientPrivateKey), v.sk);
});

await check('PQ and classical encapsulation, ciphertext, context and pinned recipient cannot be altered', () => {
  assert.throws(() => wrapping.unwrapKey({ ...envelope, encapsulation: flip(envelope.encapsulation) }, unwrapOptions));
  const classicalOffset = 1088 * 2;
  const alteredClassical = envelope.encapsulation.slice(0, classicalOffset) + flip(envelope.encapsulation.slice(classicalOffset));
  assert.throws(() => wrapping.unwrapKey({ ...envelope, encapsulation: alteredClassical }, unwrapOptions));
  assert.throws(() => wrapping.unwrapKey({ ...envelope, encapsulation: envelope.encapsulation.slice(classicalOffset) }, unwrapOptions));
  assert.throws(() => wrapping.unwrapKey({ ...envelope, wrapped_key: flip(envelope.wrapped_key) }, unwrapOptions));
  assert.throws(() => wrapping.unwrapKey({ ...envelope, context: flip(envelope.context) }, unwrapOptions));
  assert.throws(() => wrapping.unwrapKey(envelope, { ...unwrapOptions, expectedContext: text('different-fixture-context') }));
  assert.throws(() => wrapping.unwrapKey(envelope, { ...unwrapOptions, recipientPublicKey: fromHex(flip(v.pk)) }));
  assert.throws(() => wrapping.unwrapKey(envelope, { ...unwrapOptions, recipientPrivateKey: new Uint8Array(32).fill(0x41) }));
});

await check('closed wrap profile and native byte bounds reject downgrade shapes and length spoofing', () => {
  for (const change of [{ schema: 'other' }, { profile: 'x25519-only' }, { extra: true }, { wrapped_key: '00' }]) {
    assert.throws(() => wrapping.unwrapKey({ ...envelope, ...change }, unwrapOptions));
  }
  const tooWide = new Uint8Array(64);
  Object.defineProperty(tooWide, 'length', { value: 32 });
  assert.throws(() => wrapping.wrapKey(tooWide, wrapOptions));
  const tooLongContext = new Uint8Array(2048);
  Object.defineProperty(tooLongContext, 'length', { value: 1 });
  assert.throws(() => wrapping.wrapKey(dataKey, { ...wrapOptions, context: tooLongContext }));
  assert.throws(() => wrapping.wrapKey(new Proxy(dataKey, {}), wrapOptions));
  const extraProperty = Uint8Array.from(dataKey);
  extraProperty.extra = true;
  assert.throws(() => wrapping.wrapKey(extraProperty, wrapOptions));
  for (const invalidContext of [new Uint8Array(), new Uint8Array(1025)]) {
    assert.throws(() => wrapping.wrapKey(dataKey, { ...wrapOptions, context: invalidContext }));
  }
  assert.throws(() => wrapping.wrapKey(dataKey, { ...wrapOptions, randomness: new Uint8Array(32) }));
  let getterCalls = 0;
  const accessor = { ...wrapOptions };
  Object.defineProperty(accessor, 'context', { enumerable: true, get() { getterCalls++; return context; } });
  assert.throws(() => wrapping.wrapKey(dataKey, accessor));
  assert.equal(getterCalls, 0);
});

await check('a classical shared secret alone cannot open the hybrid wrapper', () => {
  const expanded = shake256(fromHex(v.seed), { dkLen: 96 });
  const classical = x25519.getSharedSecret(expanded.subarray(64), fromHex(v.ct).subarray(1088));
  const classicalSchedule = referenceSchedule(Buffer.from(classical), info);
  const decipher = createDecipheriv('aes-256-gcm', classicalSchedule.key, classicalSchedule.nonce);
  decipher.setAAD(info);
  decipher.setAuthTag(expectedCiphertext.subarray(32));
  decipher.update(expectedCiphertext.subarray(0, 32));
  assert.throws(() => decipher.final());
  expanded.fill(0); classical.fill(0); classicalSchedule.key.fill(0); classicalSchedule.nonce.fill(0);
});

// Fault injection stays in memory: neither mutated production source nor a
// bypass entrypoint is written. Each mutant has a positive control first.
async function mutant(modulePath, transform) {
  const url = new URL(modulePath, import.meta.url);
  let source = await readFile(url, 'utf8');
  source = transform(source);
  source = source.replace(/from '(\.\.\/[^']+)';/g, (_match, path) => `from '${new URL(path, url).href}';`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
await check('PQ signature verification removal mutant is killed', async () => {
  const mutantSignatures = await mutant('../signatures.mjs', source => {
    const before = 'return mlOk === true && edOk === true;';
    assert.equal(source.split(before).length, 2);
    return source.replace(before, 'return edOk === true;');
  });
  assert.equal(mutantSignatures.hybridVerify(bundle, digest, pubs), true);
  assert.throws(() => assert.equal(mutantSignatures.hybridVerify(badPq, digest, pubs), false), assert.AssertionError);
});

await check('PQ shared-secret removal mutant is killed by independent wrapper reference', async () => {
  const mutantWrapping = await mutant('../key-wrap.mjs', source => {
    const before = /import \{ KitchenSink_ml_kem768_x25519 as kem \} from '([^']+)';/;
    assert.equal(before.test(source), true);
    return source.replace(before, (_match, path) =>
      `import { combineKEMS, expandSeedXof, ecdhKem } from '${path}';\n`
      + "import { ml_kem768 } from '../../packages/authority/upstream/vendor/authority/deps/@noble/post-quantum@0.6.1/ml-kem.js';\n"
      + "import { x25519 } from '../../packages/authority/upstream/vendor/authority/deps/@noble/curves@2.2.0/ed25519.js';\n"
      + "import { shake256 } from '../../packages/authority/upstream/vendor/authority/deps/@noble/hashes@2.2.0/sha3.js';\n"
      + 'const kem = combineKEMS(32, 32, expandSeedXof(shake256), (_pk, _ct, ss) => ss[1], ml_kem768, ecdhKem(x25519));');
  });
  const candidate = mutantWrapping.wrapKey(dataKey, wrapOptions);
  assert.equal(candidate.encapsulation, envelope.encapsulation); // same genuine component ciphertexts
  assert.deepEqual(mutantWrapping.unwrapKey(candidate, unwrapOptions), dataKey); // self-roundtrip misses the downgrade
  assert.throws(() => fullWrapperReference(candidate), assert.AssertionError);
});

await check('both lab modules explicitly grant no authority', () => {
  assert.equal(signatures.pqcGrantsAuthority(), false);
  assert.equal(wrapping.keyWrapGrantsAuthority(), false);
});

mlPair.secretKey.fill(0); edSeed.fill(0); fixtureKeypair.secretKey.fill(0);
fixtureEncapsulation.sharedSecret.fill(0); schedule.key.fill(0); schedule.nonce.fill(0);
console.log(`PASS ${groups.length} focused groups; 2 downgrade mutants killed; no persistent keys or runtime activation`);
