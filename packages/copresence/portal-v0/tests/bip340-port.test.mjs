// Gates for bip340-port.js (BIP-340 Schnorr signer + NIP-01 serializer for the single-file portal).
// Run: node --test copresence-portal-v0/tests/bip340-port.test.mjs
//
//  (a) every row of the official BIP-340 test-vector file (signing rows and verify-only rows)
//  (b) byte-for-byte differential check against Prime's existing vendored Noble reference
//  (c) NIP-01 serialization + event id against values computed independently of the port
import { before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const PORT_JS = path.join(here, 'bip340-port.js');
const REFERENCE_MJS = path.resolve(here, '../../../../plugins/aukora-nostr/lib/vendor/noble-curves/curves/secp256k1.js');
const source = fs.readFileSync(PORT_JS, 'utf8');

// Indirect eval runs the exact file bytes as a classic (non-module, sloppy) script in the global
// scope, which is how the page will run them. A file containing import/export or top-level await
// would fail to parse here. b340 (the internals object) is pulled out only for the curve tests.
const { schnorrPubkey, schnorrSign, schnorrVerify, nostrSerialize, b340 } = (0, eval)(
  source + '\n;({ schnorrPubkey, schnorrSign, schnorrVerify, nostrSerialize, b340 });',
);

// The injected hash, written the way the browser page will write it.
const sha256 = async (bytes) => new Uint8Array(await webcrypto.subtle.digest('SHA-256', bytes));

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (h) => {
  assert.match(h, /^([0-9a-fA-F]{2})*$/, `not hex: ${h}`);
  return new Uint8Array(Buffer.from(h, 'hex')); // plain Uint8Array, as in a browser
};
const N_HEX = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';

// ---------------------------------------------------------------------------------------------
// (a) Official vectors, embedded verbatim (all 19 rows, index 0..18) from
//     https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340/test-vectors.csv
//     Fetched 2026-10-10. Line endings are LF here; upstream uses CRLF. UPSTREAM_SHA256 is the
//     SHA-256 of the upstream bytes, so any edit to the embedded rows fails the first test below.
// ---------------------------------------------------------------------------------------------
const UPSTREAM_SHA256 = '34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d';
const VECTORS_CSV = `
index,secret key,public key,aux_rand,message,signature,verification result,comment
0,0000000000000000000000000000000000000000000000000000000000000003,F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,0000000000000000000000000000000000000000000000000000000000000000,0000000000000000000000000000000000000000000000000000000000000000,E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0,TRUE,
1,B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,0000000000000000000000000000000000000000000000000000000000000001,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A,TRUE,
2,C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9,DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8,C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906,7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C,5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7,TRUE,
3,0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710,25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3,TRUE,test fails if msg is reduced modulo p or n
4,,D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9,,4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703,00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4,TRUE,
5,,EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,public key not on the curve
6,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2,FALSE,has_even_y(R) is false
7,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD,FALSE,negated message
8,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6,FALSE,negated s value
9,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051,FALSE,sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
10,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197,FALSE,sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
11,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,sig[0:32] is not an X coordinate on the curve
12,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,sig[0:32] is equal to field size
13,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,FALSE,sig[32:64] is equal to curve order
14,,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,public key is not a valid X coordinate because it exceeds the field size
15,0340034003400340034003400340034003400340034003400340034003400340,778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117,0000000000000000000000000000000000000000000000000000000000000000,,71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63,TRUE,message of size 0 (added 2022-12)
16,0340034003400340034003400340034003400340034003400340034003400340,778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117,0000000000000000000000000000000000000000000000000000000000000000,11,08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF,TRUE,message of size 1 (added 2022-12)
17,0340034003400340034003400340034003400340034003400340034003400340,778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117,0000000000000000000000000000000000000000000000000000000000000000,0102030405060708090A0B0C0D0E0F1011,5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5,TRUE,message of size 17 (added 2022-12)
18,0340034003400340034003400340034003400340034003400340034003400340,778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117,0000000000000000000000000000000000000000000000000000000000000000,99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999,403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367,TRUE,message of size 100 (added 2022-12)
`;

const CSV_HEADER = 'index,secret key,public key,aux_rand,message,signature,verification result,comment';
const csvLines = VECTORS_CSV.trim().split('\n');
const vectors = csvLines.slice(1).map((line) => {
  const [index, sk, pk, aux, msg, sig, result, ...comment] = line.split(',');
  return { index: Number(index), sk, pk, aux, msg, sig, result, comment: comment.join(',') };
});

describe('(a) official BIP-340 test vectors', () => {
  it('embedded CSV is the unmodified upstream file with all 19 rows', () => {
    const upstreamBytes = csvLines.join('\r\n') + '\r\n';
    assert.equal(createHash('sha256').update(upstreamBytes, 'utf8').digest('hex'), UPSTREAM_SHA256);
    assert.equal(csvLines[0], CSV_HEADER);
    assert.deepEqual(vectors.map((v) => v.index), Array.from({ length: 19 }, (_, i) => i));
    assert.equal(vectors.filter((v) => v.sk !== '').length, 8, 'signing rows');
    assert.equal(vectors.filter((v) => v.sk === '').length, 11, 'verification-only rows');
    assert.equal(vectors.filter((v) => v.result === 'TRUE').length, 9);
    assert.equal(vectors.filter((v) => v.result === 'FALSE').length, 10);
  });

  for (const v of vectors) {
    const kind = v.sk !== '' ? 'sign + verify' : 'verify only';
    it(`vector ${v.index} (${kind}) -> ${v.result}${v.comment ? ` [${v.comment}]` : ''}`, async () => {
      assert.ok(v.result === 'TRUE' || v.result === 'FALSE');
      const msg = unhex(v.msg);
      if (v.sk !== '') {
        const sk = unhex(v.sk);
        assert.equal(hex(await schnorrPubkey(sk, sha256)), v.pk.toLowerCase(), 'pubkey');
        assert.equal(hex(await schnorrSign(msg, sk, unhex(v.aux), sha256)), v.sig.toLowerCase(), 'signature');
      }
      assert.equal(await schnorrVerify(msg, unhex(v.pk), unhex(v.sig), sha256), v.result === 'TRUE', 'verify');
    });
  }
});

// ---------------------------------------------------------------------------------------------
// (b) The existing independent Noble implementation produces the donor's 25 deterministic tuples.
// ---------------------------------------------------------------------------------------------
const JS_REFERENCE = `
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const { schnorr } = await import(pathToFileURL(process.argv[1]).href);
const hex = bytes => Buffer.from(bytes).toString('hex');
const h = (label, i) => createHash('sha256').update('bip340-port/' + label + '/' + i).digest();
const n = schnorr.Point.Fn.ORDER;
const rows = [];
for (let i = 0; i < 25; i++) {
  let d0 = BigInt('0x' + hex(h('sk', i))) % (n - 1n) + 1n;
  let msg = h('msg', i), aux = h('aux', i);
  if (i === 0) d0 = 1n;
  if (i === 1) d0 = n - 1n;
  if (i === 2) aux = Buffer.alloc(32);
  if (i === 3) aux = Buffer.alloc(32, 255);
  if (i === 4) msg = Buffer.alloc(32);
  if (i === 5) msg = Buffer.alloc(32, 255);
  const sk = Buffer.from(d0.toString(16).padStart(64, '0'), 'hex');
  const pk = schnorr.getPublicKey(sk), sig = schnorr.sign(msg, sk, aux);
  if (!schnorr.verify(sig, msg, pk)) throw new Error('reference_signature_invalid');
  const odd_y = (schnorr.Point.BASE.multiply(d0).toAffine().y & 1n) !== 0n;
  rows.push({ sk: hex(sk), msg: hex(msg), aux: hex(aux), pk: hex(pk), sig: hex(sig), odd_y });
}
process.stdout.write(JSON.stringify(rows));
`;

describe('(b) differential vs Prime vendored Noble', () => {
  let rows;
  before(() => {
    const out = execFileSync(process.execPath, ['--input-type=module', '-e', JS_REFERENCE, REFERENCE_MJS], { encoding: 'utf8' });
    rows = JSON.parse(out);
  });

  it('independent reference produced 25 distinct tuples covering both public-key parities', () => {
    assert.equal(rows.length, 25);
    assert.equal(new Set(rows.map((r) => r.sig)).size, 25);
    for (const r of rows) {
      assert.match(r.sk, /^[0-9a-f]{64}$/);
      assert.match(r.pk, /^[0-9a-f]{64}$/);
      assert.match(r.sig, /^[0-9a-f]{128}$/);
    }
    assert.equal(rows[0].sk, '1'.padStart(64, '0'));
    assert.equal(rows[1].sk, N_HEX.slice(0, -1) + '0'); // n - 1
    assert.ok(rows.some((r) => r.odd_y) && rows.some((r) => !r.odd_y), 'both d and n-d branches exercised');
  });

  it('port reproduces all 25 pubkeys and signatures byte-for-byte', async () => {
    let checked = 0;
    for (const [i, r] of rows.entries()) {
      const sk = unhex(r.sk), msg = unhex(r.msg), aux = unhex(r.aux);
      assert.equal(hex(await schnorrPubkey(sk, sha256)), r.pk, `tuple ${i}: pubkey`);
      assert.equal(hex(await schnorrSign(msg, sk, aux, sha256)), r.sig, `tuple ${i}: signature`);
      assert.equal(await schnorrVerify(msg, unhex(r.pk), unhex(r.sig), sha256), true, `tuple ${i}: verify`);
      checked++;
    }
    assert.equal(checked, 25);
  });

  it('port rejects every reference signature after a one-bit change to sig, msg or pubkey', async () => {
    for (const [i, r] of rows.entries()) {
      const msg = unhex(r.msg), pk = unhex(r.pk), sig = unhex(r.sig);
      const flip = (bytes, bit) => { const c = bytes.slice(); c[bit >> 3] ^= 1 << (bit & 7); return c; };
      assert.equal(await schnorrVerify(msg, pk, flip(sig, (i * 37) % 512), sha256), false, `tuple ${i}: sig`);
      assert.equal(await schnorrVerify(flip(msg, (i * 11) % 256), pk, sig, sha256), false, `tuple ${i}: msg`);
      assert.equal(await schnorrVerify(msg, flip(pk, (i * 13) % 256), sig, sha256), false, `tuple ${i}: pk`);
    }
  });
});

// ---------------------------------------------------------------------------------------------
// (c) NIP-01 serialization and event id.
//     EXPECTED is written out by hand (String.raw, so the backslashes below are the literal JSON
//     escapes) rather than produced by JSON.stringify. PINNED_EVENT_ID was computed outside
//     JavaScript altogether: python3 json.dumps(..., separators=(",", ":"), ensure_ascii=False)
//     over the same event spelled with numeric code-point escapes, then hashlib.sha256 of the
//     UTF-8 bytes.
// ---------------------------------------------------------------------------------------------
const LINE_SEP = ' '; // legal unescaped inside a JSON string
const DEL = '\u007f'; // not a JSON control character: stays raw
const E_COMBINING_ACUTE = 'é'; // decomposed; must not be normalized to U+00E9

const EVENT = {
  pubkey: 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
  created_at: 1760000000,
  kind: 1,
  tags: [
    ['e', '5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36', 'wss://relay.example.com', 'root'],
    ['t', 'co-presence'],
    ['alt', 'say "hi"\n\ttwo \\ lines'],
    ['emoji', '🤝', '日本語', ''],
  ],
  content:
    'Héllo "wörld" — 你好 🌍\nline two\r\n\ttabbed \\ back / slash ' + LINE_SEP +
    ' <b>&amp;</b> \u0001 \b\f' + DEL + ' ' + E_COMBINING_ACUTE,
};

const EXPECTED =
  String.raw`[0,"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",1760000000,1,` +
  String.raw`[["e","5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36","wss://relay.example.com","root"],` +
  String.raw`["t","co-presence"],["alt","say \"hi\"\n\ttwo \\ lines"],["emoji","🤝","日本語",""]],` +
  String.raw`"Héllo \"wörld\" — 你好 🌍\nline two\r\n\ttabbed \\ back / slash ` + LINE_SEP +
  String.raw` <b>&amp;</b> \u0001 \b\f` + DEL + ' ' + E_COMBINING_ACUTE + '"]';

const PINNED_EVENT_ID = '80f89317389c48239b1211ff606f379cac2926ea51ec45d70b1a183bdb3170df';

const eventId = async (evt) => hex(await sha256(new TextEncoder().encode(nostrSerialize(evt))));

describe('(c) nostrSerialize / NIP-01 event id', () => {
  it('serializes unicode, quotes, newlines, control characters and nested tags exactly', () => {
    assert.equal(nostrSerialize(EVENT), EXPECTED);
  });

  it('event id equals sha256 of the UTF-8 bytes computed independently with node:crypto', async () => {
    const independent = createHash('sha256').update(Buffer.from(EXPECTED, 'utf8')).digest('hex');
    assert.equal(independent, PINNED_EVENT_ID, 'hand-written serialization vs python-computed id');
    assert.equal(await eventId(EVENT), independent);
  });

  it('ignores id/sig/extra fields and key order', () => {
    const shuffled = { sig: 'ff', content: EVENT.content, id: '00', tags: EVENT.tags, kind: 1, extra: {}, created_at: EVENT.created_at, pubkey: EVENT.pubkey };
    assert.equal(nostrSerialize(shuffled), EXPECTED);
    assert.equal(
      nostrSerialize({ pubkey: EVENT.pubkey, created_at: 0, kind: 0, tags: [], content: '' }),
      `[0,"${EVENT.pubkey}",0,0,[],""]`,
    );
  });

  it('throws on malformed events instead of hashing garbage', () => {
    const bad = {
      'missing content': { ...EVENT, content: undefined },
      'uppercase pubkey': { ...EVENT, pubkey: EVENT.pubkey.toUpperCase() },
      'short pubkey': { ...EVENT, pubkey: EVENT.pubkey.slice(2) },
      'pubkey bytes': { ...EVENT, pubkey: unhex(EVENT.pubkey) },
      'string kind': { ...EVENT, kind: '1' },
      'kind out of range': { ...EVENT, kind: 65536 },
      'float created_at': { ...EVENT, created_at: 1760000000.5 },
      'millisecond string created_at': { ...EVENT, created_at: '1760000000' },
      'negative created_at': { ...EVENT, created_at: -1 },
      'tags not array': { ...EVENT, tags: 'e' },
      'flat tags': { ...EVENT, tags: ['e', 'abc'] },
      'non-string tag item': { ...EVENT, tags: [['expiration', 1760000000]] },
    };
    for (const [name, evt] of Object.entries(bad)) assert.throws(() => nostrSerialize(evt), TypeError, name);
    assert.throws(() => nostrSerialize(undefined), TypeError);
  });

  it('signs and verifies a complete event with a throwaway key', async () => {
    const sk = webcrypto.getRandomValues(new Uint8Array(32));
    const aux = webcrypto.getRandomValues(new Uint8Array(32));
    const pk = await schnorrPubkey(sk, sha256);
    const evt = { ...EVENT, pubkey: hex(pk) };
    const id = await sha256(new TextEncoder().encode(nostrSerialize(evt)));
    const sig = await schnorrSign(id, sk, aux, sha256);
    assert.equal(await schnorrVerify(id, pk, sig, sha256), true);
    const otherId = await sha256(new TextEncoder().encode(nostrSerialize({ ...evt, content: evt.content + '!' })));
    assert.equal(await schnorrVerify(otherId, pk, sig, sha256), false, 'signature is bound to the event id');
  });
});

// ---------------------------------------------------------------------------------------------
// Curve arithmetic, and the verification rules that the official vectors cannot isolate.
// With a real hash the challenge e is unpredictable, so e.g. "s >= n must be rejected, not
// reduced" never decides a vector on its own. Injecting an all-zero hash forces e = 0, which
// makes R = s*G and lets each rule be the only thing standing between true and false.
// ---------------------------------------------------------------------------------------------
describe('curve arithmetic and isolated verification rules', () => {
  const { P, N, G, mod, dbl, add, mul, affine, liftX } = b340;
  const TWO_G = [
    0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5n,
    0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52an,
  ];
  const onCurve = ([x, y]) => mod(y * y - x * x * x - 7n) === 0n;
  const neg = ([X, Y, Z]) => [X, P - Y, Z];

  it('doubling, addition and the infinite cases agree with the group law', () => {
    assert.deepEqual(affine(G), [G[0], G[1]]);
    assert.deepEqual(affine(dbl(G)), TWO_G);
    assert.deepEqual(affine(add(G, G)), TWO_G, 'add() of equal points must double');
    assert.deepEqual(affine(mul(G, 2n)), TWO_G);
    assert.equal(mul(G, 0n), null);
    assert.equal(mul(G, N), null, 'n*G is the point at infinity');
    assert.equal(add(mul(G, N - 1n), G), null, 'P + (-P)');
    assert.equal(add(null, null), null);
    assert.equal(dbl(null), null);
    assert.equal(affine(null), null);
    assert.deepEqual(affine(add(null, dbl(G))), TWO_G);
    assert.deepEqual(affine(add(dbl(G), null)), TWO_G);
    // The same point reached two ways has different Jacobian coordinates; add() must still see
    // that the operands are equal (or opposite).
    const a = mul(G, 5n), b = add(mul(G, 2n), mul(G, 3n));
    assert.notDeepEqual(a, b);
    assert.deepEqual(affine(a), affine(b));
    assert.deepEqual(affine(add(a, b)), affine(mul(G, 10n)));
    assert.equal(add(a, neg(b)), null);
  });

  it('scalar multiplication is linear and stays on the curve', () => {
    let k = 0x243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89n;
    for (let i = 0; i < 8; i++) {
      const a = k % N, b = (k * k + 7n) % N;
      const A = mul(G, a), B = mul(G, b);
      assert.ok(onCurve(affine(A)) && onCurve(affine(B)));
      assert.deepEqual(affine(add(A, B)), affine(mul(G, (a + b) % N)), 'aG + bG = (a+b)G');
      assert.deepEqual(affine(mul(A, b)), affine(mul(G, (a * b) % N)), 'b(aG) = (ab)G');
      assert.deepEqual(affine(mul(G, N - a)), affine(neg(A)), '(n-a)G = -(aG)');
      k = (k * 6364136223846793005n + 1442695040888963407n) % (1n << 256n);
    }
  });

  it('liftX returns the even-y point and rejects x >= p or x off the curve', () => {
    assert.deepEqual(liftX(G[0]), [G[0], G[1], 1n]); // G itself has even y
    const threeG = affine(mul(G, 3n));
    assert.equal(threeG[1] & 1n, 0n);
    assert.deepEqual(liftX(threeG[0]), [...threeG, 1n]);
    const oddY = affine(neg(G));
    assert.equal(oddY[1] & 1n, 1n);
    assert.deepEqual(liftX(oddY[0]), [G[0], G[1], 1n]);
    assert.notEqual(liftX(1n), null, 'x = 1 is on the curve');
    assert.equal(liftX(P + 1n), null, 'p + 1 must not be reduced to x = 1');
    assert.equal(liftX(P), null);
    assert.equal(liftX(BigInt('0x' + vectors[5].pk)), null, 'vector 5 public key is off the curve');
  });

  it('verification rules hold on their own when the challenge is forced to zero', async () => {
    const zeroHash = async () => new Uint8Array(32);
    const msg = unhex('00'.repeat(32));
    const pk = unhex(vectors[0].pk);
    const scalar = (v) => v.toString(16).padStart(64, '0');
    const GX = scalar(G[0]);
    const verify = (pkBytes, rHex, s) => schnorrVerify(msg, pkBytes, unhex(rHex + scalar(s)), zeroHash);

    assert.equal(await verify(pk, GX, 1n), true, 'control: e = 0, so R = 1*G and r = x(G) verifies');
    assert.equal(await verify(pk, GX, N + 1n), false, 's >= n must be rejected, not reduced mod n');
    assert.equal(await verify(pk, GX, N), false);
    assert.equal(await verify(pk, GX, N - 1n), false, 'R = -G has the right x but odd y');
    assert.equal(await verify(pk, GX, 0n), false, 'R is infinite');
    assert.equal(await verify(pk, scalar(0n), 0n), false, 'R is infinite, r = 0');
    assert.equal(await verify(pk, scalar(TWO_G[0]), 1n), false, 'wrong r');
    assert.equal(await verify(pk, scalar(TWO_G[0]), 2n), true, 'control: R = 2*G (even y)');
    assert.equal(await verify(unhex(vectors[5].pk), GX, 1n), false, 'public key off the curve');
    assert.equal(await verify(unhex(vectors[14].pk), GX, 1n), false, 'public key x = p + 1 must not be reduced');

    const sk = unhex('03'.padStart(64, '0'));
    await assert.rejects(schnorrSign(msg, sk, msg, zeroHash), /nonce/, 'k = 0 must abort signing');
  });
});

// ---------------------------------------------------------------------------------------------
// Contract checks: return types, input validation, never-throwing verify, self-verification.
// ---------------------------------------------------------------------------------------------
describe('API contract', () => {
  const sk = unhex('b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef');
  const aux = unhex('00'.repeat(31) + '01');
  const msg = unhex('243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89');

  it('source is a self-contained browser script (no modules, no Node APIs, safe inside a script tag)', () => {
    assert.doesNotMatch(source, /\b(import|export|require|process|Buffer|module|globalThis|__dirname)\b/);
    assert.doesNotMatch(source, /node:|<\/script|<!--/i);
    assert.doesNotMatch(source, /[^\x00-\x7f]/, 'ASCII only, so page encoding cannot corrupt it');
    for (const name of ['schnorrPubkey', 'schnorrSign', 'schnorrVerify']) {
      assert.match(source, new RegExp(`^async function ${name}\\(`, 'm'));
    }
    assert.match(source, /^function nostrSerialize\(evt\)/m);
  });

  it('returns plain Uint8Arrays of the right size and leaves its inputs untouched', async () => {
    const before = [hex(sk), hex(aux), hex(msg)];
    const pk = await schnorrPubkey(sk, sha256);
    const sig = await schnorrSign(msg, sk, aux, sha256);
    assert.equal(Object.getPrototypeOf(pk), Uint8Array.prototype);
    assert.equal(Object.getPrototypeOf(sig), Uint8Array.prototype);
    assert.equal(pk.length, 32);
    assert.equal(sig.length, 64);
    assert.deepEqual([hex(sk), hex(aux), hex(msg)], before);
    assert.equal(hex(await schnorrSign(msg, sk, aux, sha256)), hex(sig), 'deterministic for fixed aux');
    assert.notEqual(hex(await schnorrSign(msg, sk, unhex('00'.repeat(32)), sha256)), hex(sig), 'aux changes the nonce');
  });

  it('works with a sha256 that resolves to an ArrayBuffer (bare crypto.subtle.digest)', async () => {
    const bare = (bytes) => webcrypto.subtle.digest('SHA-256', bytes);
    const sig = await schnorrSign(msg, sk, aux, bare);
    assert.equal(hex(sig), hex(await schnorrSign(msg, sk, aux, sha256)));
    assert.equal(await schnorrVerify(msg, await schnorrPubkey(sk, bare), sig, bare), true);
  });

  it('schnorrPubkey and schnorrSign reject invalid secret keys', async () => {
    const invalid = {
      zero: unhex('00'.repeat(32)),
      'n (group order)': unhex(N_HEX),
      'n + 1': unhex(N_HEX.slice(0, -1) + '2'),
      '2^256 - 1': unhex('ff'.repeat(32)),
      '31 bytes': unhex('01'.repeat(31)),
      '33 bytes': unhex('00' + '01'.repeat(32)),
      'hex string': '01'.repeat(32),
      'plain array': Array(32).fill(1),
      'Uint16Array': new Uint16Array(32).fill(1),
      undefined: undefined,
      null: null,
    };
    for (const [name, bad] of Object.entries(invalid)) {
      await assert.rejects(schnorrPubkey(bad, sha256), /secret key/, `pubkey: ${name}`);
      await assert.rejects(schnorrSign(msg, bad, aux, sha256), /secret key/, `sign: ${name}`);
    }
    // Boundaries that must be accepted.
    assert.equal(hex(await schnorrPubkey(unhex('1'.padStart(64, '0')), sha256)), '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    assert.equal(hex(await schnorrPubkey(unhex(N_HEX.slice(0, -1) + '0'), sha256)), '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  });

  it('schnorrSign rejects a missing or wrong-size aux and a non-byte message', async () => {
    for (const bad of [undefined, null, unhex('00'.repeat(31)), unhex('00'.repeat(33)), '00'.repeat(32)]) {
      await assert.rejects(schnorrSign(msg, sk, bad, sha256), /aux_rand/);
    }
    for (const bad of [undefined, null, hex(msg), Array.from(msg)]) {
      await assert.rejects(schnorrSign(bad, sk, aux, sha256), /message/);
    }
    await assert.rejects(schnorrSign(msg, sk, aux, undefined));
    await assert.rejects(schnorrSign(msg, sk, aux, async () => new Uint8Array(20)), /sha256/);
  });

  it('schnorrSign verifies its own signature and refuses to return one that fails', async () => {
    // A hash that never answers the same way twice: the challenge recomputed by the built-in
    // verification cannot match the one the signature was made with.
    let calls = 0;
    const unstable = async (bytes) => sha256(Uint8Array.of(...bytes, calls++ & 0xff));
    await assert.rejects(schnorrSign(msg, sk, aux, unstable), /self-verification/);
    assert.ok(calls >= 8, 'three tagged hashes to sign plus one to verify');
  });

  it('schnorrVerify never throws: malformed inputs and failing hashes are just false', async () => {
    const pk = await schnorrPubkey(sk, sha256);
    const sig = await schnorrSign(msg, sk, aux, sha256);
    assert.equal(await schnorrVerify(msg, pk, sig, sha256), true);
    const junk = [undefined, null, '', hex(sig), 42, {}, [], Array.from(sig), new Uint8Array(0), new Uint8Array(31),
      new Uint8Array(33), new Uint8Array(63), new Uint8Array(65), new Uint16Array(32), new Uint16Array(64)];
    for (const j of junk) {
      assert.equal(await schnorrVerify(j, pk, sig, sha256), false);
      assert.equal(await schnorrVerify(msg, j, sig, sha256), false);
      assert.equal(await schnorrVerify(msg, pk, j, sha256), false);
    }
    assert.equal(await schnorrVerify(), false);
    const brokenHashes = [undefined, null, 'sha256', () => { throw new Error('sync'); }, async () => { throw new Error('async'); },
      async () => new Uint8Array(31), async () => 32, async () => 'x'.repeat(32), async () => Array(32).fill(0)];
    for (const h of brokenHashes) assert.equal(await schnorrVerify(msg, pk, sig, h), false);
  });

  it('timing (informational)', async (t) => {
    const rounds = 20;
    const ids = await Promise.all(Array.from({ length: rounds }, (_, i) => sha256(Uint8Array.of(i))));
    for (let i = 0; i < 3; i++) await schnorrSign(ids[i], sk, aux, sha256); // warm up
    let t0 = performance.now();
    const sigs = [];
    for (const id of ids) sigs.push(await schnorrSign(id, sk, aux, sha256));
    const signMs = (performance.now() - t0) / rounds;
    const pk = await schnorrPubkey(sk, sha256);
    t0 = performance.now();
    for (let i = 0; i < rounds; i++) assert.equal(await schnorrVerify(ids[i], pk, sigs[i], sha256), true);
    const verifyMs = (performance.now() - t0) / rounds;
    t0 = performance.now();
    for (let i = 0; i < rounds; i++) await schnorrPubkey(sk, sha256);
    const pubMs = (performance.now() - t0) / rounds;
    t.diagnostic(`schnorrSign ${signMs.toFixed(2)} ms/call (includes self-verify), schnorrVerify ${verifyMs.toFixed(2)} ms/call, schnorrPubkey ${pubMs.toFixed(2)} ms/call`);
  });
});
