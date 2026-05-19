/**
 * @pq-jwt/hybrid — full test suite for IETF draft-prabel-jose-pq-composite-sigs-05
 * Run: node test/test.mjs
 */
import {
  generateCompositeKeyPair, signComposite, verifyComposite, decode,
  exportCompositeKey, importCompositeKey,
  HybridJWTError, HybridTokenExpiredError, HybridSignatureError, HybridInvalidTokenError,
  SUPPORTED_ALGORITHMS,
} from '../src/index.mjs';

let passed = 0, failed = 0;

function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); passed++; }
  catch (e) { console.log(`  ✗  ${name} — ${e.message}`); failed++; }
}
function assert(c, m) { if (!c) throw new Error(m || 'assertion failed'); }
function assertThrows(fn, errorClass, code) {
  let threw = false;
  try { fn(); }
  catch (e) {
    threw = true;
    if (errorClass && !(e instanceof errorClass))
      throw new Error(`Expected ${errorClass.name}, got ${e.constructor.name}: ${e.message}`);
    if (code && e.code !== code)
      throw new Error(`Expected code ${code}, got ${e.code}`);
  }
  if (!threw) throw new Error('Expected an error to be thrown');
}

// ── Key generation ─────────────────────────────────────────────
console.log('\n── Key generation ────────────────────────────────────────');

let keys65;

test('generateCompositeKeyPair ML-DSA-65-ES256 returns correct sizes', () => {
  keys65 = generateCompositeKeyPair('ML-DSA-65-ES256');
  assert(keys65.compositePublicKey instanceof Uint8Array, 'pk type');
  assert(keys65.compositePrivateKey instanceof Uint8Array, 'sk type');
  assert(keys65.compositePublicKey.length === 1952 + 33, 'pk len');
  assert(keys65.compositePrivateKey.length === 32 + 32, 'sk len');
  assert(keys65.algorithm === 'ML-DSA-65-ES256', 'alg');
});
test('generateCompositeKeyPair defaults to ML-DSA-65-ES256', () => {
  const k = generateCompositeKeyPair();
  assert(k.algorithm === 'ML-DSA-65-ES256', 'default alg');
});
test('generateCompositeKeyPair ML-DSA-87-Ed448', () => {
  const k = generateCompositeKeyPair('ML-DSA-87-Ed448');
  assert(k.compositePrivateKey.length === 32 + 57, 'sk len');
  assert(k.compositePublicKey.length === 2592 + 57, 'pk len');
});
test('generateCompositeKeyPair throws for unknown algorithm', () => {
  assertThrows(() => generateCompositeKeyPair('FAKE'), HybridJWTError, 'UNKNOWN_ALGORITHM');
});

// ── exportKey / importKey ──────────────────────────────────────
console.log('\n── Key serialisation ─────────────────────────────────────');

test('exportCompositeKey produces hex string', () => {
  const hex = exportCompositeKey(keys65.compositePublicKey);
  assert(typeof hex === 'string' && /^[0-9a-f]+$/.test(hex), 'hex format');
  assert(hex.length === (1952 + 33) * 2, 'length');
});
test('importCompositeKey round-trips key', () => {
  const hex = exportCompositeKey(keys65.compositePrivateKey);
  const sk2 = importCompositeKey(hex);
  assert(sk2.every((b, i) => b === keys65.compositePrivateKey[i]), 'bytes match');
});

// ── signComposite() ───────────────────────────────────────────────
console.log('\n── signComposite() ──────────────────────────────────────────');

const BASE_TOKEN = signComposite(
  { sub: 'user_42', role: 'admin', org: 'acme' },
  keys65.compositePrivateKey,
  { algorithm: 'ML-DSA-65-ES256', expiresIn: '1h', issuer: 'test', audience: 'api' }
);

test('returns 3-part dot-separated string', () => {
  assert(typeof BASE_TOKEN === 'string', 'type');
  assert(BASE_TOKEN.split('.').length === 3, 'parts');
});
test('accepts hex string keys', () => {
  const tok = signComposite(
    { x: 1 }, exportCompositeKey(keys65.compositePrivateKey),
    { algorithm: 'ML-DSA-65-ES256' }
  );
  assert(tok.split('.').length === 3, 'parts');
});
test('sets iat automatically', () => {
  const { payload } = verifyComposite(BASE_TOKEN, keys65.compositePublicKey, { ignoreExpiry: true });
  assert(typeof payload.iat === 'number', 'iat type');
  assert(payload.iat <= Math.floor(Date.now() / 1000), 'iat value');
});
test('sets exp from expiresIn string', () => {
  const now = Math.floor(Date.now() / 1000);
  const tok = signComposite({ x: 1 }, keys65.compositePrivateKey, {
    algorithm: 'ML-DSA-65-ES256', expiresIn: '1h'
  });
  const { payload } = verifyComposite(tok, keys65.compositePublicKey);
  assert(Math.abs(payload.exp - (now + 3600)) <= 2, 'exp value');
});
test('sets nbf from notBefore option', () => {
  const now = Math.floor(Date.now() / 1000);
  const tok = signComposite({ x: 1 }, keys65.compositePrivateKey, {
    algorithm: 'ML-DSA-65-ES256', expiresIn: '2h', notBefore: '1h'
  });
  const { payload } = verifyComposite(tok, keys65.compositePublicKey, { ignoreExpiry: true, clockTolerance: 7200 });
  assert(Math.abs(payload.nbf - (now + 3600)) <= 2, 'nbf value');
});
test('throws for non-object payload', () => {
  assertThrows(() => signComposite('bad', keys65.compositePrivateKey), HybridJWTError, 'INVALID_PAYLOAD');
});

// ── verifyComposite() ─────────────────────────────────────────────
console.log('\n── verifyComposite() ────────────────────────────────────────');

test('returns correct header (JWT, alg, ver)', () => {
  const { header } = verifyComposite(BASE_TOKEN, keys65.compositePublicKey, { issuer:'test', audience:'api' });
  assert(header.typ === 'JWT', 'typ');
  assert(header.alg === 'ML-DSA-65-ES256', 'alg');
  assert(header.ver === '2', 'ver');
});
test('returns correct payload', () => {
  const { payload } = verifyComposite(BASE_TOKEN, keys65.compositePublicKey, { issuer:'test', audience:'api' });
  assert(payload.sub === 'user_42', 'sub');
});
test('throws HybridSignatureError if token is tampered', () => {
  const parts = BASE_TOKEN.split('.');
  const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g,'+').replace(/_/g,'/'), 'base64'));
  payload.role = 'superadmin';
  parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
  assertThrows(
    () => verifyComposite(parts.join('.'), keys65.compositePublicKey),
    HybridSignatureError
  );
});

// ── decode() ──────────────────────────────────────────────────
console.log('\n── decode() ──────────────────────────────────────────────');

test('decode returns all fields', () => {
  const d = decode(BASE_TOKEN);
  assert(d.header.typ === 'JWT', 'typ');
  assert(d.header.alg === 'ML-DSA-65-ES256', 'alg');
  assert(d.payload.sub === 'user_42', 'sub');
  assert(d.signature instanceof Uint8Array, 'sig type');
  assert(d.signature.length === 3309 + 64, 'sig len');
});

// ── All PQ algorithms ────────────────────────────────────────
console.log('\n── All PQ algorithms ───────────────────────────────────');

for (const alg of SUPPORTED_ALGORITHMS) {
  test(`${alg}: signComposite + verifyComposite`, () => {
    const k = generateCompositeKeyPair(alg);
    const tok = signComposite({ alg }, k.compositePrivateKey, { algorithm: alg, expiresIn: '1h' });
    const r1 = verifyComposite(tok, k.compositePublicKey);
    assert(r1.payload.alg === alg, 'hybrid');
  });
}

// ── Results ────────────────────────────────────────────────────
console.log('\n── Results ───────────────────────────────────────────────');
const total = passed + failed;
console.log(`\n  ${passed}/${total} passed ${failed > 0 ? `(${failed} FAILED)` : '— ALL PASS ✓'}\n`);
if (failed > 0) process.exit(1);
