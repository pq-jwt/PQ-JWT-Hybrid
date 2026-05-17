/**
 * @pq-jwt/hybrid — full test suite
 * Run: node test/test.mjs
 */
import {
  generateHybridKeyPair, signHybrid, verifyHybrid, verifyPQ, verifyEcdsa, decode,
  exportKey, importKey,
  HybridJWTError, HybridTokenExpiredError, HybridSignatureError, HybridInvalidTokenError,
  SUPPORTED_PQ_ALGORITHMS,
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

let keys65, keys44, keys87, keysSlh;

test('generateHybridKeyPair ML-DSA-65 returns correct sizes', () => {
  keys65 = generateHybridKeyPair('ML-DSA-65');
  assert(keys65.ecdsa.secretKey instanceof Uint8Array, 'ecdsa sk type');
  assert(keys65.ecdsa.publicKey instanceof Uint8Array, 'ecdsa pk type');
  assert(keys65.ecdsa.secretKey.length === 32, 'ecdsa sk len');
  assert(keys65.ecdsa.publicKey.length === 33, 'ecdsa pk len (compressed)');
  assert(keys65.pq.secretKey.length === 4032, 'pq sk len');
  assert(keys65.pq.publicKey.length === 1952, 'pq pk len');
  assert(keys65.pq.algorithm === 'ML-DSA-65', 'pq alg');
});
test('generateHybridKeyPair defaults to ML-DSA-65', () => {
  const k = generateHybridKeyPair();
  assert(k.pq.algorithm === 'ML-DSA-65', 'default alg');
});
test('generateHybridKeyPair ML-DSA-44', () => {
  keys44 = generateHybridKeyPair('ML-DSA-44');
  assert(keys44.pq.secretKey.length === 2560, 'sk len');
  assert(keys44.pq.publicKey.length === 1312, 'pk len');
});
test('generateHybridKeyPair ML-DSA-87', () => {
  keys87 = generateHybridKeyPair('ML-DSA-87');
  assert(keys87.pq.secretKey.length === 4896, 'sk len');
  assert(keys87.pq.publicKey.length === 2592, 'pk len');
});
test('generateHybridKeyPair SLH-DSA-SHA2-128s', () => {
  keysSlh = generateHybridKeyPair('SLH-DSA-SHA2-128s');
  assert(keysSlh.pq.secretKey.length === 64, 'sk len');
  assert(keysSlh.pq.publicKey.length === 32, 'pk len');
});
test('generateHybridKeyPair throws for unknown algorithm', () => {
  assertThrows(() => generateHybridKeyPair('FAKE'), HybridJWTError, 'UNKNOWN_ALGORITHM');
});

// ── exportKey / importKey ──────────────────────────────────────
console.log('\n── Key serialisation ─────────────────────────────────────');

test('exportKey produces hex string', () => {
  const hex = exportKey(keys65.ecdsa.publicKey);
  assert(typeof hex === 'string' && /^[0-9a-f]+$/.test(hex), 'hex format');
  assert(hex.length === 33 * 2, 'length');
});
test('importKey round-trips ECDSA key', () => {
  const hex = exportKey(keys65.ecdsa.secretKey);
  const sk2 = importKey(hex);
  assert(sk2.every((b, i) => b === keys65.ecdsa.secretKey[i]), 'bytes match');
});
test('importKey round-trips PQ key', () => {
  const hex = exportKey(keys65.pq.publicKey);
  const pk2 = importKey(hex);
  assert(pk2.every((b, i) => b === keys65.pq.publicKey[i]), 'bytes match');
});
test('exportKey throws for non-Uint8Array', () => {
  assertThrows(() => exportKey('string'), HybridJWTError, 'INVALID_KEY');
});
test('importKey throws for non-hex', () => {
  assertThrows(() => importKey('not-hex!'), HybridJWTError, 'INVALID_KEY');
});

// ── signHybrid() ───────────────────────────────────────────────
console.log('\n── signHybrid() ──────────────────────────────────────────');

const { ecdsa, pq } = keys65;
const BASE_TOKEN = signHybrid(
  { sub: 'user_42', role: 'admin', org: 'acme' },
  ecdsa.secretKey,
  pq.secretKey,
  { pqAlgorithm: 'ML-DSA-65', expiresIn: '1h', issuer: 'test', audience: 'api' }
);

test('returns 3-part dot-separated string', () => {
  assert(typeof BASE_TOKEN === 'string', 'type');
  assert(BASE_TOKEN.split('.').length === 3, 'parts');
});
test('accepts hex string keys', () => {
  const tok = signHybrid(
    { x: 1 }, exportKey(ecdsa.secretKey), exportKey(pq.secretKey),
    { pqAlgorithm: 'ML-DSA-65' }
  );
  assert(tok.split('.').length === 3, 'parts');
});
test('sets iat automatically', () => {
  const { payload } = verifyPQ(BASE_TOKEN, pq.publicKey, { ignoreExpiry: true });
  assert(typeof payload.iat === 'number', 'iat type');
  assert(payload.iat <= Math.floor(Date.now() / 1000), 'iat value');
});
test('sets exp from expiresIn string', () => {
  const now = Math.floor(Date.now() / 1000);
  const tok = signHybrid({ x: 1 }, ecdsa.secretKey, pq.secretKey, {
    pqAlgorithm: 'ML-DSA-65', expiresIn: '1h'
  });
  const { payload } = verifyPQ(tok, pq.publicKey);
  assert(Math.abs(payload.exp - (now + 3600)) <= 2, 'exp value');
});
test('sets nbf from notBefore option', () => {
  const now = Math.floor(Date.now() / 1000);
  const tok = signHybrid({ x: 1 }, ecdsa.secretKey, pq.secretKey, {
    pqAlgorithm: 'ML-DSA-65', expiresIn: '2h', notBefore: '1h'
  });
  const { payload } = verifyPQ(tok, pq.publicKey, { ignoreExpiry: true, clockTolerance: 7200 });
  assert(Math.abs(payload.nbf - (now + 3600)) <= 2, 'nbf value');
});
test('sets iss, sub, aud, jti claims', () => {
  const tok = signHybrid({ x: 1 }, ecdsa.secretKey, pq.secretKey, {
    pqAlgorithm: 'ML-DSA-65',
    issuer: 'auth', subject: 'u1', audience: 'api', jwtId: 'j001'
  });
  const { payload } = verifyPQ(tok, pq.publicKey);
  assert(payload.iss === 'auth', 'iss');
  assert(payload.sub === 'u1', 'sub');
  assert(payload.aud === 'api', 'aud');
  assert(payload.jti === 'j001', 'jti');
});
test('throws for non-object payload', () => {
  assertThrows(() => signHybrid('bad', ecdsa.secretKey, pq.secretKey), HybridJWTError, 'INVALID_PAYLOAD');
});
test('throws for invalid expiresIn', () => {
  assertThrows(
    () => signHybrid({ x: 1 }, ecdsa.secretKey, pq.secretKey, { expiresIn: 'bad' }),
    HybridJWTError, 'INVALID_DURATION'
  );
});
test('throws for wrong ECDSA key size', () => {
  assertThrows(
    () => signHybrid({ x: 1 }, new Uint8Array(10), pq.secretKey),
    HybridJWTError, 'INVALID_KEY'
  );
});

// ── verifyHybrid() ─────────────────────────────────────────────
console.log('\n── verifyHybrid() ────────────────────────────────────────');

test('returns correct header (HYBRID-JWT, alg, ver)', () => {
  const { header } = verifyHybrid(BASE_TOKEN, ecdsa.publicKey, pq.publicKey, { issuer:'test', audience:'api' });
  assert(header.typ === 'HYBRID-JWT', 'typ');
  assert(header.alg === 'ECDSA-P256+ML-DSA-65', 'alg');
  assert(header.ver === '1', 'ver');
});
test('returns correct payload', () => {
  const { payload } = verifyHybrid(BASE_TOKEN, ecdsa.publicKey, pq.publicKey, { issuer:'test', audience:'api' });
  assert(payload.sub === 'user_42', 'sub');
  assert(payload.role === 'admin', 'role');
  assert(payload.org === 'acme', 'org');
});
test('accepts hex string public keys', () => {
  const { payload } = verifyHybrid(
    BASE_TOKEN,
    exportKey(ecdsa.publicKey), exportKey(pq.publicKey),
    { issuer: 'test', audience: 'api' }
  );
  assert(payload.sub === 'user_42', 'payload');
});
test('throws HybridSignatureError if ECDSA sig is tampered', () => {
  const parts = BASE_TOKEN.split('.');
  const sigObj = JSON.parse(Buffer.from(parts[2].replace(/-/g,'+').replace(/_/g,'/'), 'base64'));
  sigObj.e = '00'.repeat(64); // corrupt ECDSA sig
  parts[2] = Buffer.from(JSON.stringify(sigObj)).toString('base64url');
  assertThrows(
    () => verifyHybrid(parts.join('.'), ecdsa.publicKey, pq.publicKey),
    HybridSignatureError
  );
});
test('throws HybridSignatureError if ML-DSA sig is tampered', () => {
  const parts = BASE_TOKEN.split('.');
  const sigObj = JSON.parse(Buffer.from(parts[2].replace(/-/g,'+').replace(/_/g,'/'), 'base64'));
  sigObj.m = '00'.repeat(3309); // corrupt PQ sig
  parts[2] = Buffer.from(JSON.stringify(sigObj)).toString('base64url');
  assertThrows(
    () => verifyHybrid(parts.join('.'), ecdsa.publicKey, pq.publicKey),
    HybridSignatureError
  );
});
test('throws HybridSignatureError if payload is tampered', () => {
  const parts = BASE_TOKEN.split('.');
  const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g,'+').replace(/_/g,'/'), 'base64'));
  payload.role = 'superadmin';
  parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
  assertThrows(
    () => verifyHybrid(parts.join('.'), ecdsa.publicKey, pq.publicKey),
    HybridSignatureError
  );
});
test('throws HybridSignatureError with wrong ECDSA key', () => {
  const other = generateHybridKeyPair('ML-DSA-65');
  assertThrows(
    () => verifyHybrid(BASE_TOKEN, other.ecdsa.publicKey, pq.publicKey),
    HybridSignatureError
  );
});
test('throws HybridSignatureError with wrong PQ key', () => {
  const other = generateHybridKeyPair('ML-DSA-65');
  assertThrows(
    () => verifyHybrid(BASE_TOKEN, ecdsa.publicKey, other.pq.publicKey),
    HybridSignatureError
  );
});
test('issuer mismatch throws HybridInvalidTokenError', () => {
  assertThrows(
    () => verifyHybrid(BASE_TOKEN, ecdsa.publicKey, pq.publicKey, { issuer: 'wrong' }),
    HybridInvalidTokenError
  );
});
test('audience mismatch throws HybridInvalidTokenError', () => {
  assertThrows(
    () => verifyHybrid(BASE_TOKEN, ecdsa.publicKey, pq.publicKey, { issuer:'test', audience: 'wrong' }),
    HybridInvalidTokenError
  );
});

// ── verifyPQ() — post-quantum only path ────────────────────────
console.log('\n── verifyPQ() — PQ-only path ─────────────────────────────');

test('verifyPQ passes with correct PQ key', () => {
  const { payload } = verifyPQ(BASE_TOKEN, pq.publicKey, { issuer:'test', audience:'api' });
  assert(payload.sub === 'user_42', 'sub');
});
test('verifyPQ throws HybridSignatureError with wrong PQ key', () => {
  const other = generateHybridKeyPair('ML-DSA-65');
  assertThrows(() => verifyPQ(BASE_TOKEN, other.pq.publicKey), HybridSignatureError);
});
test('verifyPQ does NOT need ECDSA key', () => {
  // Should work without providing any ECDSA key
  const { header } = verifyPQ(BASE_TOKEN, pq.publicKey, { ignoreExpiry: true });
  assert(header.typ === 'HYBRID-JWT', 'typ');
});

// ── verifyEcdsa() — classical only path ───────────────────────
console.log('\n── verifyEcdsa() — ECDSA-only (legacy) path ─────────────');

test('verifyEcdsa passes with correct ECDSA key', () => {
  const { payload } = verifyEcdsa(BASE_TOKEN, ecdsa.publicKey, { issuer:'test', audience:'api' });
  assert(payload.sub === 'user_42', 'sub');
});
test('verifyEcdsa throws HybridSignatureError with wrong ECDSA key', () => {
  const other = generateHybridKeyPair('ML-DSA-65');
  assertThrows(() => verifyEcdsa(BASE_TOKEN, other.ecdsa.publicKey), HybridSignatureError);
});
test('verifyEcdsa does NOT need PQ key', () => {
  const { header } = verifyEcdsa(BASE_TOKEN, ecdsa.publicKey, { ignoreExpiry: true });
  assert(header.typ === 'HYBRID-JWT', 'typ');
});

// ── decode() ──────────────────────────────────────────────────
console.log('\n── decode() ──────────────────────────────────────────────');

test('decode returns all fields', () => {
  const d = decode(BASE_TOKEN);
  assert(d.header.typ === 'HYBRID-JWT', 'typ');
  assert(d.header.alg === 'ECDSA-P256+ML-DSA-65', 'alg');
  assert(d.payload.sub === 'user_42', 'sub');
  assert(d.ecdsaSignature instanceof Uint8Array, 'ecdsa sig type');
  assert(d.ecdsaSignature.length === 64, 'ecdsa sig len');
  assert(d.pqSignature instanceof Uint8Array, 'pq sig type');
  assert(d.pqSignature.length > 3000, 'pq sig len');
});
test('decode throws for malformed token', () => {
  assertThrows(() => decode('not.valid'), HybridInvalidTokenError);
});

// ── Temporal claims ────────────────────────────────────────────
console.log('\n── Temporal claims ───────────────────────────────────────');

test('expired token throws HybridTokenExpiredError', () => {
  const tok = signHybrid({ x:1 }, ecdsa.secretKey, pq.secretKey, { expiresIn: -10 });
  assertThrows(() => verifyHybrid(tok, ecdsa.publicKey, pq.publicKey), HybridTokenExpiredError, 'TOKEN_EXPIRED');
});
test('ignoreExpiry bypasses expiry', () => {
  const tok = signHybrid({ x:1 }, ecdsa.secretKey, pq.secretKey, { expiresIn: -10 });
  const { payload } = verifyHybrid(tok, ecdsa.publicKey, pq.publicKey, { ignoreExpiry: true });
  assert(payload.x === 1, 'payload');
});
test('clockTolerance: token expired 5s ago accepted with tolerance 10', () => {
  const tok = signHybrid({ x:1 }, ecdsa.secretKey, pq.secretKey, { expiresIn: -5 });
  const { payload } = verifyPQ(tok, pq.publicKey, { clockTolerance: 10 });
  assert(payload.x === 1, 'payload');
});
test('clockTolerance: token expired 15s ago rejected with tolerance 10', () => {
  const tok = signHybrid({ x:1 }, ecdsa.secretKey, pq.secretKey, { expiresIn: -15 });
  assertThrows(() => verifyPQ(tok, pq.publicKey, { clockTolerance: 10 }), HybridTokenExpiredError);
});
test('notBefore in future rejected without clockTolerance', () => {
  const tok = signHybrid({ x:1 }, ecdsa.secretKey, pq.secretKey, { notBefore: '1h', expiresIn: '2h' });
  assertThrows(() => verifyHybrid(tok, ecdsa.publicKey, pq.publicKey), HybridJWTError, 'TOKEN_NOT_YET_VALID');
});

// ── Migration scenario ─────────────────────────────────────────
console.log('\n── Migration scenario ────────────────────────────────────');

test('Phase 1 — old service verifies ECDSA only', () => {
  const tok = signHybrid(
    { userId: 'u1', role: 'admin' }, ecdsa.secretKey, pq.secretKey,
    { pqAlgorithm: 'ML-DSA-65', expiresIn: '1h', issuer: 'auth.myapp.com' }
  );
  // Old service: only knows ECDSA key, ignores PQ
  const { payload } = verifyEcdsa(tok, ecdsa.publicKey, { issuer: 'auth.myapp.com' });
  assert(payload.userId === 'u1', 'userId');
  assert(payload.role === 'admin', 'role');
});
test('Phase 1 — new service verifies PQ only', () => {
  const tok = signHybrid(
    { userId: 'u1', role: 'admin' }, ecdsa.secretKey, pq.secretKey,
    { pqAlgorithm: 'ML-DSA-65', expiresIn: '1h', issuer: 'auth.myapp.com' }
  );
  // New service: only needs ML-DSA key
  const { payload } = verifyPQ(tok, pq.publicKey, { issuer: 'auth.myapp.com' });
  assert(payload.userId === 'u1', 'userId');
});
test('Phase 1 — bridge service verifies both', () => {
  const tok = signHybrid(
    { userId: 'u1' }, ecdsa.secretKey, pq.secretKey,
    { pqAlgorithm: 'ML-DSA-65', expiresIn: '1h', issuer: 'auth.myapp.com' }
  );
  const { payload } = verifyHybrid(tok, ecdsa.publicKey, pq.publicKey, { issuer: 'auth.myapp.com' });
  assert(payload.userId === 'u1', 'both sigs valid');
});

// ── All 4 PQ algorithms ────────────────────────────────────────
console.log('\n── All 4 PQ algorithms ───────────────────────────────────');

for (const alg of SUPPORTED_PQ_ALGORITHMS) {
  test(`${alg}: signHybrid + verifyHybrid + verifyPQ + verifyEcdsa`, () => {
    const k = generateHybridKeyPair(alg);
    const tok = signHybrid({ alg }, k.ecdsa.secretKey, k.pq.secretKey, {
      pqAlgorithm: alg, expiresIn: '1h'
    });
    const r1 = verifyHybrid(tok, k.ecdsa.publicKey, k.pq.publicKey);
    const r2 = verifyPQ(tok, k.pq.publicKey);
    const r3 = verifyEcdsa(tok, k.ecdsa.publicKey);
    assert(r1.payload.alg === alg, 'hybrid');
    assert(r2.payload.alg === alg, 'pq');
    assert(r3.payload.alg === alg, 'ecdsa');
  });
}

// ── Large payload ──────────────────────────────────────────────
console.log('\n── Edge cases ────────────────────────────────────────────');

test('large payload (500 items) round-trips', () => {
  const big = { items: Array.from({ length: 500 }, (_, i) => ({ id: i, v: `val_${i}` })) };
  const tok = signHybrid(big, ecdsa.secretKey, pq.secretKey, { pqAlgorithm: 'ML-DSA-65' });
  const { payload } = verifyHybrid(tok, ecdsa.publicKey, pq.publicKey);
  assert(payload.items.length === 500, 'length');
  assert(payload.items[499].v === 'val_499', 'last item');
});
test('unicode + emoji payload round-trips', () => {
  const tok = signHybrid({ name: '日本語', emoji: '🔐' }, ecdsa.secretKey, pq.secretKey);
  const { payload } = verifyPQ(tok, pq.publicKey);
  assert(payload.name === '日本語', 'unicode');
  assert(payload.emoji === '🔐', 'emoji');
});
test('SUPPORTED_PQ_ALGORITHMS exports 4 algorithms', () => {
  assert(SUPPORTED_PQ_ALGORITHMS.length === 4, 'count');
  assert(SUPPORTED_PQ_ALGORITHMS.includes('ML-DSA-65'), 'ML-DSA-65');
  assert(SUPPORTED_PQ_ALGORITHMS.includes('SLH-DSA-SHA2-128s'), 'SLH-DSA');
});

// ── Results ────────────────────────────────────────────────────
console.log('\n── Results ───────────────────────────────────────────────');
const total = passed + failed;
console.log(`\n  ${passed}/${total} passed ${failed > 0 ? `(${failed} FAILED)` : '— ALL PASS ✓'}\n`);
if (failed > 0) process.exit(1);
