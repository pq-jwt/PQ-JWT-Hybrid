# @pq-jwt/hybrid

**Hybrid JWT library — ECDSA P-256 + ML-DSA dual signing.**
The migration bridge from classical to post-quantum authentication.

Part of the [pq-jwt ecosystem](https://pq-jwt.github.io) by **Sachin Ruhil**.

```bash
npm install @pq-jwt/hybrid
```

---

## What is a hybrid JWT?

A hybrid token carries **two independent signatures** in one string:

- **ECDSA P-256** — the classical signature your existing services already verify
- **ML-DSA** (NIST FIPS 204) — the quantum-resistant signature new services verify

Token format: `base64url(header) . base64url(payload) . base64url({e: ecdsa_sig, m: mldsa_sig})`

The header is:
```json
{ "alg": "ECDSA-P256+ML-DSA-65", "typ": "HYBRID-JWT", "ver": "1" }
```

---

## Why does this exist?

You cannot migrate your entire infrastructure to post-quantum on day one.
Services go live on different timelines. `@pq-jwt/hybrid` bridges the gap:

```
Phase 1 — issue hybrid tokens, all services accept them:
  Old services   → verifyEcdsa(token, ecdsaPublicKey)     ← classical path
  New services   → verifyPQ(token, pqPublicKey)           ← quantum-safe path
  Bridge         → verifyHybrid(token, ecdsaPk, pqPk)     ← both must be valid

Phase 2 — new services verify PQ only, old still work

Phase 3 — drop ECDSA entirely, migrate to @pq-jwt/core sign() + verify()
```

---

## Quick Start

```javascript
import {
  generateHybridKeyPair,
  signHybrid,
  verifyHybrid,
  verifyPQ,
  verifyEcdsa,
  exportKey, importKey,
} from '@pq-jwt/hybrid';

// 1. Generate key pair — both ECDSA + ML-DSA
const { ecdsa, pq } = generateHybridKeyPair('ML-DSA-65');
const ecdsaSkHex = exportKey(ecdsa.secretKey);
const ecdsaPkHex = exportKey(ecdsa.publicKey);
const pqSkHex    = exportKey(pq.secretKey);
const pqPkHex    = exportKey(pq.publicKey);

// 2. Sign — one token, two signatures
const token = signHybrid(
  { sub: 'user_42', role: 'admin' },
  importKey(ecdsaSkHex),
  importKey(pqSkHex),
  {
    pqAlgorithm: 'ML-DSA-65',
    expiresIn:   '1h',
    issuer:      'auth.myapp.com',
    audience:    'api.myapp.com',
  }
);

// 3a. Verify BOTH (bridge service)
const { payload } = verifyHybrid(
  token,
  importKey(ecdsaPkHex),
  importKey(pqPkHex),
  { issuer: 'auth.myapp.com', audience: 'api.myapp.com' }
);

// 3b. Verify PQ only (new quantum-safe service)
const { payload: p2 } = verifyPQ(token, importKey(pqPkHex), { issuer: 'auth.myapp.com' });

// 3c. Verify ECDSA only (legacy service — no PQ key needed)
const { payload: p3 } = verifyEcdsa(token, importKey(ecdsaPkHex));
```

---

## TypeScript

Full TypeScript types included — no `@types/` package needed:

```typescript
import {
  generateHybridKeyPair,
  signHybrid, verifyHybrid, verifyPQ, verifyEcdsa,
  type HybridKeyPair, type HybridSignOptions,
  HybridTokenExpiredError, HybridSignatureError,
} from '@pq-jwt/hybrid';

const keys: HybridKeyPair = generateHybridKeyPair('ML-DSA-65');

const opts: HybridSignOptions = {
  pqAlgorithm:  'ML-DSA-65',
  expiresIn:    '8h',
  notBefore:    '0s',
  issuer:       'auth.myapp.com',
  clockTolerance: 10,
};

const token: string = signHybrid({ userId: 'u1' }, keys.ecdsa.secretKey, keys.pq.secretKey, opts);

try {
  const { payload } = verifyHybrid(token, keys.ecdsa.publicKey, keys.pq.publicKey);
} catch (e) {
  if (e instanceof HybridTokenExpiredError) { /* 401 */ }
  if (e instanceof HybridSignatureError)   { /* 403, e.which = 'ECDSA' | 'ML-DSA' */ }
}
```

---

## API Reference

### `generateHybridKeyPair(pqAlgorithm?)`
Generate an ECDSA P-256 + ML-DSA key pair.

### `signHybrid(payload, ecdsaSecretKey, pqSecretKey, options?)`
Sign with both algorithms. Returns a 3-part `HYBRID-JWT` token.

### `verifyHybrid(token, ecdsaPublicKey, pqPublicKey, options?)`
Both signatures must be valid. Use on bridge services.

### `verifyPQ(token, pqPublicKey, options?)`
Verify only the ML-DSA signature. Use on new quantum-safe services.

### `verifyEcdsa(token, ecdsaPublicKey, options?)`
Verify only the ECDSA signature. Use on legacy services.

### `decode(token)`
Inspect header, payload, and both signatures without verifying.

### `exportKey(key)` / `importKey(hexString)`
Serialize keys to/from hex for `.env` or secrets managers.

---

## Supported PQ Algorithms

| Algorithm | Standard | Quantum Security |
|-----------|----------|-----------------|
| `ML-DSA-44` | NIST FIPS 204 | 64-bit Q |
| `ML-DSA-65` | NIST FIPS 204 | 96-bit Q ← **recommended** |
| `ML-DSA-87` | NIST FIPS 204 | 128-bit Q |
| `SLH-DSA-SHA2-128s` | NIST FIPS 205 | 64-bit Q |

---

## Error Classes

| Class | Code | When |
|-------|------|------|
| `HybridSignatureError` | `SIGNATURE_INVALID` | Either sig invalid; `.which` = `'ECDSA'` or `'ML-DSA'` |
| `HybridTokenExpiredError` | `TOKEN_EXPIRED` | `exp` claim in the past |
| `HybridInvalidTokenError` | `INVALID_TOKEN` | Malformed token, wrong typ, claim mismatch |
| `HybridJWTError` | various | Base class for all errors |

---

## Ecosystem

| Package | Description |
|---------|-------------|
| [`@pq-jwt/core`](https://npmjs.com/package/@pq-jwt/core) | PQ-only JWT — sign, verify, ML-DSA, SLH-DSA |
| [`@pq-jwt/hybrid`](https://npmjs.com/package/@pq-jwt/hybrid) | This package — ECDSA + ML-DSA migration bridge |

Website: [pq-jwt.github.io](https://pq-jwt.github.io)
GitHub: [github.com/pq-jwt](https://github.com/pq-jwt)

---

## Author

**Sachin Ruhil** · [github.com/ruhil6789](https://github.com/ruhil6789)

## License

MIT
