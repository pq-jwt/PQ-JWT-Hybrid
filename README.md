# @pq-jwt/hybrid

**Hybrid JWT library — Fully compliant with IETF `draft-prabel-jose-pq-composite-sigs-05`.**

Part of the [pq-jwt ecosystem](https://pq-jwt.github.io) by **Sachin Ruhil**.

```bash
npm install @pq-jwt/hybrid
```

---

## What is a composite JWT?

A composite token carries **two independent signatures** bound together using the IETF composite algorithm standard:

- **ML-DSA** (NIST FIPS 204) — the quantum-resistant signature
- **ECDSA / EdDSA** — the classical signature

Token format: `base64url(header) . base64url(payload) . base64url(mldsa_sig || traditional_sig)`

The header is:
```json
{ "alg": "ML-DSA-65-ES256", "typ": "JWT", "ver": "2" }
```

---

## Quick Start

```javascript
import {
  generateCompositeKeyPair,
  signComposite,
  verifyComposite,
  exportCompositeKey, importCompositeKey,
} from '@pq-jwt/hybrid';

// 1. Generate key pair (ML-DSA-65 + ECDSA P-256)
const keys = generateCompositeKeyPair('ML-DSA-65-ES256');

const privateKeyHex = exportCompositeKey(keys.compositePrivateKey);
const publicKeyHex = exportCompositeKey(keys.compositePublicKey);

// 2. Sign — strictly adheres to IETF payload prefixing and M' construction
const token = signComposite(
  { sub: 'user_42', role: 'admin' },
  importCompositeKey(privateKeyHex),
  {
    algorithm: 'ML-DSA-65-ES256',
    expiresIn: '1h',
    issuer: 'auth.myapp.com',
    audience: 'api.myapp.com',
  }
);

// 3. Verify BOTH signatures
const { payload } = verifyComposite(
  token,
  importCompositeKey(publicKeyHex),
  { issuer: 'auth.myapp.com', audience: 'api.myapp.com' }
);
```

---

## Supported PQ Algorithms

| Algorithm | Post-Quantum | Traditional | Pre-Hash |
|-----------|--------------|-------------|----------|
| `ML-DSA-44-ES256` | ML-DSA-44 | ECDSA P-256 | SHA-256 |
| `ML-DSA-65-ES256` | ML-DSA-65 | ECDSA P-256 | SHA-512 |
| `ML-DSA-87-ES384` | ML-DSA-87 | ECDSA P-384 | SHA-512 |
| `ML-DSA-44-Ed25519` | ML-DSA-44 | Ed25519 | SHA-512 |
| `ML-DSA-65-Ed25519` | ML-DSA-65 | Ed25519 | SHA-512 |
| `ML-DSA-87-Ed448` | ML-DSA-87 | Ed448 | SHAKE-256 |

---

## Standards Compliance

This library is fully compliant with:
- **NIST FIPS 204**: Strictly uses the standard `ML-DSA` algorithm. Implements `ctx` domain separation and seed-based `KeyGen_internal`.
- **IETF JOSE Draft**: Implements `draft-prabel-jose-pq-composite-sigs-05` construction of the message `M' = Prefix || Label || 0x00 || Hash(M)`.

---

## Author
**Sachin Ruhil** · [github.com/ruhil6789](https://github.com/ruhil6789)

## License
MIT
