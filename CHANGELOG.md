# Changelog

## 1.2.0 — 2026-05-19

### Breaking Changes

- **IETF Standard Alignment**: Renamed classical algorithm keys (e.g., `P-256` to `ES256`) and flipped the order in the header construction to follow the draft-prabel-jose-pq-composite-sigs-05 standard. The algorithm header is now `<pqAlg>-<classicalAlg>`, for example, `ML-DSA-65-ES256` instead of `ECDSA-P256+ML-DSA-65`. Tokens generated with v1.0.x are no longer compatible with v1.2.0 verifiers.

## 0.0.1 — 2025-05-17

### Initial Release

- `signHybrid()` — sign with ECDSA P-256 AND ML-DSA in one token
- `verifyHybrid()` — verify both signatures (bridge services)
- `verifyPQ()` — verify ML-DSA only (new quantum-safe services)
- `verifyEcdsa()` — verify ECDSA only (legacy/old services)
- `decode()` — inspect token without verifying
- `generateHybridKeyPair()` — generate ECDSA + ML-DSA key pair
- `exportKey()` / `importKey()` — hex serialisation
- Full TypeScript types with `types` condition in exports map
- 53/53 tests passing
- All 4 NIST algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128s
- clockTolerance and notBefore options
- MIT license
