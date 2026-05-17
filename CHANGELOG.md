# Changelog

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
