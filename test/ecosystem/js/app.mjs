import { generateHybridKeyPair, signHybrid, verifyHybrid } from '@pq-jwt/hybrid';

const { ecdsa, pq } = generateHybridKeyPair('ML-DSA-65');
const token = signHybrid(
  { runtime: 'javascript' },
  ecdsa.secretKey,
  pq.secretKey,
  { expiresIn: '60s', pqAlgorithm: 'ML-DSA-65' }
);
const { payload } = verifyHybrid(token, ecdsa.publicKey, pq.publicKey);

if (payload.runtime !== 'javascript') {
  throw new Error('JavaScript consumer: verify payload mismatch');
}

console.log('OK javascript/esm');
