import {
  generateHybridKeyPair,
  signHybrid,
  verifyHybrid,
  type PQAlgorithm,
} from '@pq-jwt/hybrid';

const alg: PQAlgorithm = 'ML-DSA-44';
const { ecdsa, pq } = generateHybridKeyPair(alg);
const token = signHybrid(
  { runtime: 'typescript-bundler' },
  ecdsa.secretKey,
  pq.secretKey,
  { pqAlgorithm: alg }
);
const { payload } = verifyHybrid(token, ecdsa.publicKey, pq.publicKey);

if (payload.runtime !== 'typescript-bundler') {
  throw new Error('TypeScript Bundler consumer: verify payload mismatch');
}

console.log('OK typescript/bundler');
