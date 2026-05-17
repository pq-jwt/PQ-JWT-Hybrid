import {
  generateHybridKeyPair,
  signHybrid,
  verifyHybrid,
  type PQAlgorithm,
  type HybridSignOptions,
} from '@pq-jwt/hybrid';

const alg: PQAlgorithm = 'ML-DSA-65';
const options: HybridSignOptions = {
  expiresIn: '60s',
  pqAlgorithm: alg,
  issuer: 'ecosystem-test',
};

const { ecdsa, pq } = generateHybridKeyPair(alg);
const token = signHybrid(
  { runtime: 'typescript-nodenext' },
  ecdsa.secretKey,
  pq.secretKey,
  options
);
const { payload } = verifyHybrid(token, ecdsa.publicKey, pq.publicKey, {
  issuer: 'ecosystem-test',
});

if (payload.runtime !== 'typescript-nodenext') {
  throw new Error('TypeScript NodeNext consumer: verify payload mismatch');
}

console.log('OK typescript/nodenext');
