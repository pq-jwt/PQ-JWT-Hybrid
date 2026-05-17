import {
  generateHybridKeyPair,
  signHybrid,
  verifyHybrid,
  verifyPQ,
  verifyEcdsa,
} from '../src/index.mjs';

const { ecdsa, pq } = generateHybridKeyPair('ML-DSA-65');

const token = signHybrid(
  { userId: 123, role: 'admin' },
  ecdsa.secretKey,
  pq.secretKey,
  { expiresIn: '1h', issuer: 'my-app', pqAlgorithm: 'ML-DSA-65' }
);

console.log('Token:', token);

const hybrid = verifyHybrid(token, ecdsa.publicKey, pq.publicKey, { issuer: 'my-app' });
console.log('Hybrid verify:', hybrid.payload);

const pqOnly = verifyPQ(token, pq.publicKey, { issuer: 'my-app' });
console.log('PQ verify:', pqOnly.payload);

const ecdsaOnly = verifyEcdsa(token, ecdsa.publicKey);
console.log('ECDSA verify:', ecdsaOnly.payload);
