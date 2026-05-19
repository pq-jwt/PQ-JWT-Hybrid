/**
 * @package     @pq-jwt/hybrid
 * @author      Sachin Ruhil <sachinruhil11@gmail.com>
 * @version     1.0.0
 * @license     MIT
 * @description Hybrid JWT library — Fully compliant with IETF draft-prabel-jose-pq-composite-sigs-05
 * @copyright   2026 Sachin Ruhil. All rights reserved.
 * @see         https://github.com/pq-jwt/PQ-JWT-Hybrid
 *
 * This version implements the IETF Composite Algorithm Signatures 2025 standard.
 */

import { p256, p384 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const PREFIX = Buffer.from('436F6D706F73697465416C676F726974686D5369676E61747572657332303235', 'hex');

function hashPreHash(hashFn, data) {
  if (hashFn === shake256) {
    return hashFn(data, { dkLen: 64 });
  }
  return hashFn(data);
}

const ALGORITHMS = {
  'ML-DSA-44-ES256': {
    mldsa: ml_dsa44, trad: p256, tradType: 'ecdsa', hash: sha256,
    labelHex: '434F4D505349472D4D4C44534134342D45434453412D503235362D534841323536',
    mldsaPkLen: 1312, mldsaSkLen: 2560, mldsaSigLen: 2420, tradPkLen: 33, tradSkLen: 32
  },
  'ML-DSA-65-ES256': {
    mldsa: ml_dsa65, trad: p256, tradType: 'ecdsa', hash: sha512,
    labelHex: '434F4D505349472D4D4C44534136352D45434453412D503235362D534841353132',
    mldsaPkLen: 1952, mldsaSkLen: 4032, mldsaSigLen: 3309, tradPkLen: 33, tradSkLen: 32
  },
  'ML-DSA-87-ES384': {
    mldsa: ml_dsa87, trad: p384, tradType: 'ecdsa', hash: sha512,
    labelHex: '434F4D505349472D4D4C44534138372D45434453412D503338342D534841353132',
    mldsaPkLen: 2592, mldsaSkLen: 4896, mldsaSigLen: 4627, tradPkLen: 49, tradSkLen: 48
  },
  'ML-DSA-44-Ed25519': {
    mldsa: ml_dsa44, trad: ed25519, tradType: 'eddsa', hash: sha512,
    labelHex: '434F4D505349472D4D4C44534134342D456432353531392D534841353132',
    mldsaPkLen: 1312, mldsaSkLen: 2560, mldsaSigLen: 2420, tradPkLen: 32, tradSkLen: 32
  },
  'ML-DSA-65-Ed25519': {
    mldsa: ml_dsa65, trad: ed25519, tradType: 'eddsa', hash: sha512,
    labelHex: '434F4D505349472D4D4C44534136352D456432353531392D534841353132',
    mldsaPkLen: 1952, mldsaSkLen: 4032, mldsaSigLen: 3309, tradPkLen: 32, tradSkLen: 32
  },
  'ML-DSA-87-Ed448': {
    mldsa: ml_dsa87, trad: ed448, tradType: 'eddsa', hash: shake256,
    labelHex: '434F4D505349472D4D4C44534138372D45643434382D5348414B45323536',
    mldsaPkLen: 2592, mldsaSkLen: 4896, mldsaSigLen: 4627, tradPkLen: 57, tradSkLen: 57
  },
};

export const SUPPORTED_ALGORITHMS = Object.keys(ALGORITHMS);

// ── Custom errors ─────────────────────────────────────────────
export class HybridJWTError extends Error {
  constructor(message, code) { super(message); this.name = 'HybridJWTError'; this.code = code; }
}
export class HybridTokenExpiredError extends HybridJWTError {
  constructor(expiredAt) { super(`Token expired at ${new Date(expiredAt * 1000).toISOString()}`, 'TOKEN_EXPIRED'); this.name = 'HybridTokenExpiredError'; this.expiredAt = expiredAt; }
}
export class HybridInvalidTokenError extends HybridJWTError {
  constructor(reason) { super(`Invalid token: ${reason}`, 'INVALID_TOKEN'); this.name = 'HybridInvalidTokenError'; }
}
export class HybridSignatureError extends HybridJWTError {
  constructor(which) { super(which ? `Signature verification failed (${which})` : 'Signature verification failed', 'SIGNATURE_INVALID'); this.name = 'HybridSignatureError'; this.which = which ?? 'unknown'; }
}

// ── Encoding utilities ─────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromBase64Url(str) {
  const p = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = p.length % 4;
  return new Uint8Array(Buffer.from(pad ? p + '='.repeat(4 - pad) : p, 'base64'));
}
function encodeJSON(obj) { return toBase64Url(enc.encode(JSON.stringify(obj))); }
function decodeJSON(str) { return JSON.parse(dec.decode(fromBase64Url(str))); }

// ── Key utilities ─────────────────────────────────────────────

export function generateCompositeKeyPair(algorithm = 'ML-DSA-65-ES256') {
  const algParams = ALGORITHMS[algorithm];
  if (!algParams) throw new HybridJWTError(`Unknown algorithm "${algorithm}"`, 'UNKNOWN_ALGORITHM');

  // Generate ML-DSA key from 32-byte seed
  const seed = randomBytes(32);
  const mldsaKeyPair = algParams.mldsa.keygen(seed);

  // Generate traditional key
  const tradSecretKey = algParams.trad.utils.randomSecretKey();
  const tradPublicKey = algParams.trad.getPublicKey(tradSecretKey, true); // true = compressed for ecdsa

  // Composite Public Key: ML-DSA PK || Trad PK
  const compositePublicKey = new Uint8Array(algParams.mldsaPkLen + algParams.tradPkLen);
  compositePublicKey.set(mldsaKeyPair.publicKey, 0);
  compositePublicKey.set(tradPublicKey, algParams.mldsaPkLen);

  // Composite Private Key: ML-DSA Seed || Trad SK (seed is 32 bytes)
  const compositePrivateKey = new Uint8Array(32 + algParams.tradSkLen);
  compositePrivateKey.set(seed, 0);
  compositePrivateKey.set(tradSecretKey, 32);

  return { compositePublicKey, compositePrivateKey, algorithm };
}

export function exportCompositeKey(key) {
  if (!(key instanceof Uint8Array)) throw new HybridJWTError('exportCompositeKey expects Uint8Array', 'INVALID_KEY');
  return Buffer.from(key).toString('hex');
}
export function importCompositeKey(hexString) {
  if (typeof hexString !== 'string' || !/^[0-9a-f]+$/i.test(hexString)) throw new HybridJWTError('importCompositeKey expects a hex string', 'INVALID_KEY');
  return new Uint8Array(Buffer.from(hexString, 'hex'));
}

// ── Duration parser ───────────────────────────────────────────
function parseDuration(d) {
  if (typeof d === 'number') return d;
  const m = String(d).match(/^(\d+(?:\.\d+)?)(s|m|h|d|w)$/);
  if (!m) throw new HybridJWTError(`Invalid duration "${d}". Use number (seconds) or "1h","7d","30m".`, 'INVALID_DURATION');
  return Math.floor(parseFloat(m[1]) * { s:1, m:60, h:3600, d:86400, w:604800 }[m[2]]);
}

// ── signComposite() ──────────────────────────────────────────────
export function signComposite(payload, compositePrivateKey, options = {}) {
  if (typeof payload !== 'object' || payload === null) throw new HybridJWTError('Payload must be a non-null object', 'INVALID_PAYLOAD');

  const algorithm = options.algorithm ?? 'ML-DSA-65-ES256';
  const algParams = ALGORITHMS[algorithm];
  if (!algParams) throw new HybridJWTError(`Unknown algorithm "${algorithm}"`, 'UNKNOWN_ALGORITHM');

  const sk = typeof compositePrivateKey === 'string' ? importCompositeKey(compositePrivateKey) : compositePrivateKey;
  if (!(sk instanceof Uint8Array) || sk.length !== (32 + algParams.tradSkLen)) {
    throw new HybridJWTError(`Composite private key must be ${32 + algParams.tradSkLen} bytes for ${algorithm}`, 'INVALID_KEY');
  }

  // Split private key
  const mldsaSeed = sk.slice(0, 32);
  const tradSk = sk.slice(32);

  // Re-derive ML-DSA key
  const mldsaKeyPair = algParams.mldsa.keygen(mldsaSeed);

  const now = Math.floor(Date.now() / 1000);
  const claims = { iat: now, ...payload };
  if (options.expiresIn !== undefined) claims.exp = now + parseDuration(options.expiresIn);
  if (options.notBefore !== undefined) claims.nbf = now + parseDuration(options.notBefore);
  if (options.issuer) claims.iss = options.issuer;
  if (options.subject) claims.sub = options.subject;
  if (options.audience) claims.aud = options.audience;
  if (options.jwtId) claims.jti = options.jwtId;

  const header = { alg: algorithm, typ: 'JWT', ver: '2' };
  const he = encodeJSON(header);
  const pe = encodeJSON(claims);
  const signingInput = enc.encode(`${he}.${pe}`);

  // M' = Prefix || Label || 0x00 || PH(M)
  const label = Buffer.from(algParams.labelHex, 'hex');
  const phM = hashPreHash(algParams.hash, signingInput);
  
  const mPrime = new Uint8Array(PREFIX.length + label.length + 1 + phM.length);
  mPrime.set(PREFIX, 0);
  mPrime.set(label, PREFIX.length);
  mPrime.set([0x00], PREFIX.length + label.length);
  mPrime.set(phM, PREFIX.length + label.length + 1);

  // Base64URL encode M' per the IETF spec for JOSE
  const encodedMPrime = enc.encode(toBase64Url(mPrime));

  // ML-DSA signature
  const mldsaSig = algParams.mldsa.sign(encodedMPrime, mldsaKeyPair.secretKey, { context: label });

  // Traditional signature
  const tradSig = algParams.trad.sign(encodedMPrime, tradSk);

  // Concatenate signatures
  const compositeSignature = new Uint8Array(algParams.mldsaSigLen + tradSig.length);
  compositeSignature.set(mldsaSig, 0);
  compositeSignature.set(tradSig, algParams.mldsaSigLen);

  return `${he}.${pe}.${toBase64Url(compositeSignature)}`;
}

// ── verifyComposite() ────────────────────────────────────────────
export function verifyComposite(token, compositePublicKey, options = {}) {
  if (typeof token !== 'string') throw new HybridInvalidTokenError('token must be a string');

  const parts = token.split('.');
  if (parts.length !== 3) throw new HybridInvalidTokenError('token must have 3 dot-separated parts');
  
  const [he, pe, se] = parts;

  let header;
  try { header = decodeJSON(he); } catch { throw new HybridInvalidTokenError('header is not valid base64url JSON'); }
  if (!ALGORITHMS[header.alg]) throw new HybridInvalidTokenError(`unrecognized algorithm "${header.alg}"`);
  
  const algorithm = header.alg;
  const algParams = ALGORITHMS[algorithm];

  const pk = typeof compositePublicKey === 'string' ? importCompositeKey(compositePublicKey) : compositePublicKey;
  if (!(pk instanceof Uint8Array) || pk.length !== (algParams.mldsaPkLen + algParams.tradPkLen)) {
    throw new HybridJWTError(`Composite public key must be ${algParams.mldsaPkLen + algParams.tradPkLen} bytes for ${algorithm}`, 'INVALID_KEY');
  }

  // Split public key
  const mldsaPk = pk.slice(0, algParams.mldsaPkLen);
  const tradPk = pk.slice(algParams.mldsaPkLen);

  const sigBytes = fromBase64Url(se);
  const tradSigLen = sigBytes.length - algParams.mldsaSigLen;
  if (tradSigLen <= 0) throw new HybridInvalidTokenError('signature too short');

  const mldsaSig = sigBytes.slice(0, algParams.mldsaSigLen);
  const tradSigBytes = sigBytes.slice(algParams.mldsaSigLen);

  let payload;
  try { payload = decodeJSON(pe); } catch { throw new HybridInvalidTokenError('payload is not valid base64url JSON'); }

  // M' = Prefix || Label || 0x00 || PH(M)
  const signingInput = enc.encode(`${he}.${pe}`);
  const label = Buffer.from(algParams.labelHex, 'hex');
  const phM = hashPreHash(algParams.hash, signingInput);
  
  const mPrime = new Uint8Array(PREFIX.length + label.length + 1 + phM.length);
  mPrime.set(PREFIX, 0);
  mPrime.set(label, PREFIX.length);
  mPrime.set([0x00], PREFIX.length + label.length);
  mPrime.set(phM, PREFIX.length + label.length + 1);

  const encodedMPrime = enc.encode(toBase64Url(mPrime));

  // Verify ML-DSA
  let pqOk = false;
  try { pqOk = algParams.mldsa.verify(mldsaSig, encodedMPrime, mldsaPk, { context: label }); } catch { pqOk = false; }
  if (!pqOk) throw new HybridSignatureError('ML-DSA');

  // Verify Traditional
  let tradOk = false;
  try {
    if (algParams.tradType === 'ecdsa') {
      tradOk = algParams.trad.verify(tradSigBytes, encodedMPrime, tradPk);
    } else {
      tradOk = algParams.trad.verify(tradSigBytes, encodedMPrime, tradPk);
    }
  } catch { tradOk = false; }
  if (!tradOk) throw new HybridSignatureError('Traditional');

  _validateClaims(payload, options);
  return { header, payload };
}

// ── decode() — no verification ─────────────────────────────────
export function decode(token) {
  if (typeof token !== 'string') throw new HybridInvalidTokenError('token must be a string');
  const parts = token.split('.');
  if (parts.length !== 3) throw new HybridInvalidTokenError('token must have 3 dot-separated parts');
  let header, payload;
  try { header = decodeJSON(parts[0]); } catch { throw new HybridInvalidTokenError('header is not valid base64url JSON'); }
  try { payload = decodeJSON(parts[1]); } catch { throw new HybridInvalidTokenError('payload is not valid base64url JSON'); }
  return {
    header,
    payload,
    signature: fromBase64Url(parts[2])
  };
}

// ── Internal helpers ──────────────────────────────────────────
function _validateClaims(payload, options) {
  const now = Math.floor(Date.now() / 1000);
  const tol = options.clockTolerance ?? 0;

  if (!options.ignoreExpiry && payload.exp !== undefined)
    if (now > payload.exp + tol) throw new HybridTokenExpiredError(payload.exp);

  if (payload.nbf !== undefined)
    if (now < payload.nbf - tol)
      throw new HybridJWTError(`Token not valid before ${new Date(payload.nbf * 1000).toISOString()}`, 'TOKEN_NOT_YET_VALID');

  if (options.issuer && payload.iss !== options.issuer)
    throw new HybridInvalidTokenError(`issuer mismatch: expected "${options.issuer}", got "${payload.iss}"`);

  if (options.audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(options.audience)) throw new HybridInvalidTokenError('audience mismatch');
  }

  if (options.subject && payload.sub !== options.subject)
    throw new HybridInvalidTokenError('subject mismatch');
}
