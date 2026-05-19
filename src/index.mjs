/**
 * @package     @pq-jwt/hybrid
 * @author      Sachin Ruhil <sachinruhil11@gmail.com>
 * @version     0.0.1
 * @license     MIT
 * @description Hybrid JWT library — ECDSA P-256 + ML-DSA dual signing.
 *              Migration bridge from classical to post-quantum authentication.
 * @copyright   2026 Sachin Ruhil. All rights reserved.
 * @see         https://github.com/pq-jwt/PQ-JWT-Hybrid
 *
 * Token format:
 *   base64url(header) . base64url(payload) . base64url(combined_signature)
 *
 *   combined_signature = base64url(JSON({
 *     e: hex(ecdsa_sig_64_bytes),   // P-256 compact r||s
 *     m: hex(mldsa_sig_bytes),      // ML-DSA signature
 *   }))
 *
 * Header:
 *   { alg: "ML-DSA-65-ES256", typ: "HYBRID-JWT", ver: "1" }
 *
 * Migration phases:
 *   Phase 1 — issue hybrid tokens, verify with verifyHybrid() on all services
 *   Phase 2 — new services verify PQ only (verifyPQ), old still accept ECDSA
 *   Phase 3 — drop ECDSA keys, move to @pq-jwt/core sign() + verify()
 */

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';


// ── Algorithm registry ────────────────────────────────────────
const PQ_ALGORITHMS = {
  'ML-DSA-44': { impl: ml_dsa44, skLen: 2560, pkLen: 1312 },
  'ML-DSA-65': { impl: ml_dsa65, skLen: 4032, pkLen: 1952 },
  'ML-DSA-87': { impl: ml_dsa87, skLen: 4896, pkLen: 2592 },
  'SLH-DSA-SHA2-128s': { impl: slh_dsa_sha2_128s, skLen: 64, pkLen: 32 },
};

export const SUPPORTED_PQ_ALGORITHMS = Object.keys(PQ_ALGORITHMS);

// ECDSA P-256 constants
const ECDSA_SK_LEN = 32;  // bytes
const ECDSA_PK_LEN = 33;  // compressed
const ECDSA_SIG_LEN = 64; // compact r||s

// ── Custom errors ─────────────────────────────────────────────
export class HybridJWTError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'HybridJWTError';
    this.code = code;
  }
}
export class HybridTokenExpiredError extends HybridJWTError {
  constructor(expiredAt) {
    super(
      `Token expired at ${new Date(expiredAt * 1000).toISOString()}`,
      'TOKEN_EXPIRED'
    );
    this.name = 'HybridTokenExpiredError';
    this.expiredAt = expiredAt;
  }
}
export class HybridInvalidTokenError extends HybridJWTError {
  constructor(reason) {
    super(`Invalid token: ${reason}`, 'INVALID_TOKEN');
    this.name = 'HybridInvalidTokenError';
  }
}
export class HybridSignatureError extends HybridJWTError {
  constructor(which) {
    super(
      which
        ? `Signature verification failed (${which})`
        : 'Signature verification failed',
      'SIGNATURE_INVALID'
    );
    this.name = 'HybridSignatureError';
    this.which = which ?? 'unknown';
  }
}

// ── Encoding utilities ─────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64Url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
function fromBase64Url(str) {
  const p = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = p.length % 4;
  return new Uint8Array(Buffer.from(pad ? p + '='.repeat(4 - pad) : p, 'base64'));
}
function encodeJSON(obj) {
  return toBase64Url(enc.encode(JSON.stringify(obj)));
}
function decodeJSON(str) {
  return JSON.parse(dec.decode(fromBase64Url(str)));
}

// ── Key utilities ─────────────────────────────────────────────

/**
 * Generate a hybrid key pair — both ECDSA P-256 and ML-DSA keys.
 *
 * @param {'ML-DSA-44'|'ML-DSA-65'|'ML-DSA-87'|'SLH-DSA-SHA2-128s'} pqAlgorithm
 * @returns {{ ecdsa: { publicKey, secretKey }, pq: { publicKey, secretKey, algorithm } }}
 */
export function generateHybridKeyPair(pqAlgorithm = 'ML-DSA-65') {
  const pqAlg = PQ_ALGORITHMS[pqAlgorithm];
  if (!pqAlg) throw new HybridJWTError(
    `Unknown PQ algorithm "${pqAlgorithm}". Supported: ${SUPPORTED_PQ_ALGORITHMS.join(', ')}`,
    'UNKNOWN_ALGORITHM'
  );
  const ecdsaSecretKey = p256.utils.randomSecretKey();
  const ecdsaPublicKey = p256.getPublicKey(ecdsaSecretKey, true);
  const pqKp = pqAlg.impl.keygen();
  return {
    ecdsa: { publicKey: ecdsaPublicKey, secretKey: ecdsaSecretKey },
    pq:    { publicKey: pqKp.publicKey, secretKey: pqKp.secretKey, algorithm: pqAlgorithm },
  };
}

/**
 * Export a key (Uint8Array) to a hex string for secure storage.
 */
export function exportKey(key) {
  if (!(key instanceof Uint8Array))
    throw new HybridJWTError('exportKey expects Uint8Array', 'INVALID_KEY');
  return Buffer.from(key).toString('hex');
}

/**
 * Import a hex string back to a key (Uint8Array).
 */
export function importKey(hexString) {
  if (typeof hexString !== 'string' || !/^[0-9a-f]+$/i.test(hexString))
    throw new HybridJWTError('importKey expects a hex string', 'INVALID_KEY');
  return new Uint8Array(Buffer.from(hexString, 'hex'));
}

// ── Duration parser ───────────────────────────────────────────
function parseDuration(d) {
  if (typeof d === 'number') return d;
  const m = String(d).match(/^(\d+(?:\.\d+)?)(s|m|h|d|w)$/);
  if (!m) throw new HybridJWTError(
    `Invalid duration "${d}". Use number (seconds) or "1h","7d","30m".`,
    'INVALID_DURATION'
  );
  return Math.floor(parseFloat(m[1]) * { s:1, m:60, h:3600, d:86400, w:604800 }[m[2]]);
}

// ── Core signing input ────────────────────────────────────────
function buildSigningInput(header, claims) {
  const he = encodeJSON(header);
  const pe = encodeJSON(claims);
  return { he, pe, bytes: enc.encode(`${he}.${pe}`) };
}

// ── signHybrid() ──────────────────────────────────────────────
/**
 * Sign a payload with BOTH ECDSA P-256 AND ML-DSA.
 * The resulting token carries both signatures.
 *
 * Old services: call verifyEcdsa(token, ecdsaPublicKey)
 * New services: call verifyPQ(token, pqPublicKey)
 * Bridge services: call verifyHybrid(token, ecdsaPublicKey, pqPublicKey)
 *
 * @param {object}           payload
 * @param {Uint8Array|string} ecdsaSecretKey  — 32-byte P-256 private key or hex
 * @param {Uint8Array|string} pqSecretKey     — ML-DSA secret key or hex
 * @param {object}           [options]
 * @param {'ML-DSA-44'|'ML-DSA-65'|'ML-DSA-87'|'SLH-DSA-SHA2-128s'} [options.pqAlgorithm='ML-DSA-65']
 * @param {number|string}    [options.expiresIn]
 * @param {number|string}    [options.notBefore]
 * @param {string}           [options.issuer]
 * @param {string}           [options.subject]
 * @param {string}           [options.audience]
 * @param {string}           [options.jwtId]
 * @returns {string}  — header.payload.combined_signature
 */
export function signHybrid(payload, ecdsaSecretKey, pqSecretKey, options = {}) {
  if (typeof payload !== 'object' || payload === null)
    throw new HybridJWTError('Payload must be a non-null object', 'INVALID_PAYLOAD');

  const pqAlgorithm = options.pqAlgorithm ?? 'ML-DSA-65';
  const pqAlg = PQ_ALGORITHMS[pqAlgorithm];
  if (!pqAlg) throw new HybridJWTError(
    `Unknown PQ algorithm "${pqAlgorithm}"`, 'UNKNOWN_ALGORITHM'
  );

  const ecSk = typeof ecdsaSecretKey === 'string' ? importKey(ecdsaSecretKey) : ecdsaSecretKey;
  if (!(ecSk instanceof Uint8Array) || ecSk.length !== ECDSA_SK_LEN)
    throw new HybridJWTError(`ECDSA secret key must be ${ECDSA_SK_LEN} bytes`, 'INVALID_KEY');

  const pqSk = typeof pqSecretKey === 'string' ? importKey(pqSecretKey) : pqSecretKey;
  if (!(pqSk instanceof Uint8Array) || pqSk.length !== pqAlg.skLen)
    throw new HybridJWTError(
      `PQ secret key must be ${pqAlg.skLen} bytes for ${pqAlgorithm}`, 'INVALID_KEY'
    );

  const now = Math.floor(Date.now() / 1000);
  const claims = { iat: now, ...payload };

  if (options.expiresIn !== undefined) claims.exp = now + parseDuration(options.expiresIn);
  if (options.notBefore !== undefined) claims.nbf = now + parseDuration(options.notBefore);
  if (options.issuer)   claims.iss = options.issuer;
  if (options.subject)  claims.sub = options.subject;
  if (options.audience) claims.aud = options.audience;
  if (options.jwtId)    claims.jti = options.jwtId;

  const header = {
    alg: `${pqAlgorithm}-ES256`,
    typ: 'HYBRID-JWT',
    ver: '1',
  };

  const { he, pe, bytes } = buildSigningInput(header, claims);

  // ECDSA: sign SHA-256 of signing input
  const ecdsaSig = p256.sign(sha256(bytes), ecSk);

  // ML-DSA: sign SHA-512 of signing input
  const pqSig = pqAlg.impl.sign(sha512(bytes), pqSk);

  // Combine both signatures in one JSON envelope
  const combined = encodeJSON({
    e: Buffer.from(ecdsaSig).toString('hex'),
    m: Buffer.from(pqSig).toString('hex'),
  });

  return `${he}.${pe}.${combined}`;
}

// ── verifyHybrid() ────────────────────────────────────────────
/**
 * Verify a hybrid token using BOTH ECDSA and ML-DSA signatures.
 * Both must be valid. Use during the transition period on services
 * that need to validate both classical and PQ halves.
 *
 * @param {string}           token
 * @param {Uint8Array|string} ecdsaPublicKey  — 33-byte compressed P-256 public key or hex
 * @param {Uint8Array|string} pqPublicKey     — ML-DSA public key or hex
 * @param {object}           [options]
 * @param {string}           [options.issuer]
 * @param {string}           [options.audience]
 * @param {string}           [options.subject]
 * @param {boolean}          [options.ignoreExpiry]
 * @param {number}           [options.clockTolerance]  seconds, default 0
 * @returns {{ header, payload }}
 */
export function verifyHybrid(token, ecdsaPublicKey, pqPublicKey, options = {}) {
  const { header, payload, he, pe, ecdsaSig, pqSig, pqAlgorithm } =
    _decodeAndValidateStructure(token);

  const ecPk = typeof ecdsaPublicKey === 'string' ? importKey(ecdsaPublicKey) : ecdsaPublicKey;
  if (!(ecPk instanceof Uint8Array) || ecPk.length !== ECDSA_PK_LEN)
    throw new HybridJWTError(`ECDSA public key must be ${ECDSA_PK_LEN} bytes`, 'INVALID_KEY');

  const pqAlg = PQ_ALGORITHMS[pqAlgorithm];
  const pqPk = typeof pqPublicKey === 'string' ? importKey(pqPublicKey) : pqPublicKey;
  if (!(pqPk instanceof Uint8Array) || pqPk.length !== pqAlg.pkLen)
    throw new HybridJWTError(
      `PQ public key must be ${pqAlg.pkLen} bytes for ${pqAlgorithm}`, 'INVALID_KEY'
    );

  const signingBytes = enc.encode(`${he}.${pe}`);

  // Verify ECDSA
  let ecdsaOk = false;
  try { ecdsaOk = p256.verify(ecdsaSig, sha256(signingBytes), ecPk); }
  catch { ecdsaOk = false; }
  if (!ecdsaOk) throw new HybridSignatureError('ECDSA');

  // Verify ML-DSA
  let pqOk = false;
  try { pqOk = pqAlg.impl.verify(pqSig, sha512(signingBytes), pqPk); }
  catch { pqOk = false; }
  if (!pqOk) throw new HybridSignatureError('ML-DSA');

  _validateClaims(payload, options);
  return { header, payload };
}

// ── verifyPQ() ────────────────────────────────────────────────
/**
 * Verify only the ML-DSA (post-quantum) signature.
 * Use on new services that only care about quantum-safe verification.
 *
 * @param {string}           token
 * @param {Uint8Array|string} pqPublicKey
 * @param {object}           [options]
 * @returns {{ header, payload }}
 */
export function verifyPQ(token, pqPublicKey, options = {}) {
  const { header, payload, he, pe, pqSig, pqAlgorithm } =
    _decodeAndValidateStructure(token);

  const pqAlg = PQ_ALGORITHMS[pqAlgorithm];
  const pqPk = typeof pqPublicKey === 'string' ? importKey(pqPublicKey) : pqPublicKey;
  if (!(pqPk instanceof Uint8Array) || pqPk.length !== pqAlg.pkLen)
    throw new HybridJWTError(
      `PQ public key must be ${pqAlg.pkLen} bytes for ${pqAlgorithm}`, 'INVALID_KEY'
    );

  const signingBytes = enc.encode(`${he}.${pe}`);
  let pqOk = false;
  try { pqOk = pqAlg.impl.verify(pqSig, sha512(signingBytes), pqPk); }
  catch { pqOk = false; }
  if (!pqOk) throw new HybridSignatureError('ML-DSA');

  _validateClaims(payload, options);
  return { header, payload };
}

// ── verifyEcdsa() ─────────────────────────────────────────────
/**
 * Verify only the ECDSA P-256 signature — the classical (legacy) path.
 * Use on existing services that have not yet been upgraded to ML-DSA.
 * During Phase 1 migration, old services call this; new services call verifyPQ.
 *
 * @param {string}           token
 * @param {Uint8Array|string} ecdsaPublicKey  — 33-byte compressed P-256 public key or hex
 * @param {object}           [options]
 * @returns {{ header, payload }}
 */
export function verifyEcdsa(token, ecdsaPublicKey, options = {}) {
  const { header, payload, he, pe, ecdsaSig } =
    _decodeAndValidateStructure(token);

  const ecPk = typeof ecdsaPublicKey === 'string' ? importKey(ecdsaPublicKey) : ecdsaPublicKey;
  if (!(ecPk instanceof Uint8Array) || ecPk.length !== ECDSA_PK_LEN)
    throw new HybridJWTError(`ECDSA public key must be ${ECDSA_PK_LEN} bytes`, 'INVALID_KEY');

  const signingBytes = enc.encode(`${he}.${pe}`);
  let ecdsaOk = false;
  try { ecdsaOk = p256.verify(ecdsaSig, sha256(signingBytes), ecPk); }
  catch { ecdsaOk = false; }
  if (!ecdsaOk) throw new HybridSignatureError('ECDSA');

  _validateClaims(payload, options);
  return { header, payload };
}

// ── decode() — no verification ─────────────────────────────────
/**
 * Decode a hybrid token WITHOUT verifying either signature.
 * For inspection only — never use the payload for authorization.
 */
export function decode(token) {
  if (typeof token !== 'string')
    throw new HybridInvalidTokenError('token must be a string');
  const parts = token.split('.');
  if (parts.length !== 3)
    throw new HybridInvalidTokenError('token must have 3 dot-separated parts');
  let header, payload;
  try { header = decodeJSON(parts[0]); } catch { throw new HybridInvalidTokenError('header is not valid base64url JSON'); }
  try { payload = decodeJSON(parts[1]); } catch { throw new HybridInvalidTokenError('payload is not valid base64url JSON'); }
  let combined;
  try { combined = decodeJSON(parts[2]); } catch { throw new HybridInvalidTokenError('signature segment is not valid base64url JSON'); }
  return {
    header,
    payload,
    ecdsaSignature: combined.e ? new Uint8Array(Buffer.from(combined.e, 'hex')) : null,
    pqSignature:    combined.m ? new Uint8Array(Buffer.from(combined.m, 'hex')) : null,
  };
}

// ── Internal helpers ──────────────────────────────────────────

function _decodeAndValidateStructure(token) {
  if (typeof token !== 'string')
    throw new HybridInvalidTokenError('token must be a string');

  const parts = token.split('.');
  if (parts.length !== 3)
    throw new HybridInvalidTokenError('token must have 3 dot-separated parts');

  const [he, pe, se] = parts;

  let header;
  try { header = decodeJSON(he); }
  catch { throw new HybridInvalidTokenError('header is not valid base64url JSON'); }

  if (header.typ !== 'HYBRID-JWT')
    throw new HybridInvalidTokenError(`expected typ "HYBRID-JWT", got "${header.typ}"`);

  // Parse alg: "ML-DSA-65-ES256"
  const algMatch = (header.alg ?? '').match(/^(.+)-ES256$/);
  if (!algMatch)
    throw new HybridInvalidTokenError(`unrecognized algorithm "${header.alg}"`);

  const pqAlgorithm = algMatch[1];
  if (!PQ_ALGORITHMS[pqAlgorithm])
    throw new HybridInvalidTokenError(`unrecognized PQ algorithm "${pqAlgorithm}"`);

  let payload;
  try { payload = decodeJSON(pe); }
  catch { throw new HybridInvalidTokenError('payload is not valid base64url JSON'); }

  let combined;
  try { combined = decodeJSON(se); }
  catch { throw new HybridInvalidTokenError('signature segment is not valid base64url JSON'); }

  if (!combined.e || !combined.m)
    throw new HybridInvalidTokenError('signature segment missing ECDSA (e) or ML-DSA (m) field');

  const ecdsaSig = new Uint8Array(Buffer.from(combined.e, 'hex'));
  const pqSig    = new Uint8Array(Buffer.from(combined.m, 'hex'));

  if (ecdsaSig.length !== ECDSA_SIG_LEN)
    throw new HybridInvalidTokenError(`ECDSA sig must be ${ECDSA_SIG_LEN} bytes, got ${ecdsaSig.length}`);

  return { header, payload, he, pe, ecdsaSig, pqSig, pqAlgorithm };
}

function _validateClaims(payload, options) {
  const now = Math.floor(Date.now() / 1000);
  const tol = options.clockTolerance ?? 0;

  if (!options.ignoreExpiry && payload.exp !== undefined)
    if (now > payload.exp + tol)
      throw new HybridTokenExpiredError(payload.exp);

  if (payload.nbf !== undefined)
    if (now < payload.nbf - tol)
      throw new HybridJWTError(
        `Token not valid before ${new Date(payload.nbf * 1000).toISOString()}`,
        'TOKEN_NOT_YET_VALID'
      );

  if (options.issuer && payload.iss !== options.issuer)
    throw new HybridInvalidTokenError(
      `issuer mismatch: expected "${options.issuer}", got "${payload.iss}"`
    );

  if (options.audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(options.audience))
      throw new HybridInvalidTokenError('audience mismatch');
  }

  if (options.subject && payload.sub !== options.subject)
    throw new HybridInvalidTokenError('subject mismatch');
}
