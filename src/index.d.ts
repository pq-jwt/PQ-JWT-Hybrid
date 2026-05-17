/**
 * @package     @pq-jwt/hybrid
 * @author      Sachin Ruhil <sachinruhil11@gmail.com>
 * @version     0.0.1
 * @license     MIT
 * @description Hybrid JWT — ECDSA P-256 + ML-DSA dual signing. Migration bridge.
 * @copyright   2026 Sachin Ruhil. All rights reserved.
 * @see         https://github.com/pq-jwt/PQ-JWT-Hybrid
 */

export type PQAlgorithm =
  | 'ML-DSA-44'
  | 'ML-DSA-65'
  | 'ML-DSA-87'
  | 'SLH-DSA-SHA2-128s';

export const SUPPORTED_PQ_ALGORITHMS: PQAlgorithm[];

export interface ECDSAKeyPair {
  /** 33-byte compressed P-256 public key */
  publicKey: Uint8Array;
  /** 32-byte P-256 private key */
  secretKey: Uint8Array;
}

export interface PQKeyPair {
  publicKey:  Uint8Array;
  secretKey:  Uint8Array;
  algorithm:  PQAlgorithm;
}

export interface HybridKeyPair {
  ecdsa: ECDSAKeyPair;
  pq:    PQKeyPair;
}

export interface HybridSignOptions {
  /** Post-quantum algorithm. Default: 'ML-DSA-65' */
  pqAlgorithm?: PQAlgorithm;
  /** Token lifetime — duration string ('1h','7d') or seconds */
  expiresIn?:   number | string;
  /** Not-before — duration string or seconds from now */
  notBefore?:   number | string;
  issuer?:      string;
  subject?:     string;
  audience?:    string;
  jwtId?:       string;
}

export interface HybridVerifyOptions {
  issuer?:          string;
  audience?:        string;
  subject?:         string;
  ignoreExpiry?:    boolean;
  /** Seconds of allowed clock skew. Default: 0 (strict) */
  clockTolerance?:  number;
}

export interface HybridTokenHeader {
  /** e.g. 'ECDSA-P256+ML-DSA-65' */
  alg: string;
  typ: 'HYBRID-JWT';
  ver: '1';
  [key: string]: unknown;
}

export interface DecodedHybridToken {
  header:          HybridTokenHeader;
  payload:         Record<string, unknown>;
  /** 64-byte P-256 compact r||s signature */
  ecdsaSignature:  Uint8Array | null;
  /** ML-DSA signature bytes */
  pqSignature:     Uint8Array | null;
}

/* ── Error classes ── */

export class HybridJWTError extends Error {
  code: string;
  constructor(message: string, code: string);
}

export class HybridTokenExpiredError extends HybridJWTError {
  expiredAt: number;
  constructor(expiredAt: number);
}

export class HybridInvalidTokenError extends HybridJWTError {
  constructor(reason: string);
}

export class HybridSignatureError extends HybridJWTError {
  /** 'ECDSA' | 'ML-DSA' | 'unknown' */
  which: string;
  constructor(which?: string);
}

/* ── Key utilities ── */

/** Generate a full hybrid key pair (ECDSA + ML-DSA) */
export function generateHybridKeyPair(pqAlgorithm?: PQAlgorithm): HybridKeyPair;

/** Serialize a key (Uint8Array) to hex string for storage */
export function exportKey(key: Uint8Array): string;

/** Deserialize a hex string back to a key (Uint8Array) */
export function importKey(hexString: string): Uint8Array;

/* ── Core functions ── */

/**
 * Sign a payload with BOTH ECDSA P-256 AND ML-DSA.
 * Returns a 3-part dot-separated HYBRID-JWT token.
 *
 * @example
 * const token = signHybrid(
 *   { sub: 'user_42', role: 'admin' },
 *   ecdsaSecretKey,
 *   pqSecretKey,
 *   { pqAlgorithm: 'ML-DSA-65', expiresIn: '1h', issuer: 'auth.myapp.com' }
 * );
 */
export function signHybrid(
  payload:       Record<string, unknown>,
  ecdsaSecretKey: Uint8Array | string,
  pqSecretKey:   Uint8Array | string,
  options?:      HybridSignOptions
): string;

/**
 * Verify a hybrid token using BOTH signatures (ECDSA + ML-DSA).
 * Both must be valid. Use on bridge services during migration.
 */
export function verifyHybrid(
  token:          string,
  ecdsaPublicKey: Uint8Array | string,
  pqPublicKey:    Uint8Array | string,
  options?:       HybridVerifyOptions
): { header: HybridTokenHeader; payload: Record<string, unknown> };

/**
 * Verify using ONLY the ML-DSA (post-quantum) signature.
 * Use on new services that only care about quantum-safe verification.
 * Does not require the ECDSA public key.
 */
export function verifyPQ(
  token:       string,
  pqPublicKey: Uint8Array | string,
  options?:    HybridVerifyOptions
): { header: HybridTokenHeader; payload: Record<string, unknown> };

/**
 * Verify using ONLY the ECDSA P-256 (classical) signature.
 * Use on legacy services that haven't yet been updated to ML-DSA.
 * Does not require the PQ public key.
 */
export function verifyEcdsa(
  token:          string,
  ecdsaPublicKey: Uint8Array | string,
  options?:       HybridVerifyOptions
): { header: HybridTokenHeader; payload: Record<string, unknown> };

/**
 * Decode a hybrid token WITHOUT verifying either signature.
 * For inspection only. Never use the result for authorization.
 */
export function decode(token: string): DecodedHybridToken;
