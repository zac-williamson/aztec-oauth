/**
 * JWKS key fetcher and transformer.
 *
 * Fetches JWK key sets from provider endpoints (Google, Apple),
 * filters for RSA/RS256 keys, and transforms them into the limb format
 * expected by the JwksRegistry contract.
 */

import { computeKidHash } from "./kid-hash.js";

// ─── JWK Types ──────────────────────────────────────────────────────────────

export interface JwkKey {
  kty: string;
  kid: string;
  use?: string;
  alg: string;
  n: string; // Base64URL-encoded RSA modulus
  e: string; // Base64URL-encoded RSA exponent
}

export interface ProcessedKey {
  kid: string;
  kidHash: any; // Fr element from Pedersen hash
  providerId: number;
  modulusLimbs: bigint[];
  redcParamsLimbs: bigint[];
}

// ─── Constants ──────────────────────────────────────────────────────────────

const LIMB_BITS = 120n;
const NUM_LIMBS = 18;
const RSA_BITS = 2048n;

// ─── Pure math utilities (inlined from registry/scripts/src/jwk-transform.ts)

/**
 * Decode a Base64URL string to a Uint8Array.
 */
function base64UrlDecode(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64url"));
}

/**
 * Convert a Uint8Array to a BigInt (big-endian).
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Split a BigInt into fixed-size limbs (little-endian limb order).
 */
function splitBigIntToLimbs(
  value: bigint,
  limbBits: bigint,
  numLimbs: number
): bigint[] {
  const mask = (1n << limbBits) - 1n;
  const limbs: bigint[] = [];
  let remaining = value;
  for (let i = 0; i < numLimbs; i++) {
    limbs.push(remaining & mask);
    remaining >>= limbBits;
  }
  if (remaining !== 0n) {
    throw new Error(
      `Value too large for ${numLimbs} limbs of ${limbBits} bits`
    );
  }
  return limbs;
}

/**
 * Compute Barrett reduction parameters for the given modulus.
 * redc_param = floor(2^(2*2048+6) / modulus)
 *
 * OVERFLOW_BITS=6 for noir-bignum v0.9.2+
 */
function computeRedcParams(modulus: bigint): bigint {
  const twoK = 2n * RSA_BITS; // 4096
  return (1n << (twoK + 6n)) / modulus;
}

/**
 * Convert a JWK RSA modulus (Base64URL `n` field) to limb arrays.
 */
function jwkModulusToLimbs(modulusBase64Url: string): {
  modulusLimbs: bigint[];
  redcParamsLimbs: bigint[];
} {
  const modulusBytes = base64UrlDecode(modulusBase64Url);
  const modulusBigInt = bytesToBigInt(modulusBytes);
  const modulusLimbs = splitBigIntToLimbs(modulusBigInt, LIMB_BITS, NUM_LIMBS);
  const redcParams = computeRedcParams(modulusBigInt);
  const redcParamsLimbs = splitBigIntToLimbs(redcParams, LIMB_BITS, NUM_LIMBS);

  return { modulusLimbs, redcParamsLimbs };
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Fetch JWKS from a provider endpoint and process RSA/RS256 keys.
 *
 * @param providerId - Numeric provider identifier (1=Google, 2=Apple)
 * @param jwksUrl - JWKS endpoint URL
 * @returns Array of processed keys ready for on-chain comparison/submission
 */
export async function fetchAndProcessKeys(
  providerId: number,
  jwksUrl: string
): Promise<ProcessedKey[]> {
  const response = await fetch(jwksUrl);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch JWKS from ${jwksUrl}: ${response.status} ${response.statusText}`
    );
  }

  const jwks = (await response.json()) as { keys: JwkKey[] };
  const rsaKeys = jwks.keys.filter(
    (k) => k.kty === "RSA" && k.alg === "RS256"
  );

  if (rsaKeys.length === 0) {
    console.warn(`No RSA/RS256 keys found at ${jwksUrl}`);
    return [];
  }

  const processed: ProcessedKey[] = [];
  for (const key of rsaKeys) {
    const kidHash = await computeKidHash(key.kid);
    const { modulusLimbs, redcParamsLimbs } = jwkModulusToLimbs(key.n);

    processed.push({
      kid: key.kid,
      kidHash,
      providerId,
      modulusLimbs,
      redcParamsLimbs,
    });
  }

  return processed;
}
