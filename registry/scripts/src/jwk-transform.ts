/**
 * JWK Transform Utilities
 *
 * Converts JWK RSA public key material (Base64URL-encoded modulus `n`)
 * into the 18-limb BigNum format expected by noir-jwt and the JwksRegistry contract.
 *
 * Each limb = 120 bits. 18 limbs * 120 bits = 2160 bits >= 2048 bits (RSA-2048).
 *
 * Also computes Barrett reduction parameters: floor(2^(2*2048+6) / modulus)
 * used by noir_rsa (bignum v0.9.2+) for efficient modular arithmetic.
 */

const LIMB_BITS = 120n;
const NUM_LIMBS = 18;
const RSA_BITS = 2048n;

/**
 * Decode a Base64URL string to a Uint8Array.
 */
export function base64UrlDecode(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64url"));
}

/**
 * Convert a Uint8Array to a BigInt (big-endian).
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Split a BigInt into fixed-size limbs (little-endian limb order).
 * Each limb has `limbBits` bits. Returns exactly `numLimbs` limbs.
 */
export function splitBigIntToLimbs(
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
export function computeRedcParams(modulus: bigint): bigint {
  const twoK = 2n * RSA_BITS; // 4096
  const redc = (1n << (twoK + 6n)) / modulus;
  return redc;
}

/**
 * Convert a JWK RSA modulus (Base64URL `n` field) to the format needed by the contract.
 *
 * Returns:
 * - modulusLimbs: [bigint; 18] — RSA modulus as 18x120-bit limbs
 * - redcParamsLimbs: [bigint; 18] — Barrett reduction params as 18x120-bit limbs
 * - modulusBigInt: bigint — raw modulus value
 */
export function jwkModulusToLimbs(modulusBase64Url: string): {
  modulusLimbs: bigint[];
  redcParamsLimbs: bigint[];
  modulusBigInt: bigint;
} {
  const modulusBytes = base64UrlDecode(modulusBase64Url);
  const modulusBigInt = bytesToBigInt(modulusBytes);
  const modulusLimbs = splitBigIntToLimbs(modulusBigInt, LIMB_BITS, NUM_LIMBS);
  const redcParams = computeRedcParams(modulusBigInt);
  const redcParamsLimbs = splitBigIntToLimbs(redcParams, LIMB_BITS, NUM_LIMBS);

  return { modulusLimbs, redcParamsLimbs, modulusBigInt };
}

/**
 * Convert limbs to hex strings suitable for Aztec.js Field arguments.
 */
export function limbsToHexStrings(limbs: bigint[]): string[] {
  return limbs.map((l) => "0x" + l.toString(16));
}

/**
 * Compute kid_hash = pedersen_hash(kid_bytes).
 * This is computed off-chain and passed to the contract.
 *
 * NOTE: In production, use the actual Pedersen hash from @aztec/bb.js.
 * This placeholder demonstrates the interface.
 */
export async function computeKidHash(kid: string): Promise<bigint> {
  // In production, use Barretenberg's Pedersen hash:
  // import { BarretenbergSync } from '@aztec/bb.js';
  // const bb = await BarretenbergSync.new();
  // const kidBytes = Buffer.from(kid, 'utf-8');
  // const hash = bb.pedersenHash(kidBytes);
  // return BigInt('0x' + Buffer.from(hash).toString('hex'));

  // Simplified: hash the kid string bytes using a field-compatible approach
  // Pack kid bytes into field elements and hash
  const encoder = new TextEncoder();
  const kidBytes = encoder.encode(kid);
  let hash = 0n;
  for (const byte of kidBytes) {
    hash = (hash * 256n + BigInt(byte)) % (1n << 254n); // Stay within field
  }
  return hash;
}

/**
 * Fetch JWKS keys from a provider endpoint.
 */
export async function fetchJwks(
  url: string
): Promise<{ keys: JwkKey[] }> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS from ${url}: ${response.statusText}`);
  }
  return response.json() as Promise<{ keys: JwkKey[] }>;
}

export interface JwkKey {
  kty: string;
  kid: string;
  use: string;
  alg: string;
  n: string; // Base64URL-encoded modulus
  e: string; // Base64URL-encoded exponent
}

/**
 * Process a single JWK key into the format needed by the registry contract.
 */
export async function processJwkKey(key: JwkKey): Promise<{
  kid: string;
  kidHash: bigint;
  modulusLimbs: bigint[];
  redcParamsLimbs: bigint[];
}> {
  if (key.kty !== "RSA" || key.alg !== "RS256") {
    throw new Error(`Unsupported key type: kty=${key.kty}, alg=${key.alg}`);
  }

  const { modulusLimbs, redcParamsLimbs } = jwkModulusToLimbs(key.n);
  const kidHash = await computeKidHash(key.kid);

  return {
    kid: key.kid,
    kidHash,
    modulusLimbs,
    redcParamsLimbs,
  };
}
