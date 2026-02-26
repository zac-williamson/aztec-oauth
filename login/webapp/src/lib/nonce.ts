/**
 * Nonce Generation
 *
 * Generates a nonce that binds a JWT to a specific Aztec address.
 * nonce = hex(pedersen_hash([aztec_address, randomness]))
 *
 * This prevents front-running: if someone intercepts the JWT,
 * they cannot use it because the nonce commits to the original caller's address.
 */

import { Fr } from "@aztec/aztec.js/fields";
import { pedersenHash } from "@aztec/foundation/crypto/pedersen";

/**
 * Generate a random field element for nonce commitment.
 */
export function generateRandomness(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  // Reduce to field size (BN254 scalar field: ~2^254)
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  const FIELD_MODULUS =
    21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  return value % FIELD_MODULUS;
}

/**
 * Compute the nonce for the OAuth request.
 *
 * nonce = hex(pedersen_hash([address_as_field, randomness]))
 *
 * @param aztecAddress - The user's Aztec address as a hex string
 * @param randomness - Random field element (store locally for later proof)
 * @returns Hex-encoded nonce string to include in the OAuth request
 */
export async function computeNonce(
  aztecAddress: string,
  randomness: bigint
): Promise<string> {
  const hash = await pedersenHash([Fr.fromString(aztecAddress), new Fr(randomness)]);
  return "0x" + hash.toBigInt().toString(16).padStart(64, "0");
}

/**
 * Store nonce randomness in localStorage for later use in the proof.
 */
export function storeNonceRandomness(
  nonce: string,
  randomness: bigint
): void {
  const key = `aztec-sybil-nonce-${nonce}`;
  localStorage.setItem(key, randomness.toString());
}

/**
 * Retrieve stored nonce randomness.
 */
export function getNonceRandomness(nonce: string): bigint | null {
  const key = `aztec-sybil-nonce-${nonce}`;
  const stored = localStorage.getItem(key);
  if (!stored) return null;
  return BigInt(stored);
}

/**
 * Clean up stored nonce randomness after successful binding.
 */
export function clearNonceRandomness(nonce: string): void {
  const key = `aztec-sybil-nonce-${nonce}`;
  localStorage.removeItem(key);
}
