/**
 * Nonce Generation
 *
 * Generates a nonce that binds a JWT to a specific Aztec address.
 * nonce = hex(pedersen_hash([aztec_address, randomness]))
 *
 * This prevents front-running: if someone intercepts the JWT,
 * they cannot use it because the nonce commits to the original caller's address.
 */

// In production, use @aztec/bb.js for Pedersen hash
// import { BarretenbergSync, Fr } from '@aztec/bb.js';

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
  // Ensure it's within the field
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
  // In production, use Barretenberg's Pedersen hash:
  //
  // const bb = await BarretenbergSync.new();
  // const addressField = Fr.fromString(aztecAddress);
  // const randomField = Fr.fromBigInt(randomness);
  // const hash = bb.pedersenHash([addressField, randomField]);
  // return '0x' + Buffer.from(hash).toString('hex');

  // Placeholder: simple hash combining address and randomness
  // Replace with actual Pedersen hash in production
  const addressBigInt = BigInt(aztecAddress);
  const combined = addressBigInt ^ randomness;
  return "0x" + combined.toString(16).padStart(64, "0");
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
