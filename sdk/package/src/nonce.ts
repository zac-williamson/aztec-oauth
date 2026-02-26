/**
 * Nonce computation matching the Noir contract's expectations.
 *
 * nonce = hex(pedersen_hash([address, randomness]))
 *
 * The nonce is embedded in the OAuth request so Google includes it
 * in the signed JWT. The contract verifies it matches the caller's address.
 */

/**
 * Compute the nonce for an OAuth request.
 *
 * @param pedersenHash - The Pedersen hash function from @aztec/foundation
 * @param Fr - The Fr class from @aztec/aztec.js/fields
 * @param address - The user's Aztec address (as a Field-like value)
 * @param randomness - A random Fr value (will be needed again when completing bind)
 * @returns The nonce as a hex string "0x..."
 */
export async function computeNonce(
  pedersenHash: (inputs: any[]) => Promise<any>,
  Fr: any,
  address: any,
  randomness: any
): Promise<string> {
  const addressField =
    typeof address.toField === "function" ? address.toField() : address;

  const hash = await pedersenHash([addressField, randomness]);
  const bigint: bigint =
    typeof hash.toBigInt === "function" ? hash.toBigInt() : BigInt(hash);

  return "0x" + bigint.toString(16).padStart(64, "0");
}

/**
 * Compute the kid_hash matching the Noir contract's hash_bytes_to_field.
 *
 * Packs the kid string bytes into 9 Field elements (31 bytes per field,
 * big-endian within each), appends the length, then Pedersen hashes.
 */
export async function computeKidHash(
  pedersenHash: (inputs: any[]) => Promise<any>,
  Fr: any,
  kid: string
): Promise<any> {
  const kidBytes = new TextEncoder().encode(kid);
  const fields: bigint[] = new Array(9).fill(0n);

  for (let i = 0; i < kidBytes.length && i < 255; i++) {
    const fieldIdx = Math.floor(i / 31);
    fields[fieldIdx] = fields[fieldIdx] * 256n + BigInt(kidBytes[i]);
  }
  fields[8] = BigInt(kidBytes.length);

  return pedersenHash(fields.map((f) => new Fr(f)));
}
