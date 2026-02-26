/**
 * Pedersen kid hash computation.
 *
 * Replicates the exact hash_bytes_to_field logic used by the Noir contract:
 * 1. Pack kid bytes into 9 Field elements (31 bytes per field, big-endian)
 * 2. Set field[8] = length of kid string
 * 3. Pedersen hash all 9 fields
 */

import { Fr } from "@aztec/aztec.js/fields";
import { pedersenHash } from "@aztec/foundation/crypto/pedersen";

/**
 * Compute the Pedersen hash of a key ID string.
 *
 * This matches the on-chain computation in the JwksRegistry and ZkLogin contracts.
 * The kid string is packed into 9 field elements (31 bytes each, big-endian within
 * each field), with the 9th field set to the byte length. The result is Pedersen-hashed.
 *
 * @param kid - The JWK Key ID string (e.g., "abc123def")
 * @returns The Pedersen hash as an Fr element
 */
export async function computeKidHash(kid: string): Promise<typeof Fr.prototype> {
  const kidBytes = new TextEncoder().encode(kid);
  const fields: bigint[] = new Array(9).fill(0n);

  for (let i = 0; i < kidBytes.length; i++) {
    const fieldIdx = Math.floor(i / 31);
    fields[fieldIdx] = fields[fieldIdx] * 256n + BigInt(kidBytes[i]);
  }
  fields[8] = BigInt(kidBytes.length);

  const fieldInputs = fields.map((f) => new Fr(f));
  return await pedersenHash(fieldInputs);
}
