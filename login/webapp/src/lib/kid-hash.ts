/**
 * Pedersen-based kid hash computation.
 *
 * Matches the Noir contract's hash_bytes_to_field: packs bytes into 9 Fields
 * at 31 bytes each (big-endian within each), appends byte length, then
 * pedersen hashes.
 */

import { Fr } from "@aztec/aztec.js/fields";
import { pedersenHash } from "@aztec/foundation/crypto/pedersen";

export async function computeKidHash(kid: string): Promise<Fr> {
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
