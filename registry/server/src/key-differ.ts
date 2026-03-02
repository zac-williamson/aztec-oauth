/**
 * Key differ - compares fetched JWKS keys against on-chain state.
 *
 * Determines which keys need to be added, updated, or are unchanged.
 */

import type { ProcessedKey } from "./jwks-fetcher.js";
import type { StoredJwk } from "./on-chain-reader.js";
import { readOnChainKey } from "./on-chain-reader.js";

export interface DiffResult {
  /** Keys not yet on-chain or marked invalid */
  toAdd: ProcessedKey[];
  /** Keys on-chain but with different modulus hash */
  toUpdate: ProcessedKey[];
  /** Keys already on-chain and matching */
  unchanged: ProcessedKey[];
}

/**
 * Extract a bigint from a hash field value, which may be a Fr, a bigint, or a number.
 */
function fieldToBigInt(field: any): bigint {
  if (typeof field === "bigint") return field;
  if (typeof field === "number") return BigInt(field);
  if (field && typeof field.toBigInt === "function") return field.toBigInt();
  return BigInt(field);
}

/**
 * Check whether both hash fields are zero (empty slot).
 */
function allHashZero(hashFields: any[]): boolean {
  return hashFields.every((f) => fieldToBigInt(f) === 0n);
}

/**
 * Check whether the fetched hash matches the on-chain hash.
 */
function hashesMatch(
  fetchedHash: [bigint, bigint],
  onChainHash: any[]
): boolean {
  if (onChainHash.length < 2) return false;
  return (
    fetchedHash[0] === fieldToBigInt(onChainHash[0]) &&
    fetchedHash[1] === fieldToBigInt(onChainHash[1])
  );
}

/**
 * Compare fetched keys against on-chain state and classify each key.
 *
 * @param fetchedKeys - Keys fetched from JWKS endpoints
 * @param contract - JwksRegistry contract instance
 * @param fromAddress - Address to simulate reads from
 * @returns Classification of keys into toAdd, toUpdate, unchanged
 */
export async function diffKeys(
  fetchedKeys: ProcessedKey[],
  contract: any,
  fromAddress: any
): Promise<DiffResult> {
  const toAdd: ProcessedKey[] = [];
  const toUpdate: ProcessedKey[] = [];
  const unchanged: ProcessedKey[] = [];

  for (const key of fetchedKeys) {
    const onChain = await readOnChainKey(
      contract,
      key.providerId,
      key.kidHash,
      fromAddress
    );

    if (
      !onChain ||
      !onChain.is_valid ||
      allHashZero(onChain.modulus_hash)
    ) {
      toAdd.push(key);
    } else if (!hashesMatch(key.modulusHash, onChain.modulus_hash)) {
      toUpdate.push(key);
    } else {
      unchanged.push(key);
    }
  }

  return { toAdd, toUpdate, unchanged };
}
