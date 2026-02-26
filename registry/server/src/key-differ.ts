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
  /** Keys on-chain but with different modulus/redc limbs */
  toUpdate: ProcessedKey[];
  /** Keys already on-chain and matching */
  unchanged: ProcessedKey[];
}

/**
 * Extract a bigint from a limb value, which may be a Fr, a bigint, or a number.
 */
function limbToBigInt(limb: any): bigint {
  if (typeof limb === "bigint") return limb;
  if (typeof limb === "number") return BigInt(limb);
  if (limb && typeof limb.toBigInt === "function") return limb.toBigInt();
  return BigInt(limb);
}

/**
 * Check whether all 18 modulus limbs are zero.
 */
function allLimbsZero(limbs: any[]): boolean {
  return limbs.every((l) => limbToBigInt(l) === 0n);
}

/**
 * Check whether the fetched limbs match the on-chain limbs.
 */
function limbsMatch(fetchedLimbs: bigint[], onChainLimbs: any[]): boolean {
  if (fetchedLimbs.length !== onChainLimbs.length) return false;
  for (let i = 0; i < fetchedLimbs.length; i++) {
    if (fetchedLimbs[i] !== limbToBigInt(onChainLimbs[i])) return false;
  }
  return true;
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

    if (!onChain || !onChain.is_valid || allLimbsZero(onChain.modulus_limbs)) {
      toAdd.push(key);
    } else if (!limbsMatch(key.modulusLimbs, onChain.modulus_limbs)) {
      toUpdate.push(key);
    } else {
      unchanged.push(key);
    }
  }

  return { toAdd, toUpdate, unchanged };
}
