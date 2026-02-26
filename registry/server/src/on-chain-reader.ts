/**
 * On-chain JWK reader.
 *
 * Queries the JwksRegistry contract for stored key data.
 */

import { Fr } from "@aztec/aztec.js/fields";

export interface StoredJwk {
  is_valid: boolean;
  modulus_limbs: any[]; // Array of 18 Fr-like values
  redc_params_limbs: any[]; // Array of 18 Fr-like values
}

/**
 * Read a JWK from the on-chain registry by provider ID and kid hash.
 *
 * @param contract - The JwksRegistry contract instance
 * @param providerId - Numeric provider ID (1=Google, 2=Apple)
 * @param kidHash - Pedersen hash of the key ID (Fr element)
 * @param fromAddress - Address to simulate the call from
 * @returns The stored JWK data, or null if not found / error
 */
export async function readOnChainKey(
  contract: any,
  providerId: number,
  kidHash: any,
  fromAddress: any
): Promise<StoredJwk | null> {
  try {
    const result = await contract.methods
      .get_jwk(new Fr(providerId), kidHash)
      .simulate({ from: fromAddress });
    return result as StoredJwk;
  } catch (_err) {
    // Key not found or contract error
    return null;
  }
}
