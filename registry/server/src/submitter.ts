/**
 * Key submitter - writes JWK keys to the on-chain JwksRegistry.
 */

import { Fr } from "@aztec/aztec.js/fields";
import type { ProcessedKey } from "./jwks-fetcher.js";

/**
 * Submit a single JWK key to the registry contract via admin_set_jwk.
 *
 * @param contract - The JwksRegistry contract instance
 * @param adminAddress - The admin account address (transaction sender)
 * @param paymentMethod - The sponsored fee payment method
 * @param key - The processed key to submit
 */
export async function submitKey(
  contract: any,
  adminAddress: any,
  paymentMethod: any,
  key: ProcessedKey
): Promise<void> {
  console.log(
    `Submitting key: provider=${key.providerId}, kid="${key.kid}"`
  );

  await contract.methods
    .admin_set_jwk(
      new Fr(key.providerId),
      key.kidHash,
      key.modulusLimbs.map((l: bigint) => new Fr(l)),
      key.redcParamsLimbs.map((l: bigint) => new Fr(l))
    )
    .send({ from: adminAddress, fee: { paymentMethod } });

  console.log(
    `Key submitted: provider=${key.providerId}, kid="${key.kid}"`
  );
}
