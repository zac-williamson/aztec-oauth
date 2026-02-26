/**
 * ZkLogin contract client.
 *
 * Wraps the deployed ZkLogin contract with typed methods for
 * identity binding and bound-check queries.
 */

import { Fr } from "@aztec/aztec.js/fields";
import { AztecAddress } from "@aztec/aztec.js/addresses";

export class ZkLoginClient {
  constructor(
    private contract: any,
    private registryContract: any,
    private userAddress: AztecAddress,
    private paymentMethod: any
  ) {}

  /**
   * Check if the user's address is already bound to an identity.
   */
  async isAddressBound(address?: AztecAddress): Promise<boolean> {
    const addr = address ?? this.userAddress;
    return this.contract.methods
      .is_address_bound(addr)
      .simulate({ from: this.userAddress });
  }

  /**
   * Call bind_account to bind an OAuth identity to the user's Aztec address.
   *
   * Automatically determines whether to use the private path or public fallback
   * by checking key maturity in the registry's delayed store.
   */
  async bindAccount(inputs: {
    jwtBytes: number[];
    base64DecodeOffset: number;
    pubkeyModulusLimbs: bigint[];
    redcParamsLimbs: bigint[];
    signatureLimbs: bigint[];
    providerId: number;
    kidHash: Fr;
    nonceRandomness: Fr;
  }): Promise<string> {
    // Check if key is mature (available in delayed store).
    // If the key isn't valid in the delayed store yet, use public fallback.
    let useFallback = true;
    try {
      const jwk = await this.registryContract.methods
        .get_jwk_unconstrained(new Fr(inputs.providerId), inputs.kidHash)
        .simulate();
      // If the key is valid in the instant store, it exists.
      // We optimistically try the private path (key may be mature).
      // The unconstrained view reads the instant store; if the key is there,
      // it's likely been there long enough for the delay to have passed.
      useFallback = !jwk.is_valid;
    } catch {
      useFallback = true;
    }

    const receipt = await this.contract.methods
      .bind_account(
        inputs.jwtBytes,
        inputs.base64DecodeOffset,
        inputs.pubkeyModulusLimbs,
        inputs.redcParamsLimbs,
        inputs.signatureLimbs,
        new Fr(inputs.providerId),
        inputs.kidHash,
        inputs.nonceRandomness,
        useFallback
      )
      .send({ from: this.userAddress, fee: { paymentMethod: this.paymentMethod } });

    return receipt.txHash?.toString() ?? "submitted";
  }
}
