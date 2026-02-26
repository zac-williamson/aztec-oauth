/**
 * JWT Circuit Input Generation
 *
 * Uses the noir-jwt SDK's generateInputs() to prepare circuit inputs
 * for the ZkLogin contract's bind_account() function.
 */

import { generateInputs } from "noir-jwt";
import { Fr } from "@aztec/aztec.js/fields";
import { computeKidHash } from "./kid-hash";

/**
 * Circuit inputs for the bind_account() function.
 */
export interface BindAccountInputs {
  jwtBytes: number[];
  base64DecodeOffset: number;
  pubkeyModulusLimbs: bigint[];
  redcParamsLimbs: bigint[];
  signatureLimbs: bigint[];
  providerId: number;
  kidHash: Fr;
  nonceRandomness: Fr;
}

/**
 * Generate circuit inputs for bind_account from a JWT and signing key.
 *
 * @param jwt - The raw JWT string (header.payload.signature)
 * @param signingKey - The JWK public key used to sign the JWT
 * @param providerId - 1 for Google, 2 for Apple
 * @param kid - The key ID from the JWT header
 * @param nonceRandomness - The randomness used to generate the nonce
 * @param maxDataLength - Maximum JWT data length (default 1024)
 */
export async function generateBindAccountInputs(
  jwt: string,
  signingKey: JsonWebKey,
  providerId: number,
  kid: string,
  nonceRandomness: bigint,
  maxDataLength: number = 1024
): Promise<BindAccountInputs> {
  // Generate circuit inputs via noir-jwt SDK
  const inputs = await generateInputs({
    jwt,
    pubkey: signingKey,
    maxSignedDataLength: maxDataLength,
  });

  // Extract JWT bytes as BoundedVec (trim storage to actual length)
  const jwtBytes = inputs.data!.storage.slice(0, inputs.data!.len);

  // Compute real Pedersen kid hash
  const kidHash = await computeKidHash(kid);

  return {
    jwtBytes,
    base64DecodeOffset: inputs.base64_decode_offset,
    pubkeyModulusLimbs: inputs.pubkey_modulus_limbs.map((s: string) => BigInt(s)),
    redcParamsLimbs: inputs.redc_params_limbs.map((s: string) => BigInt(s)),
    signatureLimbs: inputs.signature_limbs.map((s: string) => BigInt(s)),
    providerId,
    kidHash,
    nonceRandomness: new Fr(nonceRandomness),
  };
}
