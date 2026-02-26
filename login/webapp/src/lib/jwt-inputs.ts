/**
 * JWT Circuit Input Generation
 *
 * Wraps the noir-jwt SDK's generateInputs() to prepare circuit inputs
 * for the ZkLogin contract's bind_account() function.
 */

// In production, import from the noir-jwt npm package:
// import { generateInputs } from 'noir-jwt';

/**
 * Circuit inputs for the bind_account() function.
 */
export interface BindAccountInputs {
  jwtData: number[]; // BoundedVec<u8, 1024>
  jwtDataLength: number;
  base64DecodeOffset: number;
  pubkeyModulusLimbs: string[]; // [u128; 18] as hex strings
  redcParamsLimbs: string[]; // [u128; 18] as hex strings
  signatureLimbs: string[]; // [u128; 18] as hex strings
  providerId: number;
  kidHash: string; // Field as hex
  nonceRandomness: string; // Field as hex
}

/**
 * Generate circuit inputs for bind_account from a JWT and signing key.
 *
 * @param jwt - The raw JWT string (header.payload.signature)
 * @param signingKey - The JWK public key used to sign the JWT
 * @param providerId - 1 for Google, 2 for Apple
 * @param kidHash - Pedersen hash of the key ID
 * @param nonceRandomness - The randomness used to generate the nonce
 * @param maxDataLength - Maximum JWT data length (default 1024)
 */
export async function generateBindAccountInputs(
  jwt: string,
  signingKey: JsonWebKey,
  providerId: number,
  kidHash: string,
  nonceRandomness: bigint,
  maxDataLength: number = 1024
): Promise<BindAccountInputs> {
  // Use noir-jwt SDK to generate the base inputs
  // const inputs = generateInputs({
  //   jwt,
  //   pubkey: signingKey,
  //   maxSignedDataLength: maxDataLength,
  // });

  // For now, prepare inputs manually
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  // The signed data is header.payload (base64url encoded)
  const signedData = parts[0] + "." + parts[1];
  const signedDataBytes = new TextEncoder().encode(signedData);

  if (signedDataBytes.length > maxDataLength) {
    throw new Error(
      `JWT signed data (${signedDataBytes.length} bytes) exceeds max length (${maxDataLength})`
    );
  }

  // Pad to maxDataLength
  const paddedData = new Uint8Array(maxDataLength);
  paddedData.set(signedDataBytes);

  // Find the payload start (after first '.')
  const dotIndex = signedData.indexOf(".");
  // base64_decode_offset must be a multiple of 4, at or before the payload start
  const base64DecodeOffset = Math.floor((dotIndex + 1) / 4) * 4;

  return {
    jwtData: Array.from(paddedData),
    jwtDataLength: signedDataBytes.length,
    base64DecodeOffset,
    // These would come from noir-jwt's generateInputs() in production:
    pubkeyModulusLimbs: Array(18).fill("0x0"), // placeholder
    redcParamsLimbs: Array(18).fill("0x0"), // placeholder
    signatureLimbs: Array(18).fill("0x0"), // placeholder
    providerId,
    kidHash,
    nonceRandomness: "0x" + nonceRandomness.toString(16),
  };
}
