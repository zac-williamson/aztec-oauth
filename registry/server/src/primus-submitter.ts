/**
 * Primus attestation submitter.
 *
 * Takes a Primus zkTLS attestation and submits it to the JwksRegistry
 * contract via the permissionless `update_jwk` function.
 */

import type { PrimusAttestation } from "./primus-attester.js";

/**
 * Submit a Primus attestation to the registry contract via update_jwk.
 *
 * This uses the permissionless path: the attestation data is passed as
 * private witnesses, verified in-circuit, and the resulting hash commitment
 * is stored on-chain.
 *
 * @param contract - The JwksRegistry contract instance
 * @param senderAddress - Address to send the transaction from
 * @param paymentMethod - Fee payment method
 * @param attestation - The Primus attestation result
 * @param providerId - Numeric provider ID (1=Google, 2=Apple)
 * @param kidHash - Pedersen hash of the key ID
 */
export async function submitAttestation(
  contract: any,
  senderAddress: any,
  paymentMethod: any,
  attestation: PrimusAttestation,
  providerId: number,
  kidHash: any
): Promise<void> {
  // Parse attestor public key from hex strings to byte arrays
  const attestorPubKeyX = hexToBytes32(attestation.attestorPubKey.x);
  const attestorPubKeyY = hexToBytes32(attestation.attestorPubKey.y);

  // Parse attestation hash and signature
  const attestationHash = hexToBytes32(attestation.attestationHash);
  const signature = hexToBytes64(attestation.signature);

  // Parse data hashes
  const dataHashes = attestation.dataHashes.map((h) => hexToBytes32(h));

  console.log(
    `Submitting Primus attestation: provider=${providerId}, kid="${attestation.data?.kid ?? "unknown"}"`
  );

  // NOTE: The actual call requires request_urls, allowed_urls, and
  // plain_json_response parameters matching the att_verifier_lib format.
  // These must be constructed from the attestation data once the exact
  // Primus SDK output format is confirmed via primus-test.ts.
  //
  // For now, this is a placeholder showing the intended contract call pattern:
  await contract.methods
    .update_jwk(
      attestorPubKeyX,
      attestorPubKeyY,
      attestationHash,
      signature,
      [], // request_urls - to be populated from attestation
      [], // allowed_urls - to be populated from on-chain config
      dataHashes,
      [], // plain_json_response - to be populated from attestation
      providerId,
      kidHash
    )
    .send({ from: senderAddress, fee: { paymentMethod } });

  console.log(
    `Attestation submitted: provider=${providerId}`
  );
}

/** Convert a hex string (with or without 0x prefix) to a 32-byte number array. */
function hexToBytes32(hex: string): number[] {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const padded = clean.padStart(64, "0");
  const bytes: number[] = [];
  for (let i = 0; i < 64; i += 2) {
    bytes.push(parseInt(padded.slice(i, i + 2), 16));
  }
  return bytes;
}

/** Convert a hex string to a 64-byte number array. */
function hexToBytes64(hex: string): number[] {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const padded = clean.padStart(128, "0");
  const bytes: number[] = [];
  for (let i = 0; i < 128; i += 2) {
    bytes.push(parseInt(padded.slice(i, i + 2), 16));
  }
  return bytes;
}
