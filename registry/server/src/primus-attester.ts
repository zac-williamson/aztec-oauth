/**
 * Primus zkTLS attestation wrapper.
 *
 * Handles attestation requests to the Primus network for JWKS endpoints.
 * Each attestation proves that a specific RSA modulus was fetched from
 * a known JWKS URL, producing a verifiable commitment (SHA-256 hash)
 * of the modulus value.
 */

import type { PrimusConfig } from "./config.js";

/**
 * Raw attestation result from the Primus SDK.
 * Exact shape depends on SDK version — this captures the fields
 * needed for on-chain verification.
 */
export interface PrimusAttestation {
  /** Attestor's secp256k1 public key (hex or bytes) */
  attestorPubKey: { x: string; y: string };
  /** SHA-256 hash of the attestation payload */
  attestationHash: string;
  /** ECDSA signature over the attestation hash */
  signature: string;
  /** Request URL(s) used */
  requestUrls: string[];
  /** SHA-256 hashes of the resolved data fields */
  dataHashes: string[];
  /** Plaintext resolved values */
  data: Record<string, string>;
}

/**
 * Perform a Primus zkTLS attestation for a JWKS key.
 *
 * @param config - Primus SDK credentials
 * @param jwksUrl - The JWKS endpoint URL to attest
 * @param keyIndex - Index of the key in the JWKS keys array
 * @returns The attestation result containing proof data
 */
export async function attestJwksKey(
  config: PrimusConfig,
  jwksUrl: string,
  keyIndex: number
): Promise<PrimusAttestation> {
  // Dynamic import to avoid hard dependency when running in admin mode
  // @ts-expect-error — Primus SDK types may not be available
  const { PrimusCoreTLS } = await import("@primuslabs/zktls-core-sdk");

  const zkTLS = new PrimusCoreTLS();
  await zkTLS.init(config.appId, config.appSecret);

  const request = {
    url: jwksUrl,
    method: "GET",
    header: {},
  };

  const responseResolves = [
    { keyName: "kid", parsePath: `$.keys[${keyIndex}].kid` },
    { keyName: "n", parsePath: `$.keys[${keyIndex}].n` },
  ];

  const attestation = await zkTLS.startAttestation(
    zkTLS.generateRequestParams(request, responseResolves)
  );

  return attestation as PrimusAttestation;
}
