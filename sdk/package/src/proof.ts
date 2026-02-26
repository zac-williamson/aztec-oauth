/**
 * JWT proof input generation.
 *
 * Wraps the noir-jwt SDK to produce the circuit inputs needed for bind_account.
 */

import { generateInputs } from "noir-jwt";

/** Maximum JWT data length matching the Noir contract's MAX_JWT_DATA_LENGTH. */
const MAX_JWT_DATA_LENGTH = 1024;

/** Provider ID constants matching the Noir contract. */
const PROVIDER_IDS: Record<string, number> = {
  "https://accounts.google.com": 1,
  "https://appleid.apple.com": 2,
};

/**
 * Fetch the JWKS for a provider and find the key matching the given kid.
 */
async function fetchJwk(
  issuer: string,
  kid: string
): Promise<JsonWebKey> {
  const jwksUrls: Record<string, string> = {
    "https://accounts.google.com": "https://www.googleapis.com/oauth2/v3/certs",
    "https://appleid.apple.com": "https://appleid.apple.com/auth/keys",
  };

  const url = jwksUrls[issuer];
  if (!url) throw new Error(`Unknown issuer: ${issuer}`);

  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to fetch JWKS: ${response.status}`);

  const jwks = (await response.json()) as { keys: Array<JsonWebKey & { kid: string }> };
  const key = jwks.keys.find((k) => k.kid === kid);

  if (!key) throw new Error(`Key ${kid} not found in JWKS for ${issuer}`);

  return key;
}

/**
 * Generate all the inputs needed for the bind_account contract call.
 *
 * Takes a raw JWT string (id_token from Google/Apple) and produces:
 * - JWT byte array and decode offset
 * - RSA public key limbs (modulus + Barrett reduction params)
 * - Signature limbs
 * - Provider ID and kid hash
 */
export async function generateBindInputs(params: {
  jwt: string;
  pedersenHash: (inputs: any[]) => Promise<any>;
  Fr: any;
  computeKidHash: (
    pedersenHash: (inputs: any[]) => Promise<any>,
    Fr: any,
    kid: string
  ) => Promise<any>;
}): Promise<{
  jwtBytes: number[];
  base64DecodeOffset: number;
  pubkeyModulusLimbs: bigint[];
  redcParamsLimbs: bigint[];
  signatureLimbs: bigint[];
  providerId: number;
  kidHash: any;
}> {
  // Decode JWT header to get kid and issuer
  const parts = params.jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");

  const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
  const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));

  const kid: string = header.kid;
  const issuer: string = payload.iss;

  if (!kid) throw new Error("JWT header missing kid");
  if (!issuer) throw new Error("JWT payload missing iss");

  const providerId = PROVIDER_IDS[issuer];
  if (!providerId) throw new Error(`Unsupported issuer: ${issuer}`);

  // Fetch the public key from the provider's JWKS endpoint
  const jwk = await fetchJwk(issuer, kid);

  // Generate circuit inputs via noir-jwt
  const inputs = await generateInputs({
    jwt: params.jwt,
    pubkey: jwk,
    maxSignedDataLength: MAX_JWT_DATA_LENGTH,
  });

  // Extract the JWT bytes (trimmed to actual length)
  const jwtBytes = inputs.data!.storage.slice(0, inputs.data!.len);

  // Compute kid hash matching the contract's hash_bytes_to_field
  const kidHash = await params.computeKidHash(
    params.pedersenHash,
    params.Fr,
    kid
  );

  return {
    jwtBytes,
    base64DecodeOffset: inputs.base64_decode_offset,
    pubkeyModulusLimbs: inputs.pubkey_modulus_limbs.map((s: string) => BigInt(s)),
    redcParamsLimbs: inputs.redc_params_limbs.map((s: string) => BigInt(s)),
    signatureLimbs: inputs.signature_limbs.map((s: string) => BigInt(s)),
    providerId,
    kidHash,
  };
}
