/**
 * Check on-chain JWKS keys for verification.
 *
 * Reads stored keys from the JwksRegistry contract and prints their details.
 * Useful for verifying that the JWKS monitor has synced keys correctly.
 *
 * Usage: npx tsx check-keys.ts <registry-address>
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Google JWKS endpoint
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_PROVIDER_ID = 1;

async function main() {
  const registryAddress = process.argv[2];
  if (!registryAddress) {
    console.error("Usage: npx tsx check-keys.ts <registry-address>");
    process.exit(1);
  }

  // Import SDK modules
  const { Fr } = await import("@aztec/aztec.js/fields");
  const { AztecAddress } = await import("@aztec/aztec.js/addresses");
  const { Contract, getContractInstanceFromInstantiationParams } = await import(
    "@aztec/aztec.js/contracts"
  );
  const { loadContractArtifact } = await import("@aztec/aztec.js/abi");
  const { createAztecNodeClient, waitForNode } = await import(
    "@aztec/aztec.js/node"
  );
  const { EmbeddedWallet } = await import("@aztec/wallets/embedded");
  const { SponsoredFPCContract } = await import(
    "@aztec/noir-contracts.js/SponsoredFPC"
  );
  const { pedersenHash } = await import(
    "@aztec/foundation/crypto/pedersen"
  );

  // Connect to sandbox
  console.log("Connecting to Aztec sandbox...");
  const node = createAztecNodeClient("http://localhost:8080");
  await waitForNode(node);

  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });

  // Register sponsored FPC (needed for simulate calls)
  const sponsoredFPCInstance =
    await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
  await wallet.registerContract(
    sponsoredFPCInstance,
    SponsoredFPCContract.artifact
  );

  // Load registry contract
  const registryArtifactPath = path.resolve(
    __dirname,
    "../../registry/contracts/jwks_registry/target/jwks_registry-JwksRegistry.json"
  );
  const registryRaw = JSON.parse(fs.readFileSync(registryArtifactPath, "utf-8"));
  const registryArtifact = loadContractArtifact(registryRaw);

  const addr = AztecAddress.fromString(registryAddress);
  const registryContract = await Contract.at(addr, registryArtifact, wallet);
  console.log("Connected to JwksRegistry at:", addr.toString());

  // Fetch live Google JWKS to know which kids to check
  console.log("\nFetching live Google JWKS...");
  const response = await fetch(GOOGLE_JWKS_URL);
  const jwks = (await response.json()) as { keys: Array<{ kid: string; alg: string; kty: string }> };
  const rsaKeys = jwks.keys.filter((k) => k.kty === "RSA" && k.alg === "RS256");

  console.log(`Found ${rsaKeys.length} RSA/RS256 key(s) from Google:\n`);

  // Compute kid hash (same as registry/server/src/kid-hash.ts)
  async function computeKidHash(kid: string) {
    const kidBytes = new TextEncoder().encode(kid);
    const fields: bigint[] = new Array(9).fill(0n);
    for (let i = 0; i < kidBytes.length; i++) {
      const fieldIdx = Math.floor(i / 31);
      fields[fieldIdx] = fields[fieldIdx] * 256n + BigInt(kidBytes[i]);
    }
    fields[8] = BigInt(kidBytes.length);
    return await pedersenHash(fields.map((f: bigint) => new Fr(f)));
  }

  for (const key of rsaKeys) {
    const kidHash = await computeKidHash(key.kid);
    console.log(`Key ID: "${key.kid}"`);
    console.log(`  Kid Hash: ${kidHash.toString()}`);

    try {
      const storedJwk = await registryContract.methods
        .get_jwk(new Fr(GOOGLE_PROVIDER_ID), kidHash)
        .simulate({ from: addr });

      if (storedJwk.is_valid) {
        // Show first and last limb for quick verification
        const firstLimb =
          typeof storedJwk.modulus_limbs[0] === "bigint"
            ? storedJwk.modulus_limbs[0]
            : storedJwk.modulus_limbs[0].toBigInt();
        const lastNonZeroIdx = storedJwk.modulus_limbs.findIndex(
          (l: any) => {
            const v = typeof l === "bigint" ? l : l.toBigInt();
            return v === 0n;
          }
        );
        console.log(`  On-chain: VALID`);
        console.log(`  Modulus limb[0]: ${firstLimb.toString(16)}`);
        console.log(`  Non-zero limbs: ${lastNonZeroIdx === -1 ? 18 : lastNonZeroIdx}`);
      } else {
        console.log(`  On-chain: NOT FOUND (key not yet synced)`);
      }
    } catch (err) {
      console.log(`  On-chain: ERROR reading - ${err instanceof Error ? err.message : err}`);
    }
    console.log();
  }
}

main().catch((err) => {
  console.error("Check failed:", err);
  process.exit(1);
});
