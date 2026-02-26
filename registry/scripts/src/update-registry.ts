/**
 * Registry Update Script
 *
 * Fetches JWKS from Google and Apple endpoints, converts keys to the contract format,
 * and submits them to the JwksRegistry contract.
 *
 * Usage:
 *   # Admin path (bootstrapping):
 *   ADMIN_KEY=<private_key> REGISTRY_ADDRESS=<address> tsx src/update-registry.ts --admin
 *
 *   # Permissionless path (with Primus attestation):
 *   REGISTRY_ADDRESS=<address> tsx src/update-registry.ts --primus --attestation-file=<path>
 */

import {
  fetchJwks,
  processJwkKey,
  limbsToHexStrings,
  type JwkKey,
} from "./jwk-transform.js";

// JWKS endpoints
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys";

// Provider IDs (must match contract)
const PROVIDER_GOOGLE = 1n;
const PROVIDER_APPLE = 2n;

interface ProcessedKey {
  provider: string;
  providerId: bigint;
  kid: string;
  kidHash: bigint;
  modulusLimbs: bigint[];
  redcParamsLimbs: bigint[];
}

async function fetchAllKeys(): Promise<ProcessedKey[]> {
  const keys: ProcessedKey[] = [];

  console.log("Fetching Google JWKS...");
  const googleJwks = await fetchJwks(GOOGLE_JWKS_URL);
  for (const key of googleJwks.keys) {
    if (key.kty === "RSA" && key.alg === "RS256") {
      const processed = await processJwkKey(key);
      keys.push({
        provider: "Google",
        providerId: PROVIDER_GOOGLE,
        ...processed,
      });
      console.log(`  Google key: kid=${key.kid}`);
    }
  }

  console.log("Fetching Apple JWKS...");
  const appleJwks = await fetchJwks(APPLE_JWKS_URL);
  for (const key of appleJwks.keys) {
    if (key.kty === "RSA" && key.alg === "RS256") {
      const processed = await processJwkKey(key);
      keys.push({
        provider: "Apple",
        providerId: PROVIDER_APPLE,
        ...processed,
      });
      console.log(`  Apple key: kid=${key.kid}`);
    }
  }

  console.log(`\nTotal keys fetched: ${keys.length}`);
  return keys;
}

async function submitAdminKeys(keys: ProcessedKey[]): Promise<void> {
  const registryAddress = process.env.REGISTRY_ADDRESS;
  if (!registryAddress) {
    throw new Error("REGISTRY_ADDRESS environment variable required");
  }

  // In production, this would use @aztec/aztec.js to submit transactions:
  //
  // import { createPXEClient, Contract } from '@aztec/aztec.js';
  // import { getSchnorrAccount } from '@aztec/accounts/schnorr';
  // import JwksRegistryJson from '../contracts/jwks_registry/target/jwks_registry-JwksRegistry.json';
  //
  // const pxe = createPXEClient('http://localhost:8080');
  // const wallet = await getSchnorrAccount(pxe, adminPrivateKey, signingKey).getWallet();
  // const registry = await Contract.at(registryAddress, JwksRegistryJson.abi, wallet);
  //
  // for (const key of keys) {
  //   const tx = registry.methods.admin_set_jwk(
  //     key.providerId,
  //     key.kidHash,
  //     key.modulusLimbs.map(l => Fr.fromBigInt(l)),
  //     key.redcParamsLimbs.map(l => Fr.fromBigInt(l)),
  //   ).send();
  //   const receipt = await tx.wait();
  //   console.log(`Set ${key.provider} key kid=${key.kid}: tx=${receipt.txHash}`);
  // }

  console.log("\n--- Admin Key Submission (dry run) ---");
  for (const key of keys) {
    console.log(`\n${key.provider} key: kid=${key.kid}`);
    console.log(`  provider_id: ${key.providerId}`);
    console.log(`  kid_hash: 0x${key.kidHash.toString(16)}`);
    console.log(
      `  modulus_limbs: [${limbsToHexStrings(key.modulusLimbs).join(", ")}]`
    );
    console.log(
      `  redc_params_limbs: [${limbsToHexStrings(key.redcParamsLimbs).join(", ")}]`
    );
  }
}

async function submitPrimusKeys(
  keys: ProcessedKey[],
  attestationFile: string
): Promise<void> {
  // In production, this would:
  // 1. Parse the Primus attestation file using att_verifier_parsing
  // 2. Submit via the permissionless update_jwk() function
  //
  // import { parseHashingData } from '../../lib/att_verifier_parsing';
  // const attestation = JSON.parse(fs.readFileSync(attestationFile, 'utf-8'));
  // const { publicData, privateData } = parseHashingData(attestation);
  //
  // for (const key of keys) {
  //   const tx = registry.methods.update_jwk(
  //     publicData.attestorPubKeyX,
  //     publicData.attestorPubKeyY,
  //     publicData.attestationHash,
  //     publicData.attestationSignature,
  //     publicData.requestUrls,
  //     publicData.allowedUrls,
  //     publicData.dataHashes,
  //     privateData.plainJsonResponse,
  //     key.providerId,
  //     key.kidHash,
  //     key.modulusLimbs,
  //     key.redcParamsLimbs,
  //   ).send();
  //   await tx.wait();
  // }

  console.log("\n--- Primus Attestation Submission (not yet implemented) ---");
  console.log(`Attestation file: ${attestationFile}`);
  console.log(`Keys to submit: ${keys.length}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const isAdmin = args.includes("--admin");
  const isPrimus = args.includes("--primus");
  const attestationArg = args.find((a) => a.startsWith("--attestation-file="));
  const attestationFile = attestationArg?.split("=")[1];

  const keys = await fetchAllKeys();

  if (isAdmin) {
    await submitAdminKeys(keys);
  } else if (isPrimus && attestationFile) {
    await submitPrimusKeys(keys, attestationFile);
  } else {
    console.log("\nUsage:");
    console.log("  --admin                        Submit via admin_set_jwk()");
    console.log(
      "  --primus --attestation-file=X  Submit via update_jwk() with Primus attestation"
    );
    console.log("\nDry run complete. Keys fetched and processed.");
  }
}

main().catch(console.error);
