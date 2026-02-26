/**
 * One-shot setup: deploy contracts + sync live Google JWKS keys.
 *
 * Runs everything in a single process so the same admin account deploys
 * the registry AND submits keys (avoids multi-process admin mismatch).
 *
 * Usage: npx tsx setup-and-sync.ts
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_PROVIDER_ID = 1;
const APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys";
const APPLE_PROVIDER_ID = 2;
const LIMB_BITS = 120n;
const NUM_LIMBS = 18;

// ─── RSA key transform (inlined from registry/server/src/jwks-fetcher.ts) ───

function base64UrlDecode(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64url"));
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

function splitBigIntToLimbs(value: bigint): bigint[] {
  const mask = (1n << LIMB_BITS) - 1n;
  const limbs: bigint[] = [];
  let remaining = value;
  for (let i = 0; i < NUM_LIMBS; i++) {
    limbs.push(remaining & mask);
    remaining >>= LIMB_BITS;
  }
  return limbs;
}

function computeRedcParams(modulus: bigint): bigint {
  return (1n << (2n * 2048n + 6n)) / modulus;
}

async function main() {
  const { Fr, GrumpkinScalar } = await import("@aztec/aztec.js/fields");
  const { AztecAddress } = await import("@aztec/aztec.js/addresses");
  const { Contract, getContractInstanceFromInstantiationParams } = await import(
    "@aztec/aztec.js/contracts"
  );
  const { loadContractArtifact } = await import("@aztec/aztec.js/abi");
  const { createAztecNodeClient, waitForNode } = await import(
    "@aztec/aztec.js/node"
  );
  const { EmbeddedWallet } = await import("@aztec/wallets/embedded");
  const { SponsoredFeePaymentMethod } = await import("@aztec/aztec.js/fee");
  const { SponsoredFPCContract } = await import(
    "@aztec/noir-contracts.js/SponsoredFPC"
  );
  const { pedersenHash } = await import("@aztec/foundation/crypto/pedersen");

  // ─── Connect ───────────────────────────────────────────────────────────────

  console.log("Connecting to Aztec sandbox...");
  const node = createAztecNodeClient("http://localhost:8080");
  await waitForNode(node);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });

  const sponsoredFPCInstance =
    await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
  await wallet.registerContract(sponsoredFPCInstance, SponsoredFPCContract.artifact);
  const paymentMethod = new SponsoredFeePaymentMethod(sponsoredFPCInstance.address);

  const adminAcctMgr = await wallet.createSchnorrAccount(
    Fr.random(),
    Fr.random(),
    GrumpkinScalar.random()
  );
  const adminAddress = adminAcctMgr.address;
  console.log("Admin address:", adminAddress.toString());

  const adminDeployMethod = await adminAcctMgr.getDeployMethod();
  await adminDeployMethod.send({
    from: AztecAddress.ZERO,
    fee: { paymentMethod },
  });
  await wallet.registerSender(adminAddress, "admin");
  console.log("Admin account deployed.");

  // ─── Deploy contracts ──────────────────────────────────────────────────────

  const registryArtifactPath = path.resolve(
    __dirname,
    "../../registry/contracts/jwks_registry/target/jwks_registry-JwksRegistry.json"
  );
  const registryRaw = JSON.parse(fs.readFileSync(registryArtifactPath, "utf-8"));
  const registryArtifact = loadContractArtifact(registryRaw);

  console.log("Deploying JwksRegistry...");
  const registryContract = await Contract.deploy(wallet, registryArtifact, [
    adminAddress,
    new Fr(0n),
    new Fr(0n),
    new Fr(0n),
  ]).send({ from: adminAddress, fee: { paymentMethod } });
  console.log("JwksRegistry:", registryContract.address.toString());

  const zkLoginArtifactPath = path.resolve(
    __dirname,
    "../../login/contracts/zk_login/target/zk_login-ZkLogin.json"
  );
  const zkLoginRaw = JSON.parse(fs.readFileSync(zkLoginArtifactPath, "utf-8"));
  const zkLoginArtifact = loadContractArtifact(zkLoginRaw);

  console.log("Deploying ZkLogin...");
  const zkLoginContract = await Contract.deploy(wallet, zkLoginArtifact, [
    registryContract.address,
  ]).send({ from: adminAddress, fee: { paymentMethod } });
  console.log("ZkLogin:", zkLoginContract.address.toString());

  // ─── Kid hash helper ───────────────────────────────────────────────────────

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

  // ─── Fetch & sync JWKS keys ───────────────────────────────────────────────

  async function syncProvider(name: string, providerId: number, jwksUrl: string) {
    console.log(`\nFetching JWKS for ${name}...`);
    const response = await fetch(jwksUrl);
    const jwks = (await response.json()) as {
      keys: Array<{ kid: string; kty: string; alg: string; n: string; e: string }>;
    };
    const rsaKeys = jwks.keys.filter((k) => k.kty === "RSA" && k.alg === "RS256");
    console.log(`  Found ${rsaKeys.length} RSA/RS256 key(s)`);

    for (const key of rsaKeys) {
      const kidHash = await computeKidHash(key.kid);
      const modulusBytes = base64UrlDecode(key.n);
      const modulusBigInt = bytesToBigInt(modulusBytes);
      const modulusLimbs = splitBigIntToLimbs(modulusBigInt);
      const redcParams = computeRedcParams(modulusBigInt);
      const redcParamsLimbs = splitBigIntToLimbs(redcParams);

      console.log(`  Submitting kid="${key.kid}"...`);
      await registryContract.methods
        .admin_set_jwk(
          new Fr(providerId),
          kidHash,
          modulusLimbs.map((l: bigint) => new Fr(l)),
          redcParamsLimbs.map((l: bigint) => new Fr(l))
        )
        .send({ from: adminAddress, fee: { paymentMethod } });
      console.log(`  Submitted kid="${key.kid}"`);
    }
  }

  await syncProvider("Google", GOOGLE_PROVIDER_ID, GOOGLE_JWKS_URL);
  await syncProvider("Apple", APPLE_PROVIDER_ID, APPLE_JWKS_URL);

  // ─── Print summary ────────────────────────────────────────────────────────

  console.log("\n" + "=".repeat(60));
  console.log("SETUP COMPLETE — contracts deployed, keys synced");
  console.log("=".repeat(60));
  console.log(`  JwksRegistry:  ${registryContract.address.toString()}`);
  console.log(`  ZkLogin:       ${zkLoginContract.address.toString()}`);
  console.log("\n--- login/webapp/.env ---");
  console.log(`VITE_NETWORK=local`);
  console.log(`VITE_REGISTRY_ADDRESS=${registryContract.address.toString()}`);
  console.log(`VITE_ZK_LOGIN_ADDRESS=${zkLoginContract.address.toString()}`);
  console.log(`VITE_GOOGLE_CLIENT_ID=<your-google-client-id>`);
  console.log("=".repeat(60));
}

main().catch((err) => {
  console.error("Setup failed:", err);
  process.exit(1);
});
