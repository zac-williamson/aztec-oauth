/**
 * Deploy both JwksRegistry and ZkLogin contracts to a running Aztec sandbox.
 *
 * Prints contract addresses and .env snippets for the monitor and webapp.
 *
 * Usage: npx tsx deploy.ts [admin-secret-key]
 *   If admin-secret-key is not provided, a random key is generated.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const adminSecretKeyArg = process.argv[2];

  // Import SDK modules via sub-path exports
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

  // Connect to sandbox
  console.log("Connecting to Aztec sandbox at http://localhost:8080...");
  const node = createAztecNodeClient("http://localhost:8080");
  await waitForNode(node);
  console.log("Connected.");

  // Create wallet
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });

  // Setup sponsored fees
  const sponsoredFPCInstance =
    await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
  await wallet.registerContract(
    sponsoredFPCInstance,
    SponsoredFPCContract.artifact
  );
  const paymentMethod = new SponsoredFeePaymentMethod(
    sponsoredFPCInstance.address
  );

  // Create admin account
  const adminSecret = adminSecretKeyArg
    ? new Fr(BigInt(adminSecretKeyArg))
    : Fr.random();
  const adminAcctMgr = await wallet.createSchnorrAccount(
    adminSecret,
    Fr.random(),
    GrumpkinScalar.random()
  );
  const adminAddress = adminAcctMgr.address;
  console.log("Admin address:", adminAddress.toString());

  // Deploy admin account
  const adminDeployMethod = await adminAcctMgr.getDeployMethod();
  await adminDeployMethod.send({
    from: AztecAddress.ZERO,
    fee: { paymentMethod },
  });
  await wallet.registerSender(adminAddress, "admin");
  console.log("Admin account deployed.");

  // Deploy JwksRegistry
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
  console.log("JwksRegistry deployed at:", registryContract.address.toString());

  // Deploy ZkLogin
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
  console.log("ZkLogin deployed at:", zkLoginContract.address.toString());

  // Print summary
  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT COMPLETE");
  console.log("=".repeat(60));
  console.log(`  Admin Address:     ${adminAddress.toString()}`);
  console.log(`  Admin Secret Key:  ${adminSecret.toBigInt().toString()}`);
  console.log(`  JwksRegistry:      ${registryContract.address.toString()}`);
  console.log(`  ZkLogin:           ${zkLoginContract.address.toString()}`);

  console.log("\n--- registry/server/.env ---");
  console.log(`NETWORK=local`);
  console.log(`REGISTRY_ADDRESS=${registryContract.address.toString()}`);
  console.log(`ADMIN_SECRET_KEY=${adminSecret.toBigInt().toString()}`);

  console.log("\n--- login/webapp/.env ---");
  console.log(`VITE_NETWORK=local`);
  console.log(`VITE_REGISTRY_ADDRESS=${registryContract.address.toString()}`);
  console.log(`VITE_ZK_LOGIN_ADDRESS=${zkLoginContract.address.toString()}`);
  console.log(`VITE_GOOGLE_CLIENT_ID=<your-google-client-id>`);
  console.log("=".repeat(60));
}

main().catch((err) => {
  console.error("Deploy failed:", err);
  process.exit(1);
});
