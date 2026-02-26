/**
 * Aztec client setup for the JWKS Monitor.
 *
 * Creates a connected wallet, admin account, fee payment method,
 * and contract handle for the JwksRegistry.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { Fr, GrumpkinScalar } from "@aztec/aztec.js/fields";
import { AztecAddress } from "@aztec/aztec.js/addresses";
import { Contract, getContractInstanceFromInstantiationParams } from "@aztec/aztec.js/contracts";
import { loadContractArtifact } from "@aztec/aztec.js/abi";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { SponsoredFPCContract } from "@aztec/noir-contracts.js/SponsoredFPC";

import type { Config } from "./config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface AztecClient {
  wallet: InstanceType<typeof EmbeddedWallet>;
  adminAddress: InstanceType<typeof AztecAddress>;
  paymentMethod: InstanceType<typeof SponsoredFeePaymentMethod>;
  registryContract: any;
}

/**
 * Initialize the Aztec client stack:
 * 1. Connect to the Aztec node
 * 2. Create an EmbeddedWallet
 * 3. Set up sponsored fee payment
 * 4. Create and deploy the admin Schnorr account
 * 5. Load and connect to the JwksRegistry contract
 */
export async function createAztecClient(config: Config): Promise<AztecClient> {
  // 1. Connect to node
  const node = createAztecNodeClient(config.nodeUrl);
  await waitForNode(node);
  console.log("Connected to Aztec node at", config.nodeUrl);

  // 2. Create wallet
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  console.log("EmbeddedWallet created");

  // 3. Set up sponsored fee payment
  let fpcAddress: InstanceType<typeof AztecAddress>;

  if (config.sponsoredFpcAddress) {
    // Explicit FPC address provided (e.g., devnet)
    fpcAddress = AztecAddress.fromString(config.sponsoredFpcAddress);
    const fpcInstance = await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
    await wallet.registerContract(
      { ...fpcInstance, address: fpcAddress },
      SponsoredFPCContract.artifact
    );
  } else {
    // Local: compute FPC address from artifact with salt=0
    const fpcInstance = await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
    await wallet.registerContract(fpcInstance, SponsoredFPCContract.artifact);
    fpcAddress = fpcInstance.address;
  }

  const paymentMethod = new SponsoredFeePaymentMethod(fpcAddress);
  console.log("Sponsored fee payment configured at", fpcAddress.toString());

  // 4. Create admin Schnorr account from the secret key
  const adminAcctMgr = await wallet.createSchnorrAccount(
    Fr.fromString(config.adminSecretKey),
    Fr.random(),
    GrumpkinScalar.random()
  );
  const adminAddress = adminAcctMgr.address;
  console.log("Admin account address:", adminAddress.toString());

  // Deploy the admin account (signerless path with sponsored fees)
  const adminDeployMethod = await adminAcctMgr.getDeployMethod();
  await adminDeployMethod.send({
    from: AztecAddress.ZERO,
    fee: { paymentMethod },
  });
  console.log("Admin account deployed");

  // Register admin as a sender
  await wallet.registerSender(adminAddress, "admin");
  console.log("Admin registered as sender");

  // 5. Load JwksRegistry contract artifact and connect
  const artifactPath = path.resolve(
    __dirname,
    "../../contracts/jwks_registry/target/jwks_registry-JwksRegistry.json"
  );
  const raw = JSON.parse(fs.readFileSync(artifactPath, "utf-8"));
  const artifact = loadContractArtifact(raw);

  const registryAddress = AztecAddress.fromString(config.registryAddress);
  const registryContract = await Contract.at(registryAddress, artifact, wallet);
  console.log("Connected to JwksRegistry at", registryAddress.toString());

  return {
    wallet,
    adminAddress,
    paymentMethod,
    registryContract,
  };
}
