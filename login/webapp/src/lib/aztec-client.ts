/**
 * Aztec client setup for the browser.
 *
 * Creates an EmbeddedWallet with a user Schnorr account and
 * SponsoredFeePaymentMethod for gas-free transactions.
 *
 * Account keys are persisted to localStorage so the same wallet
 * can be restored after an OAuth redirect (which navigates away from the page).
 */

import { Fr, GrumpkinScalar } from "@aztec/aztec.js/fields";
import { AztecAddress } from "@aztec/aztec.js/addresses";
import { Contract, getContractInstanceFromInstantiationParams } from "@aztec/aztec.js/contracts";
import { loadContractArtifact } from "@aztec/aztec.js/abi";
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { SponsoredFPCContract } from "@aztec/noir-contracts.js/SponsoredFPC";
import type { AppConfig } from "./config";

export interface AztecClient {
  wallet: InstanceType<typeof EmbeddedWallet>;
  node: ReturnType<typeof createAztecNodeClient>;
  userAddress: AztecAddress;
  paymentMethod: SponsoredFeePaymentMethod;
}

const KEYS_STORAGE_KEY = "aztec-sybil-wallet-keys";

interface SavedKeys {
  secret: string;
  salt: string;
  signing: string;
}

function saveKeys(secret: Fr, salt: Fr, signing: InstanceType<typeof GrumpkinScalar>): void {
  const data: SavedKeys = {
    secret: secret.toString(),
    salt: salt.toString(),
    signing: signing.toString(),
  };
  localStorage.setItem(KEYS_STORAGE_KEY, JSON.stringify(data));
}

function loadKeys(): SavedKeys | null {
  const raw = localStorage.getItem(KEYS_STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function clearKeys(): void {
  localStorage.removeItem(KEYS_STORAGE_KEY);
}

export async function createAztecClient(config: AppConfig): Promise<AztecClient> {
  // Connect to node
  console.log("[aztec-client] Connecting to node:", config.nodeUrl);
  const node = createAztecNodeClient(config.nodeUrl);
  await waitForNode(node);
  console.log("[aztec-client] Node connected");

  // Create EmbeddedWallet
  console.log("[aztec-client] Creating EmbeddedWallet...");
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  console.log("[aztec-client] EmbeddedWallet created");

  // Setup SponsoredFeePaymentMethod
  console.log("[aztec-client] Setting up SponsoredFeePaymentMethod...");
  let fpcAddress: AztecAddress;
  if (config.sponsoredFpcAddress) {
    fpcAddress = AztecAddress.fromString(config.sponsoredFpcAddress);
    const fpcInstance = await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
    await wallet.registerContract(fpcInstance, SponsoredFPCContract.artifact);
  } else {
    const fpcInstance = await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
    await wallet.registerContract(fpcInstance, SponsoredFPCContract.artifact);
    fpcAddress = fpcInstance.address;
  }
  const paymentMethod = new SponsoredFeePaymentMethod(fpcAddress);
  console.log("[aztec-client] Fee payment configured at", fpcAddress.toString());

  // Restore or generate account keys
  const saved = loadKeys();
  let secret: Fr;
  let salt: Fr;
  let signing: InstanceType<typeof GrumpkinScalar>;

  if (saved) {
    console.log("[aztec-client] Restoring wallet keys from session...");
    secret = Fr.fromString(saved.secret);
    salt = Fr.fromString(saved.salt);
    signing = GrumpkinScalar.fromString(saved.signing);
  } else {
    console.log("[aztec-client] Generating new wallet keys...");
    secret = Fr.random();
    salt = Fr.random();
    signing = GrumpkinScalar.random();
    saveKeys(secret, salt, signing);
  }

  // Create Schnorr account with deterministic keys
  console.log("[aztec-client] Creating Schnorr account...");
  const userAcctMgr = await wallet.createSchnorrAccount(secret, salt, signing);
  const userAddress = userAcctMgr.address;
  console.log("[aztec-client] Schnorr account created:", userAddress.toString());

  // Deploy user account only if this is a fresh session (not restoring after redirect)
  if (saved) {
    console.log("[aztec-client] Restored keys from session — skipping deploy (already deployed)");
  } else {
    console.log("[aztec-client] Deploying user account (this may take 30-60s)...");
    const deployMethod = await userAcctMgr.getDeployMethod();
    await deployMethod.send({
      from: AztecAddress.ZERO,
      fee: { paymentMethod },
    });
    console.log("[aztec-client] User account deployed");
  }

  // Register the user account as a sender
  await wallet.registerSender(userAddress, "user");
  console.log("[aztec-client] User registered as sender");

  return { wallet, node, userAddress, paymentMethod };
}

/**
 * Load and connect to a deployed contract.
 *
 * Registers the contract with the local PXE if not already known,
 * fetching the instance from the node (which has all deployed contracts).
 */
export async function connectToContract(
  wallet: InstanceType<typeof EmbeddedWallet>,
  node: ReturnType<typeof createAztecNodeClient>,
  address: string,
  artifactJson: any
): Promise<any> {
  const artifact = loadContractArtifact(artifactJson);
  const contractAddress = AztecAddress.fromString(address);

  // Check if contract is already registered in the local PXE
  const metadata = await wallet.getContractMetadata(contractAddress);
  if (!metadata.instance) {
    console.log("[aztec-client] Contract not in local PXE, fetching from node...");
    // Fetch the on-chain contract instance from the node
    const onChainInstance = await node.getContract(contractAddress);
    if (!onChainInstance) {
      throw new Error(
        `Contract ${address} not found on-chain. Was it deployed?`
      );
    }
    await wallet.registerContract(onChainInstance, artifact);
    console.log("[aztec-client] Contract registered with local PXE");
  } else {
    console.log("[aztec-client] Contract already registered in local PXE");
  }

  return Contract.at(contractAddress, artifact, wallet);
}
