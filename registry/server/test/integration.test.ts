/**
 * Integration test for the JWKS Monitor.
 *
 * Requires:
 *   - Aztec sandbox running: `aztec start --sandbox`
 *   - Compiled JwksRegistry contract in target/
 *
 * Run: npx vitest run test/integration.test.ts
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { JwksMonitor, type ProviderConfig } from "../src/monitor.js";
import { computeKidHash } from "../src/kid-hash.js";
import type { ProcessedKey } from "../src/jwks-fetcher.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("JWKS Monitor Integration", () => {
  // Lazy-loaded SDK modules
  let Fr: any;
  let GrumpkinScalar: any;
  let AztecAddress: any;
  let Contract: any;
  let loadContractArtifact: any;
  let getContractInstanceFromInstantiationParams: any;

  let wallet: any;
  let adminAddress: any;
  let paymentMethod: any;
  let registryContract: any;

  beforeAll(async () => {
    // Verify sandbox is reachable
    const rpcResponse = await fetch("http://localhost:8080", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "node_getNodeInfo",
        params: [],
        id: 1,
      }),
    });
    const rpcResult = await rpcResponse.json();
    expect(rpcResult.result).toBeDefined();
    console.log(
      "Sandbox is running, node version:",
      rpcResult.result?.nodeVersion
    );

    // Import SDK modules via sub-path exports
    const fieldsModule = await import("@aztec/aztec.js/fields");
    Fr = fieldsModule.Fr;
    GrumpkinScalar = fieldsModule.GrumpkinScalar;

    const addressModule = await import("@aztec/aztec.js/addresses");
    AztecAddress = addressModule.AztecAddress;

    const contractsModule = await import("@aztec/aztec.js/contracts");
    Contract = contractsModule.Contract;
    getContractInstanceFromInstantiationParams =
      contractsModule.getContractInstanceFromInstantiationParams;

    const abiModule = await import("@aztec/aztec.js/abi");
    loadContractArtifact = abiModule.loadContractArtifact;

    const { createAztecNodeClient, waitForNode } = await import(
      "@aztec/aztec.js/node"
    );

    // Connect to node
    const node = createAztecNodeClient("http://localhost:8080");
    await waitForNode(node);
    console.log("Connected to Aztec node");

    // Create EmbeddedWallet
    const { EmbeddedWallet } = await import("@aztec/wallets/embedded");
    wallet = await EmbeddedWallet.create(node, { ephemeral: true });
    console.log("EmbeddedWallet created");

    // Setup sponsored fee payment
    const { SponsoredFeePaymentMethod } = await import("@aztec/aztec.js/fee");
    const { SponsoredFPCContract } = await import(
      "@aztec/noir-contracts.js/SponsoredFPC"
    );
    const sponsoredFPCInstance =
      await getContractInstanceFromInstantiationParams(
        SponsoredFPCContract.artifact,
        { salt: new Fr(0) }
      );
    await wallet.registerContract(
      sponsoredFPCInstance,
      SponsoredFPCContract.artifact
    );
    paymentMethod = new SponsoredFeePaymentMethod(
      sponsoredFPCInstance.address
    );
    console.log("Sponsored fee payment configured");

    // Create admin account
    const adminAcctMgr = await wallet.createSchnorrAccount(
      Fr.random(),
      Fr.random(),
      GrumpkinScalar.random()
    );
    adminAddress = adminAcctMgr.address;
    console.log("Admin account address:", adminAddress.toString());

    const adminDeployMethod = await adminAcctMgr.getDeployMethod();
    await adminDeployMethod.send({
      from: AztecAddress.ZERO,
      fee: { paymentMethod },
    });
    console.log("Admin account deployed");

    await wallet.registerSender(adminAddress, "admin");
    console.log("Admin registered as sender");

    // Deploy JwksRegistry
    const artifactPath = path.resolve(
      __dirname,
      "../../contracts/jwks_registry/target/jwks_registry-JwksRegistry.json"
    );
    const raw = JSON.parse(fs.readFileSync(artifactPath, "utf-8"));
    const artifact = loadContractArtifact(raw);

    registryContract = await Contract.deploy(wallet, artifact, [
      adminAddress,
      new Fr(0n),
      new Fr(0n),
      new Fr(0n),
    ]).send({ from: adminAddress, fee: { paymentMethod } });

    expect(registryContract.address).toBeDefined();
    expect(registryContract.address.isZero()).toBe(false);
    console.log(
      "JwksRegistry deployed at:",
      registryContract.address.toString()
    );
  }, 600_000);

  it("first poll syncs live JWKS keys to the registry", async () => {
    expect(registryContract).toBeDefined();

    // Track submitted keys
    const submittedKeys: ProcessedKey[] = [];

    const monitor = new JwksMonitor({
      contract: registryContract,
      adminAddress,
      paymentMethod,
      pollIntervalMs: 60_000, // Won't actually repeat in test
      submitFn: async (contract, admin, pm, key) => {
        console.log(`Submitting key: provider=${key.providerId}, kid="${key.kid}"`);
        await contract.methods
          .admin_set_jwk(
            new Fr(key.providerId),
            key.kidHash,
            key.modulusLimbs.map((l: bigint) => new Fr(l)),
            key.redcParamsLimbs.map((l: bigint) => new Fr(l))
          )
          .send({ from: admin, fee: { paymentMethod: pm } });
        submittedKeys.push(key);
        console.log(`Key submitted: provider=${key.providerId}, kid="${key.kid}"`);
      },
    });

    // Run one poll cycle
    await monitor.poll();

    // Should have submitted at least some keys (Google typically has 2-3)
    expect(submittedKeys.length).toBeGreaterThan(0);
    console.log(`First poll submitted ${submittedKeys.length} key(s)`);

    // Verify a submitted key is readable on-chain
    const firstKey = submittedKeys[0];
    const storedJwk = await registryContract.methods
      .get_jwk(new Fr(firstKey.providerId), firstKey.kidHash)
      .simulate({ from: adminAddress });

    expect(storedJwk.is_valid).toBe(true);

    // Verify modulus limbs match
    for (let i = 0; i < 18; i++) {
      const storedLimb =
        typeof storedJwk.modulus_limbs[i] === "bigint"
          ? storedJwk.modulus_limbs[i]
          : storedJwk.modulus_limbs[i].toBigInt();
      expect(storedLimb).toBe(firstKey.modulusLimbs[i]);
    }

    console.log("On-chain verification passed for first key");
  }, 600_000);

  it("second poll is a no-op (all keys already on-chain)", async () => {
    expect(registryContract).toBeDefined();

    const submittedKeys: ProcessedKey[] = [];

    const monitor = new JwksMonitor({
      contract: registryContract,
      adminAddress,
      paymentMethod,
      pollIntervalMs: 60_000,
      submitFn: async (contract, admin, pm, key) => {
        await contract.methods
          .admin_set_jwk(
            new Fr(key.providerId),
            key.kidHash,
            key.modulusLimbs.map((l: bigint) => new Fr(l)),
            key.redcParamsLimbs.map((l: bigint) => new Fr(l))
          )
          .send({ from: admin, fee: { paymentMethod: pm } });
        submittedKeys.push(key);
      },
    });

    // Run second poll
    await monitor.poll();

    // Should not submit any keys (all already on-chain and matching)
    expect(submittedKeys).toHaveLength(0);
    console.log("Second poll: no keys submitted (all unchanged)");
  }, 600_000);
});
