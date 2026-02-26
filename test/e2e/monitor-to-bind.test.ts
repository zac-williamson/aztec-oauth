/**
 * Cross-System Integration Test: Monitor → Registry → ZkLogin
 *
 * Proves the full pipeline: the JWKS monitor populates real Google public keys
 * into the registry, and those keys are in the correct format for bind_account.
 *
 * Requires:
 *   - Aztec sandbox running: `aztec start --sandbox`
 *   - Compiled contracts in their target/ directories
 *   - Internet access (fetches live Google JWKS)
 *
 * Run: npm test
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// Monitor imports (from registry/server)
import { JwksMonitor, type ProviderConfig } from "../../registry/server/src/monitor.js";
import { computeKidHash } from "../../registry/server/src/kid-hash.js";
import type { ProcessedKey } from "../../registry/server/src/jwks-fetcher.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─── Constants ──────────────────────────────────────────────────────────────

const LIMB_BITS = 120n;
const NUM_LIMBS = 18;
const MAX_LIMB_VALUE = 1n << LIMB_BITS; // 2^120

describe("Monitor → Registry → ZkLogin Integration", () => {
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
  let zkLoginContract: any;

  // Keys submitted during the monitor poll
  let submittedKeys: ProcessedKey[] = [];

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
    console.log("Sandbox is running, node version:", rpcResult.result?.nodeVersion);

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
    const registryArtifactPath = path.resolve(
      __dirname,
      "../../registry/contracts/jwks_registry/target/jwks_registry-JwksRegistry.json"
    );
    const registryRaw = JSON.parse(fs.readFileSync(registryArtifactPath, "utf-8"));
    const registryArtifact = loadContractArtifact(registryRaw);

    registryContract = await Contract.deploy(wallet, registryArtifact, [
      adminAddress,
      new Fr(0n),
      new Fr(0n),
      new Fr(0n),
    ]).send({ from: adminAddress, fee: { paymentMethod } });

    expect(registryContract.address).toBeDefined();
    expect(registryContract.address.isZero()).toBe(false);
    console.log("JwksRegistry deployed at:", registryContract.address.toString());

    // Deploy ZkLogin
    const zkLoginArtifactPath = path.resolve(
      __dirname,
      "../../login/contracts/zk_login/target/zk_login-ZkLogin.json"
    );
    const zkLoginRaw = JSON.parse(fs.readFileSync(zkLoginArtifactPath, "utf-8"));
    const zkLoginArtifact = loadContractArtifact(zkLoginRaw);

    zkLoginContract = await Contract.deploy(wallet, zkLoginArtifact, [
      registryContract.address,
    ]).send({ from: adminAddress, fee: { paymentMethod } });

    expect(zkLoginContract.address).toBeDefined();
    expect(zkLoginContract.address.isZero()).toBe(false);
    console.log("ZkLogin deployed at:", zkLoginContract.address.toString());
  }, 600_000);

  it("monitor poll populates real Google keys", async () => {
    expect(registryContract).toBeDefined();

    submittedKeys = [];

    const monitor = new JwksMonitor({
      contract: registryContract,
      adminAddress,
      paymentMethod,
      pollIntervalMs: 60_000, // Won't repeat in test
      // Only fetch Google (faster, Apple sometimes slow)
      providers: [
        {
          providerId: 1,
          name: "Google",
          jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
        },
      ],
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

    await monitor.poll();

    // Google typically serves 2-3 keys
    expect(submittedKeys.length).toBeGreaterThanOrEqual(2);
    console.log(`Monitor poll submitted ${submittedKeys.length} Google key(s)`);
  }, 600_000);

  it("registry returns valid keys with correct limb format", async () => {
    expect(registryContract).toBeDefined();
    expect(submittedKeys.length).toBeGreaterThan(0);

    for (const key of submittedKeys) {
      const storedJwk = await registryContract.methods
        .get_jwk(new Fr(key.providerId), key.kidHash)
        .simulate({ from: adminAddress });

      expect(storedJwk.is_valid).toBe(true);

      // Verify all 18 modulus limbs match
      for (let i = 0; i < NUM_LIMBS; i++) {
        const storedLimb =
          typeof storedJwk.modulus_limbs[i] === "bigint"
            ? storedJwk.modulus_limbs[i]
            : storedJwk.modulus_limbs[i].toBigInt();
        expect(storedLimb).toBe(key.modulusLimbs[i]);
      }

      // Verify all 18 redc_params limbs match
      for (let i = 0; i < NUM_LIMBS; i++) {
        const storedLimb =
          typeof storedJwk.redc_params_limbs[i] === "bigint"
            ? storedJwk.redc_params_limbs[i]
            : storedJwk.redc_params_limbs[i].toBigInt();
        expect(storedLimb).toBe(key.redcParamsLimbs[i]);
      }

      console.log(`Verified on-chain key: kid="${key.kid}" - all 36 limbs match`);
    }
  }, 120_000);

  it("ZkLogin contract can read keys cross-contract via registry", async () => {
    expect(zkLoginContract).toBeDefined();

    // This call exercises the cross-contract read path: ZkLogin → JwksRegistry
    const isBound = await zkLoginContract.methods
      .is_address_bound(adminAddress)
      .simulate({ from: adminAddress });

    // Not bound yet, but the call succeeded (proves cross-contract connectivity)
    expect(isBound).toBe(false);
    console.log("ZkLogin cross-contract call succeeded (is_address_bound = false)");
  }, 60_000);

  it("limbs are in correct u128 range for bind_account", () => {
    expect(submittedKeys.length).toBeGreaterThan(0);

    for (const key of submittedKeys) {
      // Every limb must be < 2^120 (fits in u128 with room to spare)
      for (let i = 0; i < NUM_LIMBS; i++) {
        expect(key.modulusLimbs[i]).toBeLessThan(MAX_LIMB_VALUE);
        expect(key.modulusLimbs[i]).toBeGreaterThanOrEqual(0n);
        expect(key.redcParamsLimbs[i]).toBeLessThan(MAX_LIMB_VALUE);
        expect(key.redcParamsLimbs[i]).toBeGreaterThanOrEqual(0n);
      }

      // Reconstruct modulus and verify it's a valid 2048-bit RSA modulus (> 2^2047)
      let modulus = 0n;
      for (let i = NUM_LIMBS - 1; i >= 0; i--) {
        modulus = (modulus << LIMB_BITS) | key.modulusLimbs[i];
      }
      const MIN_RSA_2048 = 1n << 2047n;
      expect(modulus).toBeGreaterThan(MIN_RSA_2048);

      // Sanity check Barrett reduction: redc * modulus should be close to 2^4102
      let redc = 0n;
      for (let i = NUM_LIMBS - 1; i >= 0; i--) {
        redc = (redc << LIMB_BITS) | key.redcParamsLimbs[i];
      }
      const product = redc * modulus;
      const target = 1n << (2n * 2048n + 6n); // 2^4102
      // product should be in [target - modulus, target)
      expect(product).toBeLessThan(target);
      expect(product).toBeGreaterThanOrEqual(target - modulus);

      console.log(`Verified limb ranges for kid="${key.kid}": modulus=${modulus.toString(16).length * 4} bits`);
    }
  });

  it("noir-jwt generateInputs produces compatible limb format", async () => {
    expect(submittedKeys.length).toBeGreaterThan(0);

    // Import generateInputs from noir-jwt
    const { generateInputs } = await import("noir-jwt");

    // Generate a test RSA key pair (NOT the Google key - we can't sign with Google's private key)
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 65537,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const testJwk = crypto.createPublicKey(publicKey).export({ format: "jwk" }) as crypto.JsonWebKey;

    // Create a test JWT signed with the test key
    const header = { alg: "RS256", typ: "JWT", kid: "test-e2e-key" };
    const payload = {
      iss: "https://accounts.google.com",
      sub: "e2e-test-user",
      nonce: "0x" + "ab".repeat(32),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const headerB64 = Buffer.from(JSON.stringify(header))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const payloadB64 = Buffer.from(JSON.stringify(payload))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const signedData = `${headerB64}.${payloadB64}`;

    const sign = crypto.createSign("RSA-SHA256");
    sign.update(signedData);
    const signature = sign.sign(privateKey);
    const signatureB64 = signature
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const jwt = `${signedData}.${signatureB64}`;

    // Generate circuit inputs via noir-jwt
    const inputs = await generateInputs({
      jwt,
      pubkey: testJwk,
      maxSignedDataLength: 1024,
    });

    // Verify limb count
    expect(inputs.pubkey_modulus_limbs).toHaveLength(NUM_LIMBS);
    expect(inputs.redc_params_limbs).toHaveLength(NUM_LIMBS);
    expect(inputs.signature_limbs).toHaveLength(NUM_LIMBS);

    // Verify all limbs are parseable to BigInt and within range
    for (let i = 0; i < NUM_LIMBS; i++) {
      const modulusLimb = BigInt(inputs.pubkey_modulus_limbs[i]);
      const redcLimb = BigInt(inputs.redc_params_limbs[i]);
      const sigLimb = BigInt(inputs.signature_limbs[i]);

      expect(modulusLimb).toBeLessThan(MAX_LIMB_VALUE);
      expect(modulusLimb).toBeGreaterThanOrEqual(0n);
      expect(redcLimb).toBeLessThan(MAX_LIMB_VALUE);
      expect(redcLimb).toBeGreaterThanOrEqual(0n);
      expect(sigLimb).toBeLessThan(MAX_LIMB_VALUE);
      expect(sigLimb).toBeGreaterThanOrEqual(0n);
    }

    // Verify the decomposition algorithm matches the monitor's:
    // Both use 120-bit little-endian limbs. Reconstruct and compare against the JWK modulus.
    const testModulusBytes = Buffer.from(testJwk.n!, "base64url");
    let expectedModulus = 0n;
    for (const byte of testModulusBytes) {
      expectedModulus = (expectedModulus << 8n) | BigInt(byte);
    }

    let reconstructedModulus = 0n;
    for (let i = NUM_LIMBS - 1; i >= 0; i--) {
      reconstructedModulus =
        (reconstructedModulus << LIMB_BITS) | BigInt(inputs.pubkey_modulus_limbs[i]);
    }

    expect(reconstructedModulus).toBe(expectedModulus);
    console.log("noir-jwt generateInputs produces identical limb format to monitor");

    // Also verify Barrett reduction matches the monitor's formula
    const expectedRedc = (1n << (2n * 2048n + 6n)) / expectedModulus;
    let reconstructedRedc = 0n;
    for (let i = NUM_LIMBS - 1; i >= 0; i--) {
      reconstructedRedc =
        (reconstructedRedc << LIMB_BITS) | BigInt(inputs.redc_params_limbs[i]);
    }

    expect(reconstructedRedc).toBe(expectedRedc);
    console.log("Barrett reduction params match between noir-jwt and monitor");
  }, 30_000);
});
