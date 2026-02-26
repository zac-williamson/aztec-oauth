/**
 * Integration Tests for zkLogin Identity Binding
 *
 * Tests the full flow: deploy registry, populate keys, deploy ZkLogin,
 * bind accounts with mock JWTs, and verify sybil resistance.
 *
 * Requires:
 *   - Aztec sandbox running: `aztec start --sandbox`
 *   - Compiled contracts in their target/ directories
 *
 * Run: npx vitest run integration.test.ts
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { generateInputs } from "noir-jwt";

// ─── Mock JWT Construction ───────────────────────────────────────────────────

/**
 * Generate a test RSA-2048 key pair.
 */
function generateTestRsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 65537,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const pubKeyObj = crypto.createPublicKey(publicKey);
  const jwk = pubKeyObj.export({ format: "jwk" }) as crypto.JsonWebKey;

  return { publicKey, privateKey, jwk };
}

/**
 * Create a mock JWT with the given claims, signed with the test RSA key.
 */
function createMockJwt(
  claims: Record<string, unknown>,
  privateKey: string,
  kid: string
): string {
  const header = { alg: "RS256", typ: "JWT", kid };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(claims));
  const signedData = `${headerB64}.${payloadB64}`;

  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signedData);
  const signature = sign.sign(privateKey);
  const signatureB64 = base64UrlEncodeBuffer(signature);

  return `${signedData}.${signatureB64}`;
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlEncodeBuffer(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Convert JWK modulus to 18 limbs of 120 bits each.
 */
function jwkModulusToLimbs(n: string): { modulus: bigint[]; redc: bigint[] } {
  const bytes = Buffer.from(
    n.replace(/-/g, "+").replace(/_/g, "/") + "==",
    "base64"
  );
  let modulusBigInt = 0n;
  for (const byte of bytes) {
    modulusBigInt = (modulusBigInt << 8n) | BigInt(byte);
  }

  const LIMB_BITS = 120n;
  const mask = (1n << LIMB_BITS) - 1n;
  const modulus: bigint[] = [];
  let remaining = modulusBigInt;
  for (let i = 0; i < 18; i++) {
    modulus.push(remaining & mask);
    remaining >>= LIMB_BITS;
  }

  // Barrett reduction params (OVERFLOW_BITS=6 for bignum v0.9.2+)
  const redcBigInt = (1n << (2n * 2048n + 6n)) / modulusBigInt;
  const redc: bigint[] = [];
  remaining = redcBigInt;
  for (let i = 0; i < 18; i++) {
    redc.push(remaining & mask);
    remaining >>= LIMB_BITS;
  }

  return { modulus, redc };
}

/**
 * Simple Pedersen hash placeholder (for unit test nonce/nullifier computation).
 * In production, use Barretenberg's actual Pedersen hash.
 */
function mockPedersenHash(inputs: bigint[]): bigint {
  let hash = 0n;
  for (const input of inputs) {
    hash = hash ^ input;
    hash = ((hash << 7n) | (hash >> 247n)) & ((1n << 254n) - 1n);
    hash = hash ^ (hash >> 13n);
  }
  return hash;
}

// ─── Test Suite ──────────────────────────────────────────────────────────────

describe("zkLogin Integration", () => {
  let testKeyPair: ReturnType<typeof generateTestRsaKeyPair>;
  const TEST_KID = "test-key-001";
  const PROVIDER_GOOGLE = 1;
  const PROVIDER_APPLE = 2;

  beforeAll(() => {
    testKeyPair = generateTestRsaKeyPair();
  });

  describe("Mock JWT Construction", () => {
    it("creates a valid JWT signed with RS256", () => {
      const jwt = createMockJwt(
        {
          iss: "https://accounts.google.com",
          sub: "user-12345",
          nonce: "0x1234",
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        testKeyPair.privateKey,
        TEST_KID
      );

      const parts = jwt.split(".");
      expect(parts).toHaveLength(3);

      const header = JSON.parse(
        Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()
      );
      expect(header.alg).toBe("RS256");
      expect(header.kid).toBe(TEST_KID);

      const payload = JSON.parse(
        Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()
      );
      expect(payload.iss).toBe("https://accounts.google.com");
      expect(payload.sub).toBe("user-12345");
    });

    it("signature verifies with the public key", () => {
      const jwt = createMockJwt(
        { iss: "https://accounts.google.com", sub: "user-12345", nonce: "0x1234" },
        testKeyPair.privateKey,
        TEST_KID
      );

      const parts = jwt.split(".");
      const signedData = `${parts[0]}.${parts[1]}`;
      const signature = Buffer.from(
        parts[2].replace(/-/g, "+").replace(/_/g, "/") + "==",
        "base64"
      );

      const verify = crypto.createVerify("RSA-SHA256");
      verify.update(signedData);
      expect(verify.verify(testKeyPair.publicKey, signature)).toBe(true);
    });
  });

  describe("JWK Transformation", () => {
    it("converts JWK modulus to 18 limbs", () => {
      const { modulus, redc } = jwkModulusToLimbs(testKeyPair.jwk.n!);
      expect(modulus).toHaveLength(18);
      expect(redc).toHaveLength(18);

      let reconstructed = 0n;
      for (let i = 17; i >= 0; i--) {
        reconstructed = (reconstructed << 120n) | modulus[i];
      }

      const originalBytes = Buffer.from(
        testKeyPair.jwk.n!.replace(/-/g, "+").replace(/_/g, "/") + "==",
        "base64"
      );
      let originalBigInt = 0n;
      for (const byte of originalBytes) {
        originalBigInt = (originalBigInt << 8n) | BigInt(byte);
      }

      expect(reconstructed).toBe(originalBigInt);
    });
  });

  describe("Identity Nullifier", () => {
    it("same sub+provider always produces same nullifier", () => {
      const subBytes = new TextEncoder().encode("user-12345");
      let subHash = 0n;
      for (const byte of subBytes) {
        subHash = (subHash << 8n) | BigInt(byte);
      }

      const nullifier1 = mockPedersenHash([subHash, BigInt(PROVIDER_GOOGLE)]);
      const nullifier2 = mockPedersenHash([subHash, BigInt(PROVIDER_GOOGLE)]);
      expect(nullifier1).toBe(nullifier2);
    });

    it("different subs produce different nullifiers", () => {
      const sub1Bytes = new TextEncoder().encode("user-12345");
      const sub2Bytes = new TextEncoder().encode("user-67890");

      let sub1Hash = 0n;
      for (const byte of sub1Bytes) sub1Hash = (sub1Hash << 8n) | BigInt(byte);
      let sub2Hash = 0n;
      for (const byte of sub2Bytes) sub2Hash = (sub2Hash << 8n) | BigInt(byte);

      const nullifier1 = mockPedersenHash([sub1Hash, BigInt(PROVIDER_GOOGLE)]);
      const nullifier2 = mockPedersenHash([sub2Hash, BigInt(PROVIDER_GOOGLE)]);
      expect(nullifier1).not.toBe(nullifier2);
    });

    it("same sub with different providers produces different nullifiers", () => {
      const subBytes = new TextEncoder().encode("user-12345");
      let subHash = 0n;
      for (const byte of subBytes) subHash = (subHash << 8n) | BigInt(byte);

      const googleNullifier = mockPedersenHash([subHash, BigInt(PROVIDER_GOOGLE)]);
      const appleNullifier = mockPedersenHash([subHash, BigInt(PROVIDER_APPLE)]);
      expect(googleNullifier).not.toBe(appleNullifier);
    });
  });

  describe("Nonce Binding", () => {
    it("nonce is deterministic for same address+randomness", () => {
      const address = 0x1234n;
      const randomness = 0xdeadbeefn;
      const nonce1 = mockPedersenHash([address, randomness]);
      const nonce2 = mockPedersenHash([address, randomness]);
      expect(nonce1).toBe(nonce2);
    });

    it("nonce differs for different addresses", () => {
      const randomness = 0xdeadbeefn;
      const nonce1 = mockPedersenHash([0x1234n, randomness]);
      const nonce2 = mockPedersenHash([0x5678n, randomness]);
      expect(nonce1).not.toBe(nonce2);
    });
  });

  // ── Aztec Sandbox Integration Tests ──────────────────────────────────────
  // These tests require a running Aztec sandbox and compiled contracts.
  // They deploy real contracts and interact with them on-chain.

  describe("Aztec Contract Integration", () => {
    // Lazy-loaded SDK modules (sub-path imports)
    let Fr: any;
    let AztecAddress: any;
    let Contract: any;
    let loadContractArtifact: any;
    let pedersenHash: any;
    let getContractInstanceFromInstantiationParams: any;

    let wallet: any;           // EmbeddedWallet instance
    let adminAddress: any;     // AztecAddress of the admin/deployer account
    let paymentMethod: any;    // SponsoredFeePaymentMethod

    let registryContract: any;
    let zkLoginContract: any;
    let kidHash: any; // Fr

    beforeAll(async () => {
      // Verify sandbox is reachable via JSON-RPC
      const rpcResponse = await fetch("http://localhost:8080", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "node_getNodeInfo", params: [], id: 1 }),
      });
      const rpcResult = await rpcResponse.json();
      expect(rpcResult.result).toBeDefined();
      console.log("Sandbox is running, node version:", rpcResult.result?.nodeVersion);

      // Import SDK modules via sub-path exports
      const fieldsModule = await import("@aztec/aztec.js/fields");
      Fr = fieldsModule.Fr;

      const addressModule = await import("@aztec/aztec.js/addresses");
      AztecAddress = addressModule.AztecAddress;

      const contractsModule = await import("@aztec/aztec.js/contracts");
      Contract = contractsModule.Contract;
      getContractInstanceFromInstantiationParams = contractsModule.getContractInstanceFromInstantiationParams;

      const abiModule = await import("@aztec/aztec.js/abi");
      loadContractArtifact = abiModule.loadContractArtifact;

      const { createAztecNodeClient, waitForNode } = await import("@aztec/aztec.js/node");

      const cryptoModule = await import("@aztec/foundation/crypto/pedersen");
      pedersenHash = cryptoModule.pedersenHash;

      // Create node client and verify connection
      const node = createAztecNodeClient("http://localhost:8080");
      await waitForNode(node);
      console.log("Connected to Aztec node");

      // Create EmbeddedWallet with ephemeral storage (pass node client, not URL)
      const { EmbeddedWallet } = await import("@aztec/wallets/embedded");
      wallet = await EmbeddedWallet.create(node, { ephemeral: true });
      console.log("EmbeddedWallet created");

      // Setup sponsored fee payment method
      const { SponsoredFeePaymentMethod } = await import("@aztec/aztec.js/fee");
      const { SponsoredFPCContract } = await import("@aztec/noir-contracts.js/SponsoredFPC");
      const sponsoredFPCInstance = await getContractInstanceFromInstantiationParams(
        SponsoredFPCContract.artifact,
        { salt: new Fr(0) }
      );
      await wallet.registerContract(sponsoredFPCInstance, SponsoredFPCContract.artifact);
      paymentMethod = new SponsoredFeePaymentMethod(sponsoredFPCInstance.address);
      console.log("Sponsored fee payment method configured");

      // Create a schnorr account for the admin/deployer
      const { GrumpkinScalar } = await import("@aztec/aztec.js/fields");
      const adminAcctMgr = await wallet.createSchnorrAccount(
        Fr.random(), Fr.random(), GrumpkinScalar.random()
      );
      adminAddress = adminAcctMgr.address;
      console.log("Admin account address:", adminAddress.toString());

      // Deploy the admin account contract using signerless path with sponsored fees
      const adminDeployMethod = await adminAcctMgr.getDeployMethod();
      await adminDeployMethod.send({
        from: AztecAddress.ZERO,
        fee: { paymentMethod },
      });
      console.log("Admin account deployed");

      // Register the admin account as a sender
      await wallet.registerSender(adminAddress, "admin");
      console.log("Admin account registered as sender");
    }, 600_000);

    function loadArtifact(jsonPath: string) {
      const raw = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));
      return loadContractArtifact(raw);
    }

    async function computeKidHash(kid: string): Promise<any> {
      const kidBytes = new TextEncoder().encode(kid);
      const fields: bigint[] = new Array(9).fill(0n);
      for (let i = 0; i < kidBytes.length; i++) {
        const fieldIdx = Math.floor(i / 31);
        fields[fieldIdx] = fields[fieldIdx] * 256n + BigInt(kidBytes[i]);
      }
      fields[8] = BigInt(kidBytes.length);

      const fieldInputs = fields.map((f) => new Fr(f));
      return await pedersenHash(fieldInputs);
    }

    it("deploys JwksRegistry", async () => {
      const artifactPath = path.resolve(
        __dirname,
        "../../registry/contracts/jwks_registry/target/jwks_registry-JwksRegistry.json"
      );
      const artifact = loadArtifact(artifactPath);

      registryContract = await Contract.deploy(
        wallet,
        artifact,
        [adminAddress, new Fr(0n), new Fr(0n), new Fr(0n)]
      ).send({ from: adminAddress, fee: { paymentMethod } });

      expect(registryContract.address).toBeDefined();
      expect(registryContract.address.isZero()).toBe(false);
      console.log("JwksRegistry deployed at:", registryContract.address.toString());
    }, 300_000);

    it("populates registry via admin_set_jwk", async () => {
      expect(registryContract).toBeDefined();

      const { modulus, redc } = jwkModulusToLimbs(testKeyPair.jwk.n!);

      kidHash = await computeKidHash(TEST_KID);

      await registryContract.methods
        .admin_set_jwk(
          new Fr(PROVIDER_GOOGLE),
          kidHash,
          modulus.map((l: bigint) => new Fr(l)),
          redc.map((l: bigint) => new Fr(l))
        )
        .send({ from: adminAddress, fee: { paymentMethod } });

      console.log("JWK set for Google provider, kid:", TEST_KID);
    }, 120_000);

    it("reads JWK via get_jwk view function", async () => {
      expect(registryContract).toBeDefined();

      const storedJwk = await registryContract.methods
        .get_jwk(new Fr(PROVIDER_GOOGLE), kidHash)
        .simulate({ from: adminAddress });

      expect(storedJwk.is_valid).toBe(true);

      const { modulus } = jwkModulusToLimbs(testKeyPair.jwk.n!);
      for (let i = 0; i < 18; i++) {
        const storedLimb = typeof storedJwk.modulus_limbs[i] === "bigint"
          ? storedJwk.modulus_limbs[i]
          : storedJwk.modulus_limbs[i].toBigInt();
        expect(storedLimb).toBe(modulus[i]);
      }
      console.log("JWK verified: modulus limbs match");
    }, 60_000);

    it("deploys ZkLogin contract", async () => {
      expect(registryContract).toBeDefined();

      const artifactPath = path.resolve(
        __dirname,
        "../contracts/zk_login/target/zk_login-ZkLogin.json"
      );
      const artifact = loadArtifact(artifactPath);

      zkLoginContract = await Contract.deploy(
        wallet,
        artifact,
        [registryContract.address]
      ).send({ from: adminAddress, fee: { paymentMethod } });

      expect(zkLoginContract.address).toBeDefined();
      expect(zkLoginContract.address.isZero()).toBe(false);
      console.log("ZkLogin deployed at:", zkLoginContract.address.toString());
    }, 300_000);

    it("is_address_bound returns false for unbound address", async () => {
      expect(zkLoginContract).toBeDefined();

      const isBound = await zkLoginContract.methods
        .is_address_bound(adminAddress)
        .simulate({ from: adminAddress });

      expect(isBound).toBe(false);
    }, 30_000);

    // get_bound_address was removed - binding state is now tracked via
    // nullifiers only (no public storage of identity->address mappings)

    // ── bind_account tests ─────────────────────────────────────────────────

    const BIND_SUB = "test-user-bind-001";
    let bindNonceRandomness: any; // Fr

    it("bind_account binds an identity to the caller's address", async () => {
      expect(zkLoginContract).toBeDefined();
      expect(registryContract).toBeDefined();

      // 1. Compute nonce = hex(pedersen_hash([sender, randomness]))
      bindNonceRandomness = Fr.random();
      const nonceHash = await pedersenHash([adminAddress.toField(), bindNonceRandomness]);
      // Format as "0x" + 64 lowercase hex chars (matches Noir field_to_hex_bytes)
      const nonceHex = "0x" + nonceHash.toBigInt().toString(16).padStart(64, "0");

      // 2. Create JWT with the correct nonce
      const claims = {
        iss: "https://accounts.google.com",
        sub: BIND_SUB,
        nonce: nonceHex,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      const jwt = createMockJwt(claims, testKeyPair.privateKey, TEST_KID);

      // 3. Generate circuit inputs via noir-jwt SDK
      const inputs = await generateInputs({
        jwt,
        pubkey: testKeyPair.jwk,
        maxSignedDataLength: 1024, // MAX_JWT_DATA_LENGTH
      });

      // 4. Call bind_account (use_public_fallback=true since key was just added)
      // BoundedVec encoder expects a plain array; it uses arr.length as len and pads storage
      const jwtBytes = inputs.data!.storage.slice(0, inputs.data!.len);
      await zkLoginContract.methods
        .bind_account(
          jwtBytes,
          inputs.base64_decode_offset,
          inputs.pubkey_modulus_limbs.map((s: string) => BigInt(s)),
          inputs.redc_params_limbs.map((s: string) => BigInt(s)),
          inputs.signature_limbs.map((s: string) => BigInt(s)),
          new Fr(PROVIDER_GOOGLE),
          kidHash,
          bindNonceRandomness,
          true, // use_public_fallback
        )
        .send({ from: adminAddress, fee: { paymentMethod } });

      console.log("bind_account succeeded for sub:", BIND_SUB);

      // 5. Verify is_address_bound now returns true
      const isBound = await zkLoginContract.methods
        .is_address_bound(adminAddress)
        .simulate({ from: adminAddress });

      expect(isBound).toBe(true);
      console.log("is_address_bound(admin) =", isBound);
    }, 600_000);

    // get_bound_address was removed - binding state is tracked via nullifiers.
    // Use is_address_bound to check if an address has been bound.
  });
});
