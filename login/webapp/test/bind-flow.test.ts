/**
 * Integration test: Full bind_account flow via the webapp's library code.
 *
 * Requires a running Aztec sandbox: `aztec start --sandbox`
 *
 * Deploys contracts, populates JWK, computes Pedersen nonce, creates JWT,
 * generates inputs via noir-jwt, calls bind_account, verifies on-chain.
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { generateInputs } from "noir-jwt";

describe("Bind Flow Integration", () => {
  // Lazy-loaded SDK modules
  let Fr: any;
  let GrumpkinScalar: any;
  let AztecAddress: any;
  let Contract: any;
  let loadContractArtifact: any;
  let pedersenHash: any;
  let getContractInstanceFromInstantiationParams: any;

  let wallet: any;
  let userAddress: any;
  let paymentMethod: any;

  let registryContract: any;
  let zkLoginContract: any;

  let testKeyPair: {
    publicKey: string;
    privateKey: string;
    jwk: crypto.JsonWebKey;
  };
  const TEST_KID = "webapp-test-key-001";
  const PROVIDER_GOOGLE = 1;

  beforeAll(async () => {
    // Verify sandbox is reachable
    const rpcResponse = await fetch("http://localhost:8080", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "node_getNodeInfo", params: [], id: 1 }),
    });
    const rpcResult = await rpcResponse.json();
    expect(rpcResult.result).toBeDefined();

    // Import SDK modules
    const fieldsModule = await import("@aztec/aztec.js/fields");
    Fr = fieldsModule.Fr;
    GrumpkinScalar = fieldsModule.GrumpkinScalar;

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

    // Create node client
    const node = createAztecNodeClient("http://localhost:8080");
    await waitForNode(node);

    // Create EmbeddedWallet
    const { EmbeddedWallet } = await import("@aztec/wallets/embedded");
    wallet = await EmbeddedWallet.create(node, { ephemeral: true });

    // Setup sponsored fees
    const { SponsoredFeePaymentMethod } = await import("@aztec/aztec.js/fee");
    const { SponsoredFPCContract } = await import("@aztec/noir-contracts.js/SponsoredFPC");
    const fpcInstance = await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
    await wallet.registerContract(fpcInstance, SponsoredFPCContract.artifact);
    paymentMethod = new SponsoredFeePaymentMethod(fpcInstance.address);

    // Create user account
    const userAcctMgr = await wallet.createSchnorrAccount(
      Fr.random(), Fr.random(), GrumpkinScalar.random()
    );
    userAddress = userAcctMgr.address;

    const deployMethod = await userAcctMgr.getDeployMethod();
    await deployMethod.send({ from: AztecAddress.ZERO, fee: { paymentMethod } });
    await wallet.registerSender(userAddress, "user");

    // Generate test RSA key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 65537,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const pubKeyObj = crypto.createPublicKey(publicKey);
    const jwk = pubKeyObj.export({ format: "jwk" }) as crypto.JsonWebKey;
    testKeyPair = { publicKey, privateKey, jwk };
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
    return await pedersenHash(fields.map((f: bigint) => new Fr(f)));
  }

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

    const redcBigInt = (1n << (2n * 2048n + 6n)) / modulusBigInt;
    const redc: bigint[] = [];
    remaining = redcBigInt;
    for (let i = 0; i < 18; i++) {
      redc.push(remaining & mask);
      remaining >>= LIMB_BITS;
    }

    return { modulus, redc };
  }

  function createMockJwt(
    claims: Record<string, unknown>,
    privateKey: string,
    kid: string
  ): string {
    const header = { alg: "RS256", typ: "JWT", kid };
    const headerB64 = Buffer.from(JSON.stringify(header))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const payloadB64 = Buffer.from(JSON.stringify(claims))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const signedData = `${headerB64}.${payloadB64}`;
    const sign = crypto.createSign("RSA-SHA256");
    sign.update(signedData);
    const signature = sign.sign(privateKey);
    const sigB64 = signature
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    return `${signedData}.${sigB64}`;
  }

  it("deploys JwksRegistry and ZkLogin", async () => {
    const registryPath = path.resolve(
      __dirname,
      "../../../registry/contracts/jwks_registry/target/jwks_registry-JwksRegistry.json"
    );
    const registryArtifact = loadArtifact(registryPath);
    registryContract = await Contract.deploy(
      wallet,
      registryArtifact,
      [userAddress, new Fr(0n), new Fr(0n), new Fr(0n)]
    ).send({ from: userAddress, fee: { paymentMethod } });

    expect(registryContract.address.isZero()).toBe(false);

    const zkLoginPath = path.resolve(
      __dirname,
      "../../contracts/zk_login/target/zk_login-ZkLogin.json"
    );
    const zkLoginArtifact = loadArtifact(zkLoginPath);
    zkLoginContract = await Contract.deploy(
      wallet,
      zkLoginArtifact,
      [registryContract.address]
    ).send({ from: userAddress, fee: { paymentMethod } });

    expect(zkLoginContract.address.isZero()).toBe(false);
  }, 600_000);

  it("populates JWK in registry", async () => {
    const { modulus, redc } = jwkModulusToLimbs(testKeyPair.jwk.n!);
    const kidHash = await computeKidHash(TEST_KID);

    await registryContract.methods
      .admin_set_jwk(
        new Fr(PROVIDER_GOOGLE),
        kidHash,
        modulus.map((l: bigint) => new Fr(l)),
        redc.map((l: bigint) => new Fr(l))
      )
      .send({ from: userAddress, fee: { paymentMethod } });
  }, 120_000);

  it("bind_account succeeds with real noir-jwt inputs", async () => {
    const kidHash = await computeKidHash(TEST_KID);

    // Compute nonce = pedersen_hash([sender, randomness])
    const randomness = Fr.random();
    const nonceHash = await pedersenHash([userAddress.toField(), randomness]);
    const nonceHex = "0x" + nonceHash.toBigInt().toString(16).padStart(64, "0");

    // Create JWT with the nonce
    const jwt = createMockJwt(
      {
        iss: "https://accounts.google.com",
        sub: "webapp-test-user-001",
        nonce: nonceHex,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      testKeyPair.privateKey,
      TEST_KID
    );

    // Generate circuit inputs via noir-jwt
    const inputs = await generateInputs({
      jwt,
      pubkey: testKeyPair.jwk,
      maxSignedDataLength: 1024,
    });

    const jwtBytes = inputs.data!.storage.slice(0, inputs.data!.len);

    // Call bind_account (use_public_fallback=true since key was just added)
    await zkLoginContract.methods
      .bind_account(
        jwtBytes,
        inputs.base64_decode_offset,
        inputs.pubkey_modulus_limbs.map((s: string) => BigInt(s)),
        inputs.redc_params_limbs.map((s: string) => BigInt(s)),
        inputs.signature_limbs.map((s: string) => BigInt(s)),
        new Fr(PROVIDER_GOOGLE),
        kidHash,
        randomness,
        true, // use_public_fallback
      )
      .send({ from: userAddress, fee: { paymentMethod } });

    // Verify is_address_bound
    const isBound = await zkLoginContract.methods
      .is_address_bound(userAddress)
      .simulate({ from: userAddress });

    expect(isBound).toBe(true);
  }, 600_000);

  it("duplicate bind_account attempt fails", async () => {
    const kidHash = await computeKidHash(TEST_KID);

    const randomness = Fr.random();
    const nonceHash = await pedersenHash([userAddress.toField(), randomness]);
    const nonceHex = "0x" + nonceHash.toBigInt().toString(16).padStart(64, "0");

    const jwt = createMockJwt(
      {
        iss: "https://accounts.google.com",
        sub: "webapp-test-user-001", // Same sub as above
        nonce: nonceHex,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      testKeyPair.privateKey,
      TEST_KID
    );

    const inputs = await generateInputs({
      jwt,
      pubkey: testKeyPair.jwk,
      maxSignedDataLength: 1024,
    });

    const jwtBytes = inputs.data!.storage.slice(0, inputs.data!.len);

    // Should fail — same identity already bound (duplicate nullifier)
    await expect(
      zkLoginContract.methods
        .bind_account(
          jwtBytes,
          inputs.base64_decode_offset,
          inputs.pubkey_modulus_limbs.map((s: string) => BigInt(s)),
          inputs.redc_params_limbs.map((s: string) => BigInt(s)),
          inputs.signature_limbs.map((s: string) => BigInt(s)),
          new Fr(PROVIDER_GOOGLE),
          kidHash,
          randomness,
          true, // use_public_fallback
        )
        .send({ from: userAddress, fee: { paymentMethod } })
    ).rejects.toThrow();
  }, 600_000);
});
