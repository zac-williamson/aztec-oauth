/**
 * Integration test: Full binding flow using a real Google JWT and
 * real Google JWKS keys fetched from googleapis.com.
 *
 * Requires a running Aztec sandbox: `aztec start --sandbox`
 *
 * This test:
 * 1. Fetches the real Google JWKS signing key used to sign the JWT
 * 2. Verifies the JWT signature with Node.js crypto
 * 3. Deploys JwksRegistry + ZkLogin contracts
 * 4. Registers the real Google key in the on-chain registry
 * 5. Generates noir-jwt circuit inputs from the real JWT + real Google key
 * 6. Validates inputs are in the correct format for bind_account
 * 7. Calls bind_account with a test-signed JWT (using a test key also in registry)
 * 8. Verifies sybil resistance: same identity can't bind twice
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { generateInputs } from "noir-jwt";

// Real Google JWT obtained from OAuth flow on 2026-02-26
const REAL_GOOGLE_JWT =
  "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQyNzU0MDdjMzllODAzNmFhNzM1ZWIyYzE3YzU0ODc2MWNlZDZhNjQiLCJ0eXAiOiJKV1QifQ" +
  ".eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDg3NzU2NjI1MjI5LTRqOWRtYmJiZjk5Y3M5bjBvZWVwM3ZiMzg4NTRuMnNzLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTA4Nzc1NjYyNTIyOS00ajlkbWJiYmY5OWNzOW4wb2VlcDN2YjM4ODU0bjJzcy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjExMzc2MzkwNzk4MTE0ODA5NzM1NCIsIm5vbmNlIjoiMHgyM2YwMDA1ZDUwODhkZTAyNGY1YWM3ZGQ4ZTYwMTQ5MTg5N2RmNWFmYjBhNDZjYWM4NjA1YTM0N2RkOTExOWE5IiwibmJmIjoxNzcyMTI2Mjg5LCJpYXQiOjE3NzIxMjY1ODksImV4cCI6MTc3MjEzMDE4OSwianRpIjoiZWZiNmQ5MjAyOWVkNDc0MjIxOTU4YmYxM2NhNmI0NGQ4ZDZiZjk3ZSJ9" +
  ".ExdcXq54I-h8cPlEq0Og9c2gq8_K18t8QGADYxMRCkjlJXn4kyFMpeUW9HVMNqu_NM4-m5Rjnl6cbp78YhAW6tAUpCG_vQfDtLMhgs93OxXwDpdexS9U_zkQwNcPx-OqKhvk53NQD2qHvu6g2Al6DyvGkZSssGfLZdIzazuaFCYrpPAn4cgOFJnpdlHSov9kEEGo8B5DemJcy7KGGxUS_sP5bPWnZwFYGQcsMJtXkjCc5V69hzfSRwd_7A-bTgfTyUryA2jQIXm_9u5yTcURJ57AFggcV4C-xFAmRwXn1X88HhEEwpJ0noejQwGffJ4rJ8klKrOBT297K5oKhpWz3w";

const REAL_KID = "d275407c39e8036aa735eb2c17c548761ced6a64";
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const PROVIDER_GOOGLE = 1;

describe("Google JWT Flow Integration", () => {
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

  // Real Google JWK for the kid used in the JWT
  let googleJwk: crypto.JsonWebKey | null = null;

  // Test RSA key pair for bind_account (we can't sign with Google's private key)
  let testKeyPair: {
    publicKey: string;
    privateKey: string;
    jwk: crypto.JsonWebKey;
  };
  const TEST_KID = "google-flow-test-key";

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

    // Create node client + wallet
    const node = createAztecNodeClient("http://localhost:8080");
    await waitForNode(node);

    const { EmbeddedWallet } = await import("@aztec/wallets/embedded");
    wallet = await EmbeddedWallet.create(node, { ephemeral: true });

    const { SponsoredFeePaymentMethod } = await import("@aztec/aztec.js/fee");
    const { SponsoredFPCContract } = await import("@aztec/noir-contracts.js/SponsoredFPC");
    const fpcInstance = await getContractInstanceFromInstantiationParams(
      SponsoredFPCContract.artifact,
      { salt: new Fr(0) }
    );
    await wallet.registerContract(fpcInstance, SponsoredFPCContract.artifact);
    paymentMethod = new SponsoredFeePaymentMethod(fpcInstance.address);

    // Create + deploy user account
    const userAcctMgr = await wallet.createSchnorrAccount(
      Fr.random(), Fr.random(), GrumpkinScalar.random()
    );
    userAddress = userAcctMgr.address;
    const deployMethod = await userAcctMgr.getDeployMethod();
    await deployMethod.send({ from: AztecAddress.ZERO, fee: { paymentMethod } });
    await wallet.registerSender(userAddress, "user");

    // Generate test RSA key pair (for bind_account — can't sign with Google's private key)
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

  // --- Helpers ---

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

  // --- Tests ---

  it("fetches real Google JWKS key for the JWT's kid", async () => {
    const response = await fetch(GOOGLE_JWKS_URL);
    expect(response.ok).toBe(true);
    const jwks = await response.json();
    expect(jwks.keys).toBeDefined();
    expect(jwks.keys.length).toBeGreaterThan(0);

    googleJwk = jwks.keys.find((k: { kid: string }) => k.kid === REAL_KID) ?? null;

    // Google rotates keys — the kid from the JWT may no longer be active.
    // If the key is still available, we can verify the signature.
    // If not, we skip signature verification but still test input generation.
    if (googleJwk) {
      console.log(`Found Google JWK for kid=${REAL_KID}: kty=${googleJwk.kty}, alg=${googleJwk.alg}`);
      expect(googleJwk.kty).toBe("RSA");
      expect(googleJwk.n).toBeDefined();
      expect(googleJwk.e).toBe("AQAB"); // 65537
    } else {
      console.log(
        `Google key kid=${REAL_KID} has been rotated out. ` +
        `Signature verification will be skipped, but input generation is still tested.`
      );
    }
  });

  it("verifies real JWT signature with Google's public key", async () => {
    if (!googleJwk) {
      console.log("Skipping: Google key has been rotated out");
      return;
    }

    // Import the JWK as a Node.js public key
    const pubKey = crypto.createPublicKey({ key: googleJwk as crypto.JsonWebKey, format: "jwk" });

    // Split JWT into signed data + signature
    const parts = REAL_GOOGLE_JWT.split(".");
    expect(parts).toHaveLength(3);
    const signedData = `${parts[0]}.${parts[1]}`;
    const signatureB64 = parts[2]
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const signature = Buffer.from(signatureB64, "base64");

    // Verify RSA-SHA256 signature
    const verify = crypto.createVerify("RSA-SHA256");
    verify.update(signedData);
    const isValid = verify.verify(pubKey, signature);
    expect(isValid).toBe(true);

    console.log("Real Google JWT signature verified successfully");
  });

  it("parses real JWT and extracts expected fields", () => {
    const parts = REAL_GOOGLE_JWT.split(".");
    const header = JSON.parse(
      Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()
    );
    const payload = JSON.parse(
      Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()
    );

    expect(header.alg).toBe("RS256");
    expect(header.kid).toBe(REAL_KID);
    expect(header.typ).toBe("JWT");

    expect(payload.iss).toBe("https://accounts.google.com");
    expect(payload.sub).toBe("113763907981148097354");
    expect(payload.nonce).toMatch(/^0x[0-9a-f]{64}$/);
    expect(payload.aud).toContain("apps.googleusercontent.com");
  });

  it("generates noir-jwt circuit inputs from real Google JWT", async () => {
    // Use the real Google key if available, otherwise use a placeholder key
    // (signature verification will fail in the circuit, but we're testing input FORMAT)
    const keyToUse = googleJwk ?? testKeyPair.jwk;

    const inputs = await generateInputs({
      jwt: REAL_GOOGLE_JWT,
      pubkey: keyToUse,
      maxSignedDataLength: 1024,
    });

    // Validate structure
    expect(inputs.data).toBeDefined();
    expect(inputs.data!.storage).toBeDefined();
    expect(inputs.data!.len).toBeGreaterThan(0);
    expect(inputs.data!.len).toBeLessThanOrEqual(1024);

    expect(inputs.pubkey_modulus_limbs).toHaveLength(18);
    expect(inputs.redc_params_limbs).toHaveLength(18);
    expect(inputs.signature_limbs).toHaveLength(18);

    // All limbs should be parseable as bigint and within u128 range
    const U128_MAX = (1n << 128n) - 1n;
    for (const limb of inputs.pubkey_modulus_limbs) {
      const val = BigInt(limb);
      expect(val).toBeLessThanOrEqual(U128_MAX);
    }
    for (const limb of inputs.signature_limbs) {
      const val = BigInt(limb);
      expect(val).toBeLessThanOrEqual(U128_MAX);
    }

    // JWT bytes should contain the signed data (header.payload as ASCII bytes)
    const jwtBytes = inputs.data!.storage.slice(0, inputs.data!.len);
    const signedDataStr = REAL_GOOGLE_JWT.split(".").slice(0, 2).join(".");
    const expectedBytes = Array.from(Buffer.from(signedDataStr, "ascii"));
    expect(jwtBytes).toEqual(expectedBytes);

    console.log(`Circuit inputs generated: ${jwtBytes.length} JWT bytes, offset=${inputs.base64_decode_offset}`);
  });

  it("Google key modulus decomposes to valid 18×120-bit limbs", async () => {
    if (!googleJwk) {
      console.log("Skipping: Google key has been rotated out");
      return;
    }

    const { modulus, redc } = jwkModulusToLimbs(googleJwk.n!);

    expect(modulus).toHaveLength(18);
    expect(redc).toHaveLength(18);

    // Each limb must fit in 120 bits (< 2^120)
    const LIMB_MAX = (1n << 120n) - 1n;
    for (const limb of modulus) {
      expect(limb).toBeLessThanOrEqual(LIMB_MAX);
      expect(limb).toBeGreaterThanOrEqual(0n);
    }
    for (const limb of redc) {
      expect(limb).toBeLessThanOrEqual(LIMB_MAX);
      expect(limb).toBeGreaterThanOrEqual(0n);
    }

    // Reconstruct modulus from limbs and verify it's a 2048-bit number
    let reconstructed = 0n;
    for (let i = 17; i >= 0; i--) {
      reconstructed = (reconstructed << 120n) | modulus[i];
    }
    expect(reconstructed).toBeGreaterThan(1n << 2047n);
    expect(reconstructed).toBeLessThan(1n << 2048n);

    // noir-jwt and our jwkModulusToLimbs should produce identical decompositions
    const noirInputs = await generateInputs({
      jwt: REAL_GOOGLE_JWT,
      pubkey: googleJwk,
      maxSignedDataLength: 1024,
    });
    for (let i = 0; i < 18; i++) {
      expect(modulus[i]).toBe(BigInt(noirInputs.pubkey_modulus_limbs[i]));
      expect(redc[i]).toBe(BigInt(noirInputs.redc_params_limbs[i]));
    }

    console.log("Google key limb decomposition matches noir-jwt exactly");
  });

  it("deploys JwksRegistry and ZkLogin with real Google key", async () => {
    // Deploy registry
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

    // Deploy ZkLogin
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

    // Register real Google key (if available)
    if (googleJwk) {
      const { modulus, redc } = jwkModulusToLimbs(googleJwk.n!);
      const kidHash = await computeKidHash(REAL_KID);

      await registryContract.methods
        .admin_set_jwk(
          new Fr(PROVIDER_GOOGLE),
          kidHash,
          modulus.map((l: bigint) => new Fr(l)),
          redc.map((l: bigint) => new Fr(l))
        )
        .send({ from: userAddress, fee: { paymentMethod } });

      console.log(`Real Google key kid=${REAL_KID} registered in on-chain registry`);

      // Verify key can be read back
      const storedJwk = await registryContract.methods
        .get_jwk(new Fr(PROVIDER_GOOGLE), kidHash)
        .simulate({ from: userAddress });
      expect(storedJwk.is_valid).toBe(true);
    }

    // Also register test key for bind_account
    const { modulus: testMod, redc: testRedc } = jwkModulusToLimbs(testKeyPair.jwk.n!);
    const testKidHash = await computeKidHash(TEST_KID);

    await registryContract.methods
      .admin_set_jwk(
        new Fr(PROVIDER_GOOGLE),
        testKidHash,
        testMod.map((l: bigint) => new Fr(l)),
        testRedc.map((l: bigint) => new Fr(l))
      )
      .send({ from: userAddress, fee: { paymentMethod } });
  }, 600_000);

  it("bind_account succeeds with test JWT + on-chain registry lookup", async () => {
    const testKidHash = await computeKidHash(TEST_KID);

    // Compute nonce = pedersen_hash([sender, randomness])
    const randomness = Fr.random();
    const nonceHash = await pedersenHash([userAddress.toField(), randomness]);
    const nonceHex = "0x" + nonceHash.toBigInt().toString(16).padStart(64, "0");

    // Create JWT with nonce bound to our address (signed with our test key)
    const jwt = createMockJwt(
      {
        iss: "https://accounts.google.com",
        sub: "113763907981148097354", // Same sub as the real Google JWT
        nonce: nonceHex,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      testKeyPair.privateKey,
      TEST_KID
    );

    // Generate circuit inputs
    const inputs = await generateInputs({
      jwt,
      pubkey: testKeyPair.jwk,
      maxSignedDataLength: 1024,
    });
    const jwtBytes = inputs.data!.storage.slice(0, inputs.data!.len);

    // Call bind_account
    await zkLoginContract.methods
      .bind_account(
        jwtBytes,
        inputs.base64_decode_offset,
        inputs.pubkey_modulus_limbs.map((s: string) => BigInt(s)),
        inputs.redc_params_limbs.map((s: string) => BigInt(s)),
        inputs.signature_limbs.map((s: string) => BigInt(s)),
        new Fr(PROVIDER_GOOGLE),
        testKidHash,
        randomness
      )
      .send({ from: userAddress, fee: { paymentMethod } });

    // Verify binding
    const isBound = await zkLoginContract.methods
      .is_address_bound(userAddress)
      .simulate({ from: userAddress });
    expect(isBound).toBe(true);

    console.log("bind_account succeeded — identity bound to", userAddress.toString());
  }, 600_000);

  it("sybil resistance: same identity cannot bind to a different address", async () => {
    // Create a second user account
    const user2AcctMgr = await wallet.createSchnorrAccount(
      Fr.random(), Fr.random(), GrumpkinScalar.random()
    );
    const user2Address = user2AcctMgr.address;
    const deployMethod = await user2AcctMgr.getDeployMethod();
    await deployMethod.send({ from: AztecAddress.ZERO, fee: { paymentMethod } });
    await wallet.registerSender(user2Address, "user2");

    const testKidHash = await computeKidHash(TEST_KID);

    // Compute nonce for the second user
    const randomness = Fr.random();
    const nonceHash = await pedersenHash([user2Address.toField(), randomness]);
    const nonceHex = "0x" + nonceHash.toBigInt().toString(16).padStart(64, "0");

    // Create JWT with same sub (same Google identity) but nonce for user2
    const jwt = createMockJwt(
      {
        iss: "https://accounts.google.com",
        sub: "113763907981148097354", // Same sub = same identity
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

    // Should fail — identity nullifier already exists from previous bind
    await expect(
      zkLoginContract.methods
        .bind_account(
          jwtBytes,
          inputs.base64_decode_offset,
          inputs.pubkey_modulus_limbs.map((s: string) => BigInt(s)),
          inputs.redc_params_limbs.map((s: string) => BigInt(s)),
          inputs.signature_limbs.map((s: string) => BigInt(s)),
          new Fr(PROVIDER_GOOGLE),
          testKidHash,
          randomness
        )
        .send({ from: user2Address, fee: { paymentMethod } })
    ).rejects.toThrow();

    console.log("Sybil resistance verified — duplicate identity binding rejected");
  }, 600_000);
});
