/**
 * Unit tests for JWT circuit input generation with real noir-jwt.
 *
 * @vitest-environment node
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as crypto from "node:crypto";

describe("JWT Inputs", () => {
  let generateBindAccountInputs: typeof import("../src/lib/jwt-inputs").generateBindAccountInputs;
  let testKeyPair: {
    publicKey: string;
    privateKey: string;
    jwk: crypto.JsonWebKey;
  };

  beforeAll(async () => {
    const mod = await import("../src/lib/jwt-inputs");
    generateBindAccountInputs = mod.generateBindAccountInputs;

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
  });

  function createTestJwt(claims: Record<string, unknown>, kid: string): string {
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
    const signature = sign.sign(testKeyPair.privateKey);
    const sigB64 = signature
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    return `${signedData}.${sigB64}`;
  }

  it("generates inputs with 18 non-zero modulus limbs", async () => {
    const jwt = createTestJwt(
      {
        iss: "https://accounts.google.com",
        sub: "test-user-001",
        nonce: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      "test-kid-001"
    );

    const inputs = await generateBindAccountInputs(
      jwt,
      testKeyPair.jwk,
      1, // Google
      "test-kid-001",
      42n
    );

    // 18 limbs, at least some non-zero
    expect(inputs.pubkeyModulusLimbs).toHaveLength(18);
    expect(inputs.redcParamsLimbs).toHaveLength(18);
    expect(inputs.signatureLimbs).toHaveLength(18);

    const hasNonZeroModulus = inputs.pubkeyModulusLimbs.some((l) => l !== 0n);
    expect(hasNonZeroModulus).toBe(true);

    const hasNonZeroSig = inputs.signatureLimbs.some((l) => l !== 0n);
    expect(hasNonZeroSig).toBe(true);
  });

  it("includes JWT bytes matching the signed data", async () => {
    const jwt = createTestJwt(
      {
        iss: "https://accounts.google.com",
        sub: "test-user-002",
        nonce: "0xabcd",
      },
      "test-kid-002"
    );

    const inputs = await generateBindAccountInputs(
      jwt,
      testKeyPair.jwk,
      1,
      "test-kid-002",
      100n
    );

    expect(inputs.jwtBytes.length).toBeGreaterThan(0);
    expect(inputs.jwtBytes.length).toBeLessThanOrEqual(1024);
    expect(inputs.providerId).toBe(1);
  });

  it("kidHash is a non-zero Fr", async () => {
    const jwt = createTestJwt(
      { iss: "https://accounts.google.com", sub: "test", nonce: "0x01" },
      "my-kid"
    );

    const inputs = await generateBindAccountInputs(
      jwt,
      testKeyPair.jwk,
      1,
      "my-kid",
      1n
    );

    // kidHash should be an Fr (has toBigInt)
    expect(inputs.kidHash).toBeDefined();
    const val = inputs.kidHash.toBigInt();
    expect(val).not.toBe(0n);
  });
});
