/**
 * Registry Script Unit Tests
 *
 * Tests the JWK transformation logic without requiring an Aztec sandbox.
 */

import { describe, it, expect } from "vitest";
import {
  base64UrlDecode,
  bytesToBigInt,
  splitBigIntToLimbs,
  computeRedcParams,
  jwkModulusToLimbs,
  computeKidHash,
  processJwkKey,
} from "../src/jwk-transform.js";

describe("base64UrlDecode", () => {
  it("decodes a simple Base64URL string", () => {
    // "test" in base64url = "dGVzdA"
    const decoded = base64UrlDecode("dGVzdA");
    expect(Buffer.from(decoded).toString("utf-8")).toBe("test");
  });

  it("handles Base64URL characters (- and _)", () => {
    // Standard base64 would use + and /
    const decoded = base64UrlDecode("ab-c_d");
    expect(decoded).toBeInstanceOf(Uint8Array);
  });
});

describe("bytesToBigInt", () => {
  it("converts bytes to BigInt (big-endian)", () => {
    const bytes = new Uint8Array([0x01, 0x00]);
    expect(bytesToBigInt(bytes)).toBe(256n);
  });

  it("handles single byte", () => {
    expect(bytesToBigInt(new Uint8Array([0xff]))).toBe(255n);
  });

  it("handles empty array", () => {
    expect(bytesToBigInt(new Uint8Array([]))).toBe(0n);
  });
});

describe("splitBigIntToLimbs", () => {
  it("splits a value into 120-bit limbs", () => {
    const value = (1n << 240n) + 42n;
    const limbs = splitBigIntToLimbs(value, 120n, 3);
    expect(limbs).toHaveLength(3);
    expect(limbs[0]).toBe(42n); // least significant
    expect(limbs[1]).toBe(0n);
    expect(limbs[2]).toBe(1n); // most significant
  });

  it("throws if value is too large for the number of limbs", () => {
    expect(() => splitBigIntToLimbs(1n << 240n, 120n, 1)).toThrow();
  });

  it("produces exactly 18 limbs for a 2048-bit value", () => {
    const value = (1n << 2047n) + 1n; // A 2048-bit number
    const limbs = splitBigIntToLimbs(value, 120n, 18);
    expect(limbs).toHaveLength(18);
    // Reconstruct and verify
    let reconstructed = 0n;
    for (let i = 17; i >= 0; i--) {
      reconstructed = (reconstructed << 120n) | limbs[i];
    }
    expect(reconstructed).toBe(value);
  });
});

describe("computeRedcParams", () => {
  it("computes Barrett reduction parameters (OVERFLOW_BITS=6)", () => {
    // redc_param = floor(2^(2*2048+6) / modulus) = floor(2^4102 / modulus)
    const modulus = (1n << 2047n) + 1n;
    const redc = computeRedcParams(modulus);
    expect(redc > 0n).toBe(true);
    // redc * modulus should be close to 2^4102
    const product = redc * modulus;
    const target = 1n << 4102n;
    // product <= target < product + modulus
    expect(product <= target).toBe(true);
    expect(target < product + modulus).toBe(true);
  });
});

describe("jwkModulusToLimbs", () => {
  it("converts a Base64URL modulus to 18 limbs + redc params", () => {
    // Create a synthetic 2048-bit RSA modulus (256 bytes)
    // In real usage, this would come from a JWK 'n' field
    const modulusBytes = new Uint8Array(256);
    modulusBytes[0] = 0xc0; // Set high bit to ensure 2048-bit
    modulusBytes[255] = 0x01; // Set low bit to ensure odd (as RSA moduli are)
    // Convert to Base64URL
    const base64url = Buffer.from(modulusBytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const { modulusLimbs, redcParamsLimbs, modulusBigInt } =
      jwkModulusToLimbs(base64url);

    expect(modulusLimbs).toHaveLength(18);
    expect(redcParamsLimbs).toHaveLength(18);
    expect(modulusBigInt > 0n).toBe(true);

    // Verify reconstruction
    let reconstructed = 0n;
    for (let i = 17; i >= 0; i--) {
      reconstructed = (reconstructed << 120n) | modulusLimbs[i];
    }
    expect(reconstructed).toBe(modulusBigInt);
  });
});

describe("computeKidHash", () => {
  it("produces a consistent hash for the same kid", async () => {
    const hash1 = await computeKidHash("test-kid-123");
    const hash2 = await computeKidHash("test-kid-123");
    expect(hash1).toBe(hash2);
  });

  it("produces different hashes for different kids", async () => {
    const hash1 = await computeKidHash("kid-a");
    const hash2 = await computeKidHash("kid-b");
    expect(hash1).not.toBe(hash2);
  });
});

describe("processJwkKey", () => {
  it("processes an RS256 key", async () => {
    // Synthetic RSA key in JWK format
    const modulusBytes = new Uint8Array(256);
    modulusBytes[0] = 0xc0;
    modulusBytes[255] = 0x01;
    const n = Buffer.from(modulusBytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const key = {
      kty: "RSA",
      kid: "test-kid",
      use: "sig",
      alg: "RS256",
      n,
      e: "AQAB", // 65537
    };

    const result = await processJwkKey(key);
    expect(result.kid).toBe("test-kid");
    expect(result.kidHash).toBeTypeOf("bigint");
    expect(result.modulusLimbs).toHaveLength(18);
    expect(result.redcParamsLimbs).toHaveLength(18);
  });

  it("rejects non-RSA keys", async () => {
    const key = {
      kty: "EC",
      kid: "ec-key",
      use: "sig",
      alg: "ES256",
      n: "",
      e: "",
    };

    await expect(processJwkKey(key)).rejects.toThrow("Unsupported key type");
  });
});
