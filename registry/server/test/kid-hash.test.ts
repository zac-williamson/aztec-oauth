/**
 * Unit tests for kid-hash.ts (Pedersen kid hash computation)
 */

import { describe, it, expect } from "vitest";
import { computeKidHash } from "../src/kid-hash.js";

describe("computeKidHash", () => {
  it("produces a deterministic hash for the same kid", async () => {
    const hash1 = await computeKidHash("abc123");
    const hash2 = await computeKidHash("abc123");

    const val1 = hash1.toBigInt ? hash1.toBigInt() : BigInt(hash1);
    const val2 = hash2.toBigInt ? hash2.toBigInt() : BigInt(hash2);

    expect(val1).toBe(val2);
  });

  it("produces different hashes for different kids", async () => {
    const hash1 = await computeKidHash("key-001");
    const hash2 = await computeKidHash("key-002");

    const val1 = hash1.toBigInt ? hash1.toBigInt() : BigInt(hash1);
    const val2 = hash2.toBigInt ? hash2.toBigInt() : BigInt(hash2);

    expect(val1).not.toBe(val2);
  });

  it("produces a non-zero hash", async () => {
    const hash = await computeKidHash("test-key-abc");
    const val = hash.toBigInt ? hash.toBigInt() : BigInt(hash);
    expect(val).not.toBe(0n);
  });

  it("produces a hash within the BN254 scalar field", async () => {
    // BN254 scalar field order
    const fieldOrder =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;

    const hash = await computeKidHash("some-google-kid-value");
    const val = hash.toBigInt ? hash.toBigInt() : BigInt(hash);
    expect(val).toBeGreaterThan(0n);
    expect(val).toBeLessThan(fieldOrder);
  });

  it("handles typical Google/Apple kid strings", async () => {
    // Google kids are typically ~40 chars hex-like
    const googleHash = await computeKidHash(
      "f5f4a3cd8c8b3a1e2d4f6a8b0c2e4f6a8b0d2e4f"
    );
    // Apple kids are typically short alphanumeric
    const appleHash = await computeKidHash("W6WcOKB");

    const gVal = googleHash.toBigInt ? googleHash.toBigInt() : BigInt(googleHash);
    const aVal = appleHash.toBigInt ? appleHash.toBigInt() : BigInt(appleHash);

    expect(gVal).not.toBe(0n);
    expect(aVal).not.toBe(0n);
    expect(gVal).not.toBe(aVal);
  });
});
