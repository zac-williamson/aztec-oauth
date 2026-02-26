/**
 * Unit tests for nonce generation with real Pedersen hash.
 */

import { describe, it, expect } from "vitest";

describe("Nonce", () => {
  // Lazy-load to avoid pulling in WASM at import time in CI
  let computeNonce: (address: string, randomness: bigint) => Promise<string>;
  let generateRandomness: () => bigint;

  it("loads nonce module", async () => {
    const mod = await import("../src/lib/nonce");
    computeNonce = mod.computeNonce;
    generateRandomness = mod.generateRandomness;
  });

  it("produces 0x-prefixed 64-char hex nonce", async () => {
    const nonce = await computeNonce(
      "0x0000000000000000000000000000000000000000000000000000000000001234",
      42n
    );
    expect(nonce).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("is deterministic for same inputs", async () => {
    const addr = "0x0000000000000000000000000000000000000000000000000000000000005678";
    const rand = 123456789n;
    const nonce1 = await computeNonce(addr, rand);
    const nonce2 = await computeNonce(addr, rand);
    expect(nonce1).toBe(nonce2);
  });

  it("different addresses produce different nonces", async () => {
    const rand = 999n;
    const nonce1 = await computeNonce(
      "0x0000000000000000000000000000000000000000000000000000000000001111",
      rand
    );
    const nonce2 = await computeNonce(
      "0x0000000000000000000000000000000000000000000000000000000000002222",
      rand
    );
    expect(nonce1).not.toBe(nonce2);
  });

  it("different randomness produces different nonces", async () => {
    const addr = "0x0000000000000000000000000000000000000000000000000000000000003333";
    const nonce1 = await computeNonce(addr, 1n);
    const nonce2 = await computeNonce(addr, 2n);
    expect(nonce1).not.toBe(nonce2);
  });

  it("generateRandomness returns a valid field element", () => {
    const rand = generateRandomness();
    expect(rand).toBeGreaterThan(0n);
    const FIELD_MODULUS =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    expect(rand).toBeLessThan(FIELD_MODULUS);
  });
});
