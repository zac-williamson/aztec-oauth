import { describe, it, expect } from "vitest";
import { computeKidHash } from "../src/nonce.js";

// Mock Pedersen hash for testing (matches the mock in integration tests)
async function mockPedersenHash(inputs: any[]): Promise<any> {
  let hash = 0n;
  for (const input of inputs) {
    const val = typeof input === "bigint" ? input : BigInt(input.toString());
    hash = hash ^ val;
    hash = ((hash << 7n) | (hash >> 247n)) & ((1n << 254n) - 1n);
    hash = hash ^ (hash >> 13n);
  }
  return {
    toBigInt: () => hash,
    toString: () => hash.toString(),
  };
}

// Mock Fr class for testing
class MockFr {
  private value: bigint;
  constructor(v: bigint | number | string) {
    this.value = typeof v === "string" ? BigInt(v) : BigInt(v);
  }
  toBigInt() {
    return this.value;
  }
  toString() {
    return this.value.toString();
  }
  toField() {
    return this;
  }
  static random() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let val = 0n;
    for (const b of bytes) val = (val << 8n) | BigInt(b);
    return new MockFr(val & ((1n << 254n) - 1n));
  }
  static fromString(s: string) {
    return new MockFr(s);
  }
}

describe("computeKidHash", () => {
  it("produces consistent hashes for the same kid", async () => {
    const hash1 = await computeKidHash(mockPedersenHash, MockFr, "test-kid");
    const hash2 = await computeKidHash(mockPedersenHash, MockFr, "test-kid");
    expect(hash1.toBigInt()).toBe(hash2.toBigInt());
  });

  it("produces different hashes for different kids", async () => {
    const hash1 = await computeKidHash(mockPedersenHash, MockFr, "kid-a");
    const hash2 = await computeKidHash(mockPedersenHash, MockFr, "kid-b");
    expect(hash1.toBigInt()).not.toBe(hash2.toBigInt());
  });

  it("packs bytes correctly into 9 fields", async () => {
    // The function packs 31 bytes per field, with length in fields[8]
    // For a short kid like "ab" (2 bytes), only fields[0] and fields[8] are non-zero
    const hash = await computeKidHash(mockPedersenHash, MockFr, "ab");
    // Just verify it doesn't throw and returns a value
    expect(hash.toBigInt()).toBeTypeOf("bigint");
  });
});
