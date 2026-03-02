/**
 * Unit tests for key-differ.ts
 */

import { describe, it, expect, vi } from "vitest";
import { diffKeys } from "../src/key-differ.js";
import type { ProcessedKey } from "../src/jwks-fetcher.js";

// Helper to create a mock ProcessedKey
function makeKey(overrides: Partial<ProcessedKey> = {}): ProcessedKey {
  return {
    kid: overrides.kid ?? "test-kid",
    kidHash: overrides.kidHash ?? { toBigInt: () => 123n },
    providerId: overrides.providerId ?? 1,
    modulusHash: overrides.modulusHash ?? [42n, 43n],
    modulusBase64Url: overrides.modulusBase64Url ?? "dGVzdA",
  };
}

/**
 * Create a mock contract that returns results based on a kidHash->result map.
 * Since readOnChainKey wraps providerId in new Fr(), we match by kidHash identity
 * which is the same object reference passed through from the ProcessedKey.
 */
function mockContract(
  resultMap: Map<any, any>
): any {
  return {
    methods: {
      get_jwk: (_providerId: any, kidHash: any) => ({
        simulate: async ({ from }: { from: any }) => {
          if (resultMap.has(kidHash)) return resultMap.get(kidHash);
          throw new Error("Key not found");
        },
      }),
    },
  };
}

describe("diffKeys", () => {
  const mockAddress = { toString: () => "0xadmin" };

  it("classifies a new key (on-chain returns null/error)", async () => {
    const key = makeKey({ kid: "new-key" });
    const contract = mockContract(new Map()); // Empty = all lookups fail

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.toAdd).toHaveLength(1);
    expect(diff.toAdd[0].kid).toBe("new-key");
    expect(diff.toUpdate).toHaveLength(0);
    expect(diff.unchanged).toHaveLength(0);
  });

  it("classifies a key with is_valid=false as needing addition", async () => {
    const kidHash = { toBigInt: () => 100n, toString: () => "100" };
    const key = makeKey({ kid: "invalid-key", kidHash });

    const onChainResult = {
      is_valid: false,
      modulus_hash: [0n, 0n],
    };

    const resultMap = new Map();
    resultMap.set(kidHash, onChainResult);
    const contract = mockContract(resultMap);

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.toAdd).toHaveLength(1);
    expect(diff.toAdd[0].kid).toBe("invalid-key");
  });

  it("classifies a key with all-zero hash as needing addition", async () => {
    const kidHash = { toBigInt: () => 200n, toString: () => "200" };
    const key = makeKey({ kid: "zero-hash", kidHash });

    const onChainResult = {
      is_valid: true,
      modulus_hash: [0n, 0n],
    };

    const resultMap = new Map();
    resultMap.set(kidHash, onChainResult);
    const contract = mockContract(resultMap);

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.toAdd).toHaveLength(1);
    expect(diff.toAdd[0].kid).toBe("zero-hash");
  });

  it("classifies a changed key as needing update", async () => {
    const kidHash = { toBigInt: () => 300n, toString: () => "300" };
    const key = makeKey({
      kid: "changed-key",
      kidHash,
      modulusHash: [42n, 43n],
    });

    const onChainResult = {
      is_valid: true,
      modulus_hash: [99n, 100n], // Different!
    };

    const resultMap = new Map();
    resultMap.set(kidHash, onChainResult);
    const contract = mockContract(resultMap);

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.toUpdate).toHaveLength(1);
    expect(diff.toUpdate[0].kid).toBe("changed-key");
    expect(diff.toAdd).toHaveLength(0);
    expect(diff.unchanged).toHaveLength(0);
  });

  it("classifies an unchanged key correctly", async () => {
    const kidHash = { toBigInt: () => 400n, toString: () => "400" };
    const key = makeKey({ kid: "same-key", kidHash, modulusHash: [42n, 43n] });

    const onChainResult = {
      is_valid: true,
      modulus_hash: [42n, 43n], // Same values
    };

    const resultMap = new Map();
    resultMap.set(kidHash, onChainResult);
    const contract = mockContract(resultMap);

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.unchanged).toHaveLength(1);
    expect(diff.unchanged[0].kid).toBe("same-key");
    expect(diff.toAdd).toHaveLength(0);
    expect(diff.toUpdate).toHaveLength(0);
  });

  it("handles Fr-like hash values with toBigInt()", async () => {
    const kidHash = { toBigInt: () => 500n, toString: () => "500" };
    const key = makeKey({ kid: "fr-hash", kidHash, modulusHash: [42n, 43n] });

    // On-chain hash returned as Fr-like objects
    const onChainResult = {
      is_valid: true,
      modulus_hash: [
        { toBigInt: () => 42n, toString: () => "42" },
        { toBigInt: () => 43n, toString: () => "43" },
      ],
    };

    const resultMap = new Map();
    resultMap.set(kidHash, onChainResult);
    const contract = mockContract(resultMap);

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.unchanged).toHaveLength(1);
    expect(diff.unchanged[0].kid).toBe("fr-hash");
  });

  it("handles a mix of new, changed, and unchanged keys", async () => {
    const kidHash1 = { toBigInt: () => 1n, toString: () => "1" };
    const kidHash2 = { toBigInt: () => 2n, toString: () => "2" };
    const kidHash3 = { toBigInt: () => 3n, toString: () => "3" };

    const keys = [
      makeKey({ kid: "new-key", kidHash: kidHash1 }),
      makeKey({
        kid: "changed-key",
        kidHash: kidHash2,
        modulusHash: [11n, 12n],
      }),
      makeKey({
        kid: "same-key",
        kidHash: kidHash3,
        modulusHash: [33n, 34n],
      }),
    ];

    const resultMap = new Map();
    // Key 1: not found (throws)
    // Key 2: different hash
    resultMap.set(kidHash2, {
      is_valid: true,
      modulus_hash: [22n, 23n], // Different from [11n, 12n]
    });
    // Key 3: same hash
    resultMap.set(kidHash3, {
      is_valid: true,
      modulus_hash: [33n, 34n],
    });

    const contract = mockContract(resultMap);
    const diff = await diffKeys(keys, contract, mockAddress);

    expect(diff.toAdd).toHaveLength(1);
    expect(diff.toAdd[0].kid).toBe("new-key");
    expect(diff.toUpdate).toHaveLength(1);
    expect(diff.toUpdate[0].kid).toBe("changed-key");
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.unchanged[0].kid).toBe("same-key");
  });
});
