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
    modulusLimbs: overrides.modulusLimbs ?? Array(18).fill(42n),
    redcParamsLimbs: overrides.redcParamsLimbs ?? Array(18).fill(7n),
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
      modulus_limbs: Array(18).fill(0n),
      redc_params_limbs: Array(18).fill(0n),
    };

    const resultMap = new Map();
    resultMap.set(kidHash, onChainResult);
    const contract = mockContract(resultMap);

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.toAdd).toHaveLength(1);
    expect(diff.toAdd[0].kid).toBe("invalid-key");
  });

  it("classifies a key with all-zero limbs as needing addition", async () => {
    const kidHash = { toBigInt: () => 200n, toString: () => "200" };
    const key = makeKey({ kid: "zero-limbs", kidHash });

    const onChainResult = {
      is_valid: true,
      modulus_limbs: Array(18).fill(0n),
      redc_params_limbs: Array(18).fill(0n),
    };

    const resultMap = new Map();
    resultMap.set(kidHash, onChainResult);
    const contract = mockContract(resultMap);

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.toAdd).toHaveLength(1);
    expect(diff.toAdd[0].kid).toBe("zero-limbs");
  });

  it("classifies a changed key as needing update", async () => {
    const kidHash = { toBigInt: () => 300n, toString: () => "300" };
    const fetchedLimbs = Array(18).fill(42n);
    const onChainLimbs = Array(18).fill(99n); // Different!
    const key = makeKey({
      kid: "changed-key",
      kidHash,
      modulusLimbs: fetchedLimbs,
    });

    const onChainResult = {
      is_valid: true,
      modulus_limbs: onChainLimbs,
      redc_params_limbs: Array(18).fill(7n),
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
    const limbs = Array(18).fill(42n);
    const key = makeKey({ kid: "same-key", kidHash, modulusLimbs: limbs });

    const onChainResult = {
      is_valid: true,
      modulus_limbs: limbs.slice(), // Same values
      redc_params_limbs: Array(18).fill(7n),
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

  it("handles Fr-like limb values with toBigInt()", async () => {
    const kidHash = { toBigInt: () => 500n, toString: () => "500" };
    const fetchedLimbs = Array(18).fill(42n);
    const key = makeKey({ kid: "fr-limbs", kidHash, modulusLimbs: fetchedLimbs });

    // On-chain limbs returned as Fr-like objects
    const onChainLimbs = fetchedLimbs.map((v) => ({
      toBigInt: () => v,
      toString: () => v.toString(),
    }));

    const onChainResult = {
      is_valid: true,
      modulus_limbs: onChainLimbs,
      redc_params_limbs: Array(18).fill({ toBigInt: () => 7n }),
    };

    const resultMap = new Map();
    resultMap.set(kidHash, onChainResult);
    const contract = mockContract(resultMap);

    const diff = await diffKeys([key], contract, mockAddress);

    expect(diff.unchanged).toHaveLength(1);
    expect(diff.unchanged[0].kid).toBe("fr-limbs");
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
        modulusLimbs: Array(18).fill(11n),
      }),
      makeKey({
        kid: "same-key",
        kidHash: kidHash3,
        modulusLimbs: Array(18).fill(33n),
      }),
    ];

    const resultMap = new Map();
    // Key 1: not found (throws)
    // Key 2: different limbs
    resultMap.set(kidHash2, {
      is_valid: true,
      modulus_limbs: Array(18).fill(22n), // Different from 11n
      redc_params_limbs: Array(18).fill(7n),
    });
    // Key 3: same limbs
    resultMap.set(kidHash3, {
      is_valid: true,
      modulus_limbs: Array(18).fill(33n),
      redc_params_limbs: Array(18).fill(7n),
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
