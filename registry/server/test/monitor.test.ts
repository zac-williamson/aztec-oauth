/**
 * Unit tests for monitor.ts (JwksMonitor)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { JwksMonitor, type MonitorDeps, type ProviderConfig } from "../src/monitor.js";
import type { ProcessedKey } from "../src/jwks-fetcher.js";
import type { DiffResult } from "../src/key-differ.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeKey(kid: string, providerId = 1): ProcessedKey {
  return {
    kid,
    kidHash: { toBigInt: () => BigInt(kid.length) },
    providerId,
    modulusLimbs: Array(18).fill(42n),
    redcParamsLimbs: Array(18).fill(7n),
  };
}

function createMockDeps(overrides: Partial<MonitorDeps> = {}): MonitorDeps {
  return {
    contract: {},
    adminAddress: { toString: () => "0xadmin" },
    paymentMethod: {},
    pollIntervalMs: 60_000,
    providers: overrides.providers ?? [
      { providerId: 1, name: "Google", jwksUrl: "https://google.test/certs" },
      { providerId: 2, name: "Apple", jwksUrl: "https://apple.test/keys" },
    ],
    fetchKeys: overrides.fetchKeys ?? vi.fn().mockResolvedValue([]),
    diffFn:
      overrides.diffFn ??
      vi.fn().mockResolvedValue({ toAdd: [], toUpdate: [], unchanged: [] }),
    submitFn: overrides.submitFn ?? vi.fn().mockResolvedValue(undefined),
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("JwksMonitor", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("calls fetcher for each provider during poll", async () => {
    const fetchKeys = vi.fn().mockResolvedValue([]);
    const deps = createMockDeps({ fetchKeys });
    const monitor = new JwksMonitor(deps);

    await monitor.poll();

    expect(fetchKeys).toHaveBeenCalledTimes(2);
    expect(fetchKeys).toHaveBeenCalledWith(1, "https://google.test/certs");
    expect(fetchKeys).toHaveBeenCalledWith(2, "https://apple.test/keys");
  });

  it("calls differ with all fetched keys", async () => {
    const googleKey = makeKey("google-key-1", 1);
    const appleKey = makeKey("apple-key-1", 2);

    const fetchKeys = vi
      .fn()
      .mockResolvedValueOnce([googleKey])
      .mockResolvedValueOnce([appleKey]);

    const diffFn = vi
      .fn()
      .mockResolvedValue({ toAdd: [], toUpdate: [], unchanged: [googleKey, appleKey] });

    const deps = createMockDeps({ fetchKeys, diffFn });
    const monitor = new JwksMonitor(deps);

    await monitor.poll();

    expect(diffFn).toHaveBeenCalledTimes(1);
    const calledKeys = diffFn.mock.calls[0][0] as ProcessedKey[];
    expect(calledKeys).toHaveLength(2);
    expect(calledKeys[0].kid).toBe("google-key-1");
    expect(calledKeys[1].kid).toBe("apple-key-1");
  });

  it("does not call submitter when no changes", async () => {
    const key = makeKey("unchanged-key");
    const fetchKeys = vi.fn().mockResolvedValue([key]);
    const diffFn = vi
      .fn()
      .mockResolvedValue({ toAdd: [], toUpdate: [], unchanged: [key] });
    const submitFn = vi.fn().mockResolvedValue(undefined);

    const deps = createMockDeps({ fetchKeys, diffFn, submitFn });
    const monitor = new JwksMonitor(deps);

    await monitor.poll();

    expect(submitFn).not.toHaveBeenCalled();
  });

  it("calls submitter for new keys", async () => {
    const newKey = makeKey("new-key");
    const fetchKeys = vi.fn().mockResolvedValue([newKey]);
    const diffFn = vi
      .fn()
      .mockResolvedValue({ toAdd: [newKey], toUpdate: [], unchanged: [] });
    const submitFn = vi.fn().mockResolvedValue(undefined);

    const deps = createMockDeps({ fetchKeys, diffFn, submitFn });
    const monitor = new JwksMonitor(deps);

    await monitor.poll();

    expect(submitFn).toHaveBeenCalledTimes(1);
    expect(submitFn).toHaveBeenCalledWith(
      deps.contract,
      deps.adminAddress,
      deps.paymentMethod,
      newKey
    );
  });

  it("calls submitter for updated keys", async () => {
    const updatedKey = makeKey("updated-key");
    const fetchKeys = vi.fn().mockResolvedValue([updatedKey]);
    const diffFn = vi
      .fn()
      .mockResolvedValue({ toAdd: [], toUpdate: [updatedKey], unchanged: [] });
    const submitFn = vi.fn().mockResolvedValue(undefined);

    const deps = createMockDeps({ fetchKeys, diffFn, submitFn });
    const monitor = new JwksMonitor(deps);

    await monitor.poll();

    expect(submitFn).toHaveBeenCalledTimes(1);
    expect(submitFn).toHaveBeenCalledWith(
      deps.contract,
      deps.adminAddress,
      deps.paymentMethod,
      updatedKey
    );
  });

  it("calls submitter for both new and updated keys", async () => {
    const newKey = makeKey("new-key");
    const updatedKey = makeKey("updated-key");
    const fetchKeys = vi.fn().mockResolvedValue([newKey, updatedKey]);
    const diffFn = vi.fn().mockResolvedValue({
      toAdd: [newKey],
      toUpdate: [updatedKey],
      unchanged: [],
    });
    const submitFn = vi.fn().mockResolvedValue(undefined);

    const deps = createMockDeps({ fetchKeys, diffFn, submitFn });
    const monitor = new JwksMonitor(deps);

    await monitor.poll();

    expect(submitFn).toHaveBeenCalledTimes(2);
  });

  it("prevents concurrent polls via mutex", async () => {
    let resolveFirstPoll: () => void;
    const firstPollPromise = new Promise<void>((resolve) => {
      resolveFirstPoll = resolve;
    });

    let fetchCallCount = 0;
    const fetchKeys = vi.fn().mockImplementation(async () => {
      fetchCallCount++;
      if (fetchCallCount === 1) {
        // First call: block until we release
        await firstPollPromise;
      }
      return [];
    });

    const deps = createMockDeps({ fetchKeys });
    const monitor = new JwksMonitor(deps);

    // Start first poll (will block on fetchKeys)
    const poll1 = monitor.poll();

    // Try second poll while first is blocked
    const poll2 = monitor.poll();

    // Second poll should return immediately (mutex)
    await poll2;

    // fetchKeys was called twice for poll1 (Google + Apple), but poll2 was skipped
    // At this point fetchKeys has been called once (Google, which is blocking)
    // Let's release the block
    resolveFirstPoll!();
    await poll1;

    // fetchKeys should have been called only for the first poll's providers (2 calls)
    expect(fetchKeys).toHaveBeenCalledTimes(2);
  });

  it("continues polling after a fetch error", async () => {
    const fetchKeys = vi
      .fn()
      .mockRejectedValueOnce(new Error("Network error"))
      .mockResolvedValueOnce([]);

    const diffFn = vi
      .fn()
      .mockResolvedValue({ toAdd: [], toUpdate: [], unchanged: [] });

    const deps = createMockDeps({
      fetchKeys,
      diffFn,
      providers: [
        { providerId: 1, name: "Google", jwksUrl: "https://google.test/certs" },
      ],
    });
    const monitor = new JwksMonitor(deps);

    // First poll: fetch fails, but poll completes without throwing
    await monitor.poll();

    // Diff should not have been called (no keys fetched)
    expect(diffFn).not.toHaveBeenCalled();
  });

  it("continues polling after a submit error", async () => {
    const newKey1 = makeKey("key-1");
    const newKey2 = makeKey("key-2");

    const fetchKeys = vi.fn().mockResolvedValue([newKey1, newKey2]);
    const diffFn = vi.fn().mockResolvedValue({
      toAdd: [newKey1, newKey2],
      toUpdate: [],
      unchanged: [],
    });

    let submitCallCount = 0;
    const submitFn = vi.fn().mockImplementation(async () => {
      submitCallCount++;
      if (submitCallCount === 1) throw new Error("Submit failed");
    });

    const deps = createMockDeps({
      fetchKeys,
      diffFn,
      submitFn,
      providers: [
        { providerId: 1, name: "Google", jwksUrl: "https://google.test/certs" },
      ],
    });
    const monitor = new JwksMonitor(deps);

    // Should not throw even though first submit fails
    await monitor.poll();

    // Both keys should have been attempted
    expect(submitFn).toHaveBeenCalledTimes(2);
  });

  it("start() triggers an immediate poll", async () => {
    const fetchKeys = vi.fn().mockResolvedValue([]);
    const deps = createMockDeps({ fetchKeys });
    const monitor = new JwksMonitor(deps);

    monitor.start();

    // Let the microtask queue flush
    await vi.advanceTimersByTimeAsync(0);

    expect(fetchKeys).toHaveBeenCalled();

    monitor.stop();
  });

  it("stop() clears the interval", () => {
    const deps = createMockDeps();
    const monitor = new JwksMonitor(deps);

    monitor.start();
    monitor.stop();

    // After stop, no more polls should fire
    const fetchKeys = deps.fetchKeys as ReturnType<typeof vi.fn>;
    const callsBefore = fetchKeys.mock.calls.length;

    vi.advanceTimersByTime(deps.pollIntervalMs * 3);

    // Call count should not have increased (except maybe the initial call)
    expect(fetchKeys.mock.calls.length).toBe(callsBefore);
  });
});
