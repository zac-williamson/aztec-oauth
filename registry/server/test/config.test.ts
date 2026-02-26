/**
 * Unit tests for config.ts
 */

import { describe, it, expect } from "vitest";
import { loadConfig } from "../src/config.js";

describe("loadConfig", () => {
  const validEnv = {
    NETWORK: "local",
    REGISTRY_ADDRESS: "0x1234abcd",
    ADMIN_SECRET_KEY: "0xdeadbeef",
  };

  it("parses a valid config with defaults", () => {
    const config = loadConfig(validEnv);
    expect(config.network).toBe("local");
    expect(config.nodeUrl).toBe("http://localhost:8080");
    expect(config.registryAddress).toBe("0x1234abcd");
    expect(config.adminSecretKey).toBe("0xdeadbeef");
    expect(config.sponsoredFpcAddress).toBeUndefined();
    expect(config.pollIntervalMs).toBe(300_000);
  });

  it("throws when REGISTRY_ADDRESS is missing", () => {
    const env = { ...validEnv, REGISTRY_ADDRESS: undefined };
    expect(() => loadConfig(env as any)).toThrow(
      "REGISTRY_ADDRESS environment variable is required"
    );
  });

  it("throws when ADMIN_SECRET_KEY is missing", () => {
    const env = { ...validEnv, ADMIN_SECRET_KEY: undefined };
    expect(() => loadConfig(env as any)).toThrow(
      "ADMIN_SECRET_KEY environment variable is required"
    );
  });

  it("defaults network to local when not set", () => {
    const env = { ...validEnv, NETWORK: undefined };
    const config = loadConfig(env as any);
    expect(config.network).toBe("local");
  });

  it("uses devnet default node URL", () => {
    const env = { ...validEnv, NETWORK: "devnet" };
    const config = loadConfig(env);
    expect(config.network).toBe("devnet");
    expect(config.nodeUrl).toBe("https://v4-devnet-2.aztec-labs.com/");
  });

  it("uses custom node URL when provided", () => {
    const env = { ...validEnv, AZTEC_NODE_URL: "http://custom:1234" };
    const config = loadConfig(env);
    expect(config.nodeUrl).toBe("http://custom:1234");
  });

  it("parses POLL_INTERVAL_MS", () => {
    const env = { ...validEnv, POLL_INTERVAL_MS: "60000" };
    const config = loadConfig(env);
    expect(config.pollIntervalMs).toBe(60_000);
  });

  it("throws for invalid POLL_INTERVAL_MS", () => {
    const env = { ...validEnv, POLL_INTERVAL_MS: "not-a-number" };
    expect(() => loadConfig(env)).toThrow(
      "POLL_INTERVAL_MS must be a positive integer"
    );
  });

  it("throws for negative POLL_INTERVAL_MS", () => {
    const env = { ...validEnv, POLL_INTERVAL_MS: "-1000" };
    expect(() => loadConfig(env)).toThrow(
      "POLL_INTERVAL_MS must be a positive integer"
    );
  });

  it("throws for invalid NETWORK value", () => {
    const env = { ...validEnv, NETWORK: "testnet" };
    expect(() => loadConfig(env)).toThrow(
      'Invalid NETWORK value: "testnet". Must be "local" or "devnet".'
    );
  });

  it("passes through SPONSORED_FPC_ADDRESS", () => {
    const env = { ...validEnv, SPONSORED_FPC_ADDRESS: "0xfpc123" };
    const config = loadConfig(env);
    expect(config.sponsoredFpcAddress).toBe("0xfpc123");
  });
});
