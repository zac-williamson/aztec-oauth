/**
 * Configuration loader for the JWKS Monitor.
 *
 * Reads environment variables, validates required fields,
 * and applies network-specific defaults.
 */

export interface PrimusConfig {
  appId: string;
  appSecret: string;
}

export interface Config {
  /** Target network: "local" (sandbox) or "devnet" */
  network: "local" | "devnet";
  /** Aztec node RPC URL */
  nodeUrl: string;
  /** Deployed JwksRegistry contract address */
  registryAddress: string;
  /** Update mode: "admin" (direct set) or "primus" (zkTLS attestation) */
  mode: "admin" | "primus";
  /** Admin secret key for deriving the Schnorr signer (required for admin mode) */
  adminSecretKey: string | undefined;
  /** SponsoredFPC contract address (auto-computed for local if omitted) */
  sponsoredFpcAddress: string | undefined;
  /** Polling interval in milliseconds */
  pollIntervalMs: number;
  /** Primus zkTLS credentials (required for primus mode) */
  primus: PrimusConfig | undefined;
}

const DEFAULT_LOCAL_NODE_URL = "http://localhost:8080";
const DEFAULT_DEVNET_NODE_URL = "https://v4-devnet-2.aztec-labs.com/";
const DEFAULT_POLL_INTERVAL_MS = 300_000; // 5 minutes

/**
 * Load and validate configuration from environment variables.
 *
 * Required env vars: REGISTRY_ADDRESS
 * Admin mode requires: ADMIN_SECRET_KEY
 * Primus mode requires: PRIMUS_APP_ID, PRIMUS_APP_SECRET
 * Optional env vars: NETWORK, AZTEC_NODE_URL, SPONSORED_FPC_ADDRESS, POLL_INTERVAL_MS, MODE
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const network = parseNetwork(env.NETWORK);
  const nodeUrl = env.AZTEC_NODE_URL || defaultNodeUrl(network);

  const registryAddress = env.REGISTRY_ADDRESS;
  if (!registryAddress) {
    throw new Error("REGISTRY_ADDRESS environment variable is required");
  }

  const mode = parseMode(env.MODE);

  const adminSecretKey = env.ADMIN_SECRET_KEY;
  if (mode === "admin" && !adminSecretKey) {
    throw new Error("ADMIN_SECRET_KEY environment variable is required in admin mode");
  }

  let primus: PrimusConfig | undefined;
  if (mode === "primus") {
    const appId = env.PRIMUS_APP_ID;
    const appSecret = env.PRIMUS_APP_SECRET;
    if (!appId || !appSecret) {
      throw new Error(
        "PRIMUS_APP_ID and PRIMUS_APP_SECRET environment variables are required in primus mode"
      );
    }
    primus = { appId, appSecret };
  }

  const sponsoredFpcAddress = env.SPONSORED_FPC_ADDRESS || undefined;

  const pollIntervalMs = env.POLL_INTERVAL_MS
    ? parseInt(env.POLL_INTERVAL_MS, 10)
    : DEFAULT_POLL_INTERVAL_MS;

  if (isNaN(pollIntervalMs) || pollIntervalMs <= 0) {
    throw new Error("POLL_INTERVAL_MS must be a positive integer");
  }

  return {
    network,
    nodeUrl,
    registryAddress,
    mode,
    adminSecretKey,
    sponsoredFpcAddress,
    pollIntervalMs,
    primus,
  };
}

function parseNetwork(value: string | undefined): "local" | "devnet" {
  if (!value || value === "local") return "local";
  if (value === "devnet") return "devnet";
  throw new Error(`Invalid NETWORK value: "${value}". Must be "local" or "devnet".`);
}

function parseMode(value: string | undefined): "admin" | "primus" {
  if (!value || value === "admin") return "admin";
  if (value === "primus") return "primus";
  throw new Error(`Invalid MODE value: "${value}". Must be "admin" or "primus".`);
}

function defaultNodeUrl(network: "local" | "devnet"): string {
  return network === "devnet" ? DEFAULT_DEVNET_NODE_URL : DEFAULT_LOCAL_NODE_URL;
}
