/**
 * Configuration loader for the JWKS Monitor.
 *
 * Reads environment variables, validates required fields,
 * and applies network-specific defaults.
 */

export interface Config {
  /** Target network: "local" (sandbox) or "devnet" */
  network: "local" | "devnet";
  /** Aztec node RPC URL */
  nodeUrl: string;
  /** Deployed JwksRegistry contract address */
  registryAddress: string;
  /** Admin secret key for deriving the Schnorr signer */
  adminSecretKey: string;
  /** SponsoredFPC contract address (auto-computed for local if omitted) */
  sponsoredFpcAddress: string | undefined;
  /** Polling interval in milliseconds */
  pollIntervalMs: number;
}

const DEFAULT_LOCAL_NODE_URL = "http://localhost:8080";
const DEFAULT_DEVNET_NODE_URL = "https://v4-devnet-2.aztec-labs.com/";
const DEFAULT_POLL_INTERVAL_MS = 300_000; // 5 minutes

/**
 * Load and validate configuration from environment variables.
 *
 * Required env vars: REGISTRY_ADDRESS, ADMIN_SECRET_KEY
 * Optional env vars: NETWORK, AZTEC_NODE_URL, SPONSORED_FPC_ADDRESS, POLL_INTERVAL_MS
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const network = parseNetwork(env.NETWORK);
  const nodeUrl = env.AZTEC_NODE_URL || defaultNodeUrl(network);

  const registryAddress = env.REGISTRY_ADDRESS;
  if (!registryAddress) {
    throw new Error("REGISTRY_ADDRESS environment variable is required");
  }

  const adminSecretKey = env.ADMIN_SECRET_KEY;
  if (!adminSecretKey) {
    throw new Error("ADMIN_SECRET_KEY environment variable is required");
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
    adminSecretKey,
    sponsoredFpcAddress,
    pollIntervalMs,
  };
}

function parseNetwork(value: string | undefined): "local" | "devnet" {
  if (!value || value === "local") return "local";
  if (value === "devnet") return "devnet";
  throw new Error(`Invalid NETWORK value: "${value}". Must be "local" or "devnet".`);
}

function defaultNodeUrl(network: "local" | "devnet"): string {
  return network === "devnet" ? DEFAULT_DEVNET_NODE_URL : DEFAULT_LOCAL_NODE_URL;
}
