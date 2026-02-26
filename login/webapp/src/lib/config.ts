/**
 * App configuration from Vite environment variables.
 */

export interface AppConfig {
  network: "local" | "devnet";
  nodeUrl: string;
  registryAddress: string;
  zkLoginAddress: string;
  sponsoredFpcAddress: string | undefined;
  googleClientId: string;
  appleClientId: string;
}

const DEVNET_NODE_URL = "https://v4-devnet-2.aztec-labs.com/";
const LOCAL_NODE_URL = "http://localhost:8080";
const DEVNET_FPC_ADDRESS =
  "0x09a4df73aa47f82531a038d1d51abfc85b27665c4b7ca751e2d4fa9f19caffb2";

export function loadConfig(): AppConfig {
  const env = import.meta.env;
  const network = (env.VITE_NETWORK || "local") as "local" | "devnet";

  const defaultNodeUrl = network === "devnet" ? DEVNET_NODE_URL : LOCAL_NODE_URL;
  const defaultFpc = network === "devnet" ? DEVNET_FPC_ADDRESS : undefined;

  return {
    network,
    nodeUrl: env.VITE_AZTEC_NODE_URL || defaultNodeUrl,
    registryAddress: env.VITE_REGISTRY_ADDRESS || "",
    zkLoginAddress: env.VITE_ZK_LOGIN_ADDRESS || "",
    sponsoredFpcAddress: env.VITE_SPONSORED_FPC_ADDRESS || defaultFpc,
    googleClientId: env.VITE_GOOGLE_CLIENT_ID || "",
    appleClientId: env.VITE_APPLE_CLIENT_ID || "",
  };
}
