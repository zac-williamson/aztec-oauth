import type { Network, NetworkConfig } from "./types.js";

/**
 * Network-specific configuration.
 *
 * Contract addresses are populated after deployment.
 * The service URL points to the hosted OAuth proxy.
 */
const NETWORK_CONFIGS: Record<Network, NetworkConfig> = {
  local: {
    serviceUrl: "http://localhost:3000",
    zkLoginAddress: "", // Set after local deployment
    registryAddress: "", // Set after local deployment
  },
  devnet: {
    serviceUrl: "https://zklogin-auth.example.com", // TODO: set after deployment
    zkLoginAddress: "", // TODO: set after deployment
    registryAddress: "", // TODO: set after deployment
  },
  mainnet: {
    serviceUrl: "https://zklogin-auth.example.com", // TODO: set after deployment
    zkLoginAddress: "", // TODO: set after deployment
    registryAddress: "", // TODO: set after deployment
  },
};

export function getNetworkConfig(network: Network): NetworkConfig {
  return NETWORK_CONFIGS[network];
}
