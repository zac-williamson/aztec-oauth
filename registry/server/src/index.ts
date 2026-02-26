/**
 * JWKS Monitor - Entry Point
 *
 * Polls Google and Apple JWKS endpoints and syncs keys
 * to an Aztec JwksRegistry contract.
 */

import { loadConfig } from "./config.js";
import { createAztecClient } from "./aztec-client.js";
import { JwksMonitor } from "./monitor.js";

async function main(): Promise<void> {
  const config = loadConfig();
  console.log("Starting JWKS Monitor...");
  console.log(`Network: ${config.network}, Node: ${config.nodeUrl}`);
  console.log(`Registry: ${config.registryAddress}`);
  console.log(`Poll interval: ${config.pollIntervalMs}ms`);

  const client = await createAztecClient(config);
  console.log("Connected to Aztec node");

  const monitor = new JwksMonitor({
    contract: client.registryContract,
    adminAddress: client.adminAddress,
    paymentMethod: client.paymentMethod,
    pollIntervalMs: config.pollIntervalMs,
  });

  monitor.start();

  // Graceful shutdown
  process.on("SIGINT", () => {
    console.log("\nShutting down...");
    monitor.stop();
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    console.log("\nShutting down...");
    monitor.stop();
    process.exit(0);
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
