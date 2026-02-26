/**
 * React hook for Aztec wallet connection and contract interaction.
 */

import { useState, useCallback, useRef } from "react";
import { loadConfig } from "../lib/config";
import { createAztecClient, connectToContract, type AztecClient } from "../lib/aztec-client";
import { ZkLoginClient } from "../lib/contract";

// Import contract artifacts at build time
import zkLoginArtifactJson from "../../../contracts/zk_login/target/zk_login-ZkLogin.json";
import registryArtifactJson from "../../../../registry/contracts/jwks_registry/target/jwks_registry-JwksRegistry.json";

export interface UseAztecState {
  isConnecting: boolean;
  isConnected: boolean;
  isBound: boolean | null;
  userAddress: string;
  zkLoginClient: ZkLoginClient | null;
  error: string | null;
  connect: () => Promise<void>;
}

export function useAztec(): UseAztecState {
  const [isConnecting, setIsConnecting] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [isBound, setIsBound] = useState<boolean | null>(null);
  const [userAddress, setUserAddress] = useState("");
  const [error, setError] = useState<string | null>(null);
  const zkLoginClientRef = useRef<ZkLoginClient | null>(null);

  const connect = useCallback(async () => {
    setIsConnecting(true);
    setError(null);

    try {
      const config = loadConfig();
      console.log("[useAztec] Config loaded:", config.nodeUrl, "zkLogin:", config.zkLoginAddress);
      if (!config.zkLoginAddress) {
        throw new Error("VITE_ZK_LOGIN_ADDRESS not configured");
      }
      if (!config.registryAddress) {
        throw new Error("VITE_REGISTRY_ADDRESS not configured");
      }

      // Create wallet and user account
      console.log("[useAztec] Creating Aztec client...");
      const client: AztecClient = await createAztecClient(config);
      console.log("[useAztec] Aztec client created, address:", client.userAddress.toString());
      setUserAddress(client.userAddress.toString());

      // Connect to both contracts
      console.log("[useAztec] Connecting to contracts...");
      const [contract, registryContract] = await Promise.all([
        connectToContract(client.wallet, client.node, config.zkLoginAddress, zkLoginArtifactJson),
        connectToContract(client.wallet, client.node, config.registryAddress, registryArtifactJson),
      ]);
      console.log("[useAztec] Connected to ZkLogin and Registry contracts");

      const zkClient = new ZkLoginClient(
        contract,
        registryContract,
        client.userAddress,
        client.paymentMethod
      );
      zkLoginClientRef.current = zkClient;

      // Pre-check if already bound
      console.log("[useAztec] Checking if address is already bound...");
      const bound = await zkClient.isAddressBound();
      console.log("[useAztec] isBound:", bound);
      setIsBound(bound);
      setIsConnected(true);
      console.log("[useAztec] Connection complete!");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsConnecting(false);
    }
  }, []);

  return {
    isConnecting,
    isConnected,
    isBound,
    userAddress,
    zkLoginClient: zkLoginClientRef.current,
    error,
    connect,
  };
}
