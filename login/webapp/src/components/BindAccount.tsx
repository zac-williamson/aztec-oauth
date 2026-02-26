/**
 * BindAccount Component
 *
 * Main UI for the OAuth identity binding flow:
 * 1. User connects Aztec wallet
 * 2. Selects Google or Apple
 * 3. App generates nonce and redirects to OAuth
 * 4. User authenticates with provider
 * 5. App receives JWT and submits bind_account() transaction
 * 6. PXE generates ZK proof locally — JWT never leaves device
 */

import { useState, useEffect, useCallback } from "react";
import {
  GOOGLE_PROVIDER,
  APPLE_PROVIDER,
  buildAuthUrl,
  extractIdToken,
  decodeJwt,
  fetchSigningKey,
  type OAuthProvider,
} from "../lib/providers";
import {
  generateRandomness,
  computeNonce,
  storeNonceRandomness,
  getNonceRandomness,
  clearNonceRandomness,
} from "../lib/nonce";
import { generateBindAccountInputs } from "../lib/jwt-inputs";
import { clearKeys } from "../lib/aztec-client";
import { useAztec } from "../hooks/useAztec";

type Status =
  | "idle"
  | "connecting"
  | "connected"
  | "already_bound"
  | "authenticating"
  | "processing"
  | "proving"
  | "success"
  | "error";

export default function BindAccount() {
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string>("");
  const [selectedProvider, setSelectedProvider] = useState<OAuthProvider | null>(
    null
  );
  const [txHash, setTxHash] = useState<string>("");

  const {
    isConnecting,
    isConnected,
    isBound,
    userAddress,
    zkLoginClient,
    error: aztecError,
    connect,
  } = useAztec();

  // Sync Aztec connection state to local status
  useEffect(() => {
    if (isConnecting) setStatus("connecting");
    else if (isConnected && isBound === true) setStatus("already_bound");
    else if (isConnected) setStatus("connected");
    if (aztecError) {
      setError(`Wallet connection failed: ${aztecError}`);
      setStatus("error");
    }
  }, [isConnecting, isConnected, isBound, aztecError]);

  // On OAuth redirect: auto-reconnect wallet, then process the token
  useEffect(() => {
    const hash = window.location.hash;
    if (hash && hash.includes("id_token")) {
      // Wallet state was lost during redirect — reconnect first
      if (!isConnected && !isConnecting) {
        console.log("[BindAccount] OAuth callback detected, auto-reconnecting wallet...");
        connect();
      }
      // Once connected, process the callback
      if (isConnected && zkLoginClient) {
        console.log("[BindAccount] Wallet reconnected, processing OAuth callback...");
        handleOAuthCallback(hash);
      }
    }
  }, [isConnected, isConnecting, zkLoginClient]);

  const connectWallet = useCallback(async () => {
    setError("");
    await connect();
  }, [connect]);

  const startOAuth = useCallback(
    async (provider: OAuthProvider) => {
      if (!userAddress) {
        setError("Connect wallet first");
        return;
      }

      setSelectedProvider(provider);
      setStatus("authenticating");
      setError("");

      try {
        // Generate nonce that binds JWT to this address
        const randomness = generateRandomness();
        const nonce = await computeNonce(userAddress, randomness);

        // Store randomness for later proof generation
        storeNonceRandomness(nonce, randomness);

        // Store provider selection and address
        localStorage.setItem("aztec-sybil-provider", JSON.stringify(provider));
        localStorage.setItem("aztec-sybil-nonce", nonce);
        localStorage.setItem("aztec-sybil-address", userAddress);

        // Redirect to OAuth provider
        const redirectUri = window.location.origin + window.location.pathname;
        const authUrl = buildAuthUrl(provider, nonce, redirectUri);
        window.location.href = authUrl;
      } catch (err) {
        setError(
          `OAuth setup failed: ${err instanceof Error ? err.message : String(err)}`
        );
        setStatus("error");
      }
    },
    [userAddress]
  );

  const handleOAuthCallback = useCallback(
    async (hash: string) => {
      setStatus("processing");
      setError("");

      try {
        // Extract id_token from URL fragment
        const idToken = extractIdToken(hash);
        if (!idToken) {
          throw new Error("No id_token in OAuth redirect");
        }

        console.log("[BindAccount] JWT received from OAuth provider:");
        console.log(idToken);

        // Clear the hash from URL
        window.history.replaceState(null, "", window.location.pathname);

        // Recover provider and nonce from session
        const providerJson = localStorage.getItem("aztec-sybil-provider");
        const nonce = localStorage.getItem("aztec-sybil-nonce");
        if (!providerJson || !nonce) {
          throw new Error("Missing OAuth session state — please start over");
        }
        const provider: OAuthProvider = JSON.parse(providerJson);
        setSelectedProvider(provider);

        // Decode JWT to get kid from header
        const { header, payload } = decodeJwt(idToken);
        const kid = header.kid as string;
        if (!kid) {
          throw new Error("JWT header missing kid");
        }

        console.log("JWT decoded:", {
          iss: payload.iss,
          sub: (payload.sub as string)?.substring(0, 4) + "...",
          kid,
        });

        // Fetch signing key from JWKS
        const signingKey = await fetchSigningKey(provider, kid);
        if (!signingKey) {
          throw new Error(`Signing key not found for kid=${kid}`);
        }

        // Recover nonce randomness
        const randomness = getNonceRandomness(nonce);
        if (randomness === null) {
          throw new Error("Nonce randomness not found — please start over");
        }

        // Generate circuit inputs using noir-jwt SDK
        setStatus("proving");
        const inputs = await generateBindAccountInputs(
          idToken,
          signingKey,
          provider.id,
          kid,
          randomness
        );

        console.log("Circuit inputs prepared, submitting transaction...");

        // Submit bind_account transaction
        if (!zkLoginClient) {
          // If we lost the client (e.g. page reload), need to reconnect first
          throw new Error("Wallet not connected — please reconnect and try again");
        }

        const hash_ = await zkLoginClient.bindAccount(inputs);
        setTxHash(hash_);

        // Clean up session storage
        clearNonceRandomness(nonce);
        localStorage.removeItem("aztec-sybil-provider");
        localStorage.removeItem("aztec-sybil-nonce");
        localStorage.removeItem("aztec-sybil-address");
        setStatus("success");
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        // Detect duplicate binding errors from the contract
        if (msg.includes("identity already bound") || msg.includes("nullifier")) {
          setError("This identity is already bound to an Aztec address.");
        } else {
          setError(`Binding failed: ${msg}`);
        }
        setStatus("error");
      }
    },
    [zkLoginClient]
  );

  return (
    <div style={{ maxWidth: 480, margin: "0 auto", padding: 24, fontFamily: "system-ui" }}>
      <h1>zkLogin Identity Binding</h1>
      <p style={{ color: "#666" }}>
        Bind your Google or Apple identity to your Aztec address with
        privacy-preserving ZK proofs.
      </p>

      {/* Step 1: Connect Wallet */}
      {status === "idle" && (
        <button onClick={connectWallet} style={buttonStyle}>
          Connect Aztec Wallet
        </button>
      )}

      {status === "connecting" && <p>Connecting to Aztec node and creating account...</p>}

      {/* Step 2: Select Provider */}
      {status === "connected" && (
        <div>
          <p>
            Connected: <code>{userAddress.slice(0, 10)}...</code>
          </p>
          <p>Choose identity provider:</p>
          <div style={{ display: "flex", gap: 12 }}>
            <button
              onClick={() => startOAuth(GOOGLE_PROVIDER)}
              style={buttonStyle}
            >
              Sign in with Google
            </button>
            <button
              onClick={() => startOAuth(APPLE_PROVIDER)}
              style={buttonStyle}
            >
              Sign in with Apple
            </button>
          </div>
        </div>
      )}

      {/* Step 3: Processing */}
      {status === "authenticating" && (
        <p>Redirecting to {selectedProvider?.name}...</p>
      )}

      {status === "processing" && <p>Processing JWT...</p>}

      {status === "proving" && (
        <div>
          <p>Generating ZK proof and submitting transaction...</p>
          <p style={{ color: "#666", fontSize: 14 }}>
            Your JWT and personal data stay on this device. Only the ZK proof is
            sent to the network.
          </p>
        </div>
      )}

      {/* Step 4: Success */}
      {status === "success" && (
        <div>
          <h2 style={{ color: "#16a34a" }}>Identity Bound!</h2>
          <p>
            Your {selectedProvider?.name} identity has been bound to your Aztec
            address.
          </p>
          {txHash && (
            <p>
              Transaction: <code>{txHash.slice(0, 18)}...</code>
            </p>
          )}
          <p style={{ color: "#666", fontSize: 14 }}>
            On-chain: only an opaque nullifier and provider type are visible.
            Your Google/Apple identity remains private.
          </p>
          <button
            onClick={() => {
              clearKeys();
              setStatus("idle");
              setError("");
              setTxHash("");
              setSelectedProvider(null);
            }}
            style={{ ...buttonStyle, marginTop: 16 }}
          >
            New Account + Bind Again
          </button>
          <p style={{ color: "#666", fontSize: 12, marginTop: 4 }}>
            Creates a fresh wallet. Re-binding the same identity should fail (sybil resistance).
          </p>
        </div>
      )}

      {/* Already bound */}
      {status === "already_bound" && (
        <div>
          <p>
            Connected: <code>{userAddress.slice(0, 10)}...</code>
          </p>
          <div
            style={{
              padding: 12,
              background: "#f0fdf4",
              border: "1px solid #bbf7d0",
              borderRadius: 8,
              color: "#16a34a",
            }}
          >
            This address is already bound to an identity. No further action needed.
          </div>
          <button
            onClick={() => {
              clearKeys();
              setStatus("idle");
              setError("");
              setTxHash("");
              setSelectedProvider(null);
            }}
            style={{ ...buttonStyle, marginTop: 16 }}
          >
            New Account + Bind Again
          </button>
        </div>
      )}

      {/* Error */}
      {error && (
        <div
          style={{
            marginTop: 16,
            padding: 12,
            background: "#fef2f2",
            border: "1px solid #fecaca",
            borderRadius: 8,
            color: "#dc2626",
          }}
        >
          {error}
          {(status === "error") && (
            <button
              onClick={() => { setStatus("idle"); setError(""); }}
              style={{ ...buttonStyle, marginTop: 8, display: "block" }}
            >
              Try Again
            </button>
          )}
        </div>
      )}
    </div>
  );
}

const buttonStyle: React.CSSProperties = {
  padding: "12px 24px",
  fontSize: 16,
  borderRadius: 8,
  border: "1px solid #d1d5db",
  background: "#f9fafb",
  cursor: "pointer",
};
