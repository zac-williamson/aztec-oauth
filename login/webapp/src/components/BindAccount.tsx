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

type Status =
  | "idle"
  | "connecting"
  | "connected"
  | "authenticating"
  | "processing"
  | "proving"
  | "success"
  | "error";

export default function BindAccount() {
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string>("");
  const [aztecAddress, setAztecAddress] = useState<string>("");
  const [selectedProvider, setSelectedProvider] = useState<OAuthProvider | null>(
    null
  );
  const [txHash, setTxHash] = useState<string>("");

  // Check for OAuth redirect on mount
  useEffect(() => {
    const hash = window.location.hash;
    if (hash) {
      handleOAuthCallback(hash);
    }
  }, []);

  const connectWallet = useCallback(async () => {
    setStatus("connecting");
    setError("");
    try {
      // In production, use @aztec/aztec.js:
      // const pxe = createPXEClient('http://localhost:8080');
      // const accounts = await pxe.getRegisteredAccounts();
      // if (accounts.length === 0) throw new Error('No accounts found');
      // const address = accounts[0].address.toString();

      // Placeholder for development
      const address =
        "0x" + Array.from({ length: 64 }, () => "0").join("");
      setAztecAddress(address);
      setStatus("connected");
    } catch (err) {
      setError(
        `Failed to connect wallet: ${err instanceof Error ? err.message : String(err)}`
      );
      setStatus("error");
    }
  }, []);

  const startOAuth = useCallback(
    async (provider: OAuthProvider) => {
      if (!aztecAddress) {
        setError("Connect wallet first");
        return;
      }

      setSelectedProvider(provider);
      setStatus("authenticating");
      setError("");

      try {
        // Generate nonce that binds JWT to this address
        const randomness = generateRandomness();
        const nonce = await computeNonce(aztecAddress, randomness);

        // Store randomness for later proof generation
        storeNonceRandomness(nonce, randomness);

        // Store provider selection
        sessionStorage.setItem("aztec-sybil-provider", JSON.stringify(provider));
        sessionStorage.setItem("aztec-sybil-nonce", nonce);

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
    [aztecAddress]
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

        // Clear the hash from URL
        window.history.replaceState(null, "", window.location.pathname);

        // Recover provider and nonce from session
        const providerJson = sessionStorage.getItem("aztec-sybil-provider");
        const nonce = sessionStorage.getItem("aztec-sybil-nonce");
        if (!providerJson || !nonce) {
          throw new Error("Missing OAuth session state");
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
          throw new Error("Nonce randomness not found");
        }

        // Generate circuit inputs using noir-jwt SDK
        setStatus("proving");
        const kidHash = "0x" + kid; // Placeholder; use actual Pedersen hash
        const inputs = await generateBindAccountInputs(
          idToken,
          signingKey,
          provider.id,
          kidHash,
          randomness
        );

        console.log("Circuit inputs prepared, submitting transaction...");

        // Submit bind_account transaction
        // In production:
        // const pxe = createPXEClient('http://localhost:8080');
        // const wallet = await getWallet(pxe);
        // const contract = await Contract.at(ZK_LOGIN_ADDRESS, ZkLoginAbi, wallet);
        // const tx = contract.methods.bind_account(
        //   inputs.jwtData,
        //   inputs.base64DecodeOffset,
        //   inputs.pubkeyModulusLimbs,
        //   inputs.redcParamsLimbs,
        //   inputs.signatureLimbs,
        //   inputs.providerId,
        //   inputs.kidHash,
        //   inputs.nonceRandomness,
        // ).send();
        // const receipt = await tx.wait();
        // setTxHash(receipt.txHash.toString());

        // Placeholder for development
        setTxHash("0xplaceholder_tx_hash");
        clearNonceRandomness(nonce);
        sessionStorage.removeItem("aztec-sybil-provider");
        sessionStorage.removeItem("aztec-sybil-nonce");
        setStatus("success");
      } catch (err) {
        setError(
          `Binding failed: ${err instanceof Error ? err.message : String(err)}`
        );
        setStatus("error");
      }
    },
    [aztecAddress]
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

      {status === "connecting" && <p>Connecting wallet...</p>}

      {/* Step 2: Select Provider */}
      {status === "connected" && (
        <div>
          <p>
            Connected: <code>{aztecAddress.slice(0, 10)}...</code>
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
          <p>Generating ZK proof...</p>
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
          <p>
            Transaction: <code>{txHash.slice(0, 18)}...</code>
          </p>
          <p style={{ color: "#666", fontSize: 14 }}>
            On-chain: only an opaque nullifier and provider type are visible.
            Your Google/Apple identity remains private.
          </p>
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
