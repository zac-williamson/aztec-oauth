/**
 * ZkLogin SDK — main entry point for app developers.
 *
 * Usage:
 *   import { ZkLogin } from "@aztec-zklogin/sdk";
 *
 *   const zkLogin = new ZkLogin({
 *     pxe: myPxe,
 *     wallet: myWallet,
 *     userAddress: myAddress,
 *   });
 *
 *   // Check if already bound
 *   if (await zkLogin.isBound()) return;
 *
 *   // Start the bind flow (redirects away from the page)
 *   await zkLogin.startBind("google");
 *
 *   // On page reload after redirect, complete the bind
 *   const result = await zkLogin.completeBind();
 */

import type {
  BindResult,
  Provider,
  ZkLoginOptions,
  OAuthState,
} from "./types.js";
import { getNetworkConfig } from "./config.js";
import {
  buildAuthRedirectUrl,
  generateCsrf,
  loadOAuthState,
  parseOAuthCallback,
  saveOAuthState,
} from "./oauth.js";
import { computeKidHash, computeNonce } from "./nonce.js";
import { generateBindInputs } from "./proof.js";

export class ZkLogin {
  private pxe: any;
  private wallet: any;
  private userAddress: any;
  private serviceUrl: string;
  private zkLoginAddress: string;
  private registryAddress: string;

  // Lazily loaded Aztec SDK modules
  private _Fr: any;
  private _pedersenHash: any;
  private _Contract: any;
  private _loadContractArtifact: any;
  private _SponsoredFeePaymentMethod: any;
  private _AztecAddress: any;

  constructor(options: ZkLoginOptions) {
    this.pxe = options.pxe;
    this.wallet = options.wallet;
    this.userAddress = options.userAddress;

    const network = options.network || "local";
    const networkConfig = getNetworkConfig(network);

    this.serviceUrl = options.serviceUrl || networkConfig.serviceUrl;
    this.zkLoginAddress = options.zkLoginAddress || networkConfig.zkLoginAddress;
    this.registryAddress = options.registryAddress || networkConfig.registryAddress;

    if (!this.zkLoginAddress) {
      throw new Error(
        `ZkLogin contract address not configured for network "${network}". ` +
          `Pass zkLoginAddress in options.`
      );
    }
    if (!this.registryAddress) {
      throw new Error(
        `Registry contract address not configured for network "${network}". ` +
          `Pass registryAddress in options.`
      );
    }
  }

  /**
   * Lazily import Aztec SDK modules.
   * These are peer dependencies — the app already has them installed.
   */
  private async loadAztecModules(): Promise<void> {
    if (this._Fr) return;

    const [fields, crypto, contracts, abi, addresses] = await Promise.all([
      import("@aztec/aztec.js/fields"),
      import("@aztec/foundation/crypto/pedersen"),
      import("@aztec/aztec.js/contracts"),
      import("@aztec/aztec.js/abi"),
      import("@aztec/aztec.js/addresses"),
    ]);

    this._Fr = fields.Fr;
    this._pedersenHash = crypto.pedersenHash;
    this._Contract = contracts.Contract;
    this._loadContractArtifact = abi.loadContractArtifact;
    this._AztecAddress = addresses.AztecAddress;
  }

  /**
   * Check if the user's address is already bound to an identity.
   */
  async isBound(address?: any): Promise<boolean> {
    await this.loadAztecModules();

    const contract = await this.getZkLoginContract();
    const addr = address || this.userAddress;

    return contract.methods
      .is_address_bound(addr)
      .simulate({ from: this.userAddress });
  }

  /**
   * Start the identity binding flow.
   *
   * This computes a nonce, saves state to sessionStorage, and redirects
   * the user to the OAuth service. The page will navigate away.
   *
   * After authentication, the user is redirected back to the current page.
   * Call `completeBind()` on page load to finish the flow.
   */
  async startBind(provider: Provider): Promise<void> {
    await this.loadAztecModules();

    // Generate randomness and compute nonce
    const randomness = this._Fr.random();
    const nonceHex = await computeNonce(
      this._pedersenHash,
      this._Fr,
      this.userAddress,
      randomness
    );

    // Generate CSRF token
    const csrf = generateCsrf();

    // Save state for after the redirect
    const state: OAuthState = {
      csrf,
      nonceHex,
      randomness: randomness.toString(),
      provider,
      returnUrl: window.location.href,
    };
    saveOAuthState(state);

    // Redirect to OAuth service
    const authUrl = buildAuthRedirectUrl({
      serviceUrl: this.serviceUrl,
      provider,
      nonce: nonceHex,
      redirectUri: window.location.href,
      state: csrf,
    });

    window.location.href = authUrl;
  }

  /**
   * Complete the identity binding flow after an OAuth redirect.
   *
   * Call this on every page load. It checks for OAuth callback data in
   * the URL fragment. If none is found, returns null (not a callback).
   * If callback data is found, processes the JWT and submits the
   * bind_account transaction.
   *
   * @returns BindResult if binding was completed, null if not a callback
   * @throws Error if the callback contains an error or processing fails
   */
  async completeBind(): Promise<BindResult | null> {
    // Check for OAuth callback data in the URL fragment
    const callback = parseOAuthCallback();
    if (!callback) return null;

    // Load saved state from before the redirect
    const state = loadOAuthState();
    if (!state) {
      throw new Error("No saved OAuth state found. Was startBind() called?");
    }

    // Handle OAuth errors
    if (callback.error) {
      throw new Error(`OAuth error: ${callback.error}`);
    }

    if (!callback.idToken) {
      throw new Error("No id_token in OAuth callback");
    }

    // Verify CSRF state
    if (callback.state !== state.csrf) {
      throw new Error("CSRF state mismatch — possible replay attack");
    }

    await this.loadAztecModules();

    // Generate circuit inputs from the JWT
    const inputs = await generateBindInputs({
      jwt: callback.idToken,
      pedersenHash: this._pedersenHash,
      Fr: this._Fr,
      computeKidHash,
    });

    // Restore randomness from saved state
    const randomness = this._Fr.fromString(state.randomness);

    // Determine whether to use private path or public fallback
    let useFallback = true;
    try {
      const registryContract = await this.getRegistryContract();
      const jwk = await registryContract.methods
        .get_jwk_unconstrained(new this._Fr(inputs.providerId), inputs.kidHash)
        .simulate();
      useFallback = !jwk.is_valid;
    } catch {
      useFallback = true;
    }

    // Call bind_account on the ZkLogin contract
    const contract = await this.getZkLoginContract();
    const receipt = await contract.methods
      .bind_account(
        inputs.jwtBytes,
        inputs.base64DecodeOffset,
        inputs.pubkeyModulusLimbs,
        inputs.redcParamsLimbs,
        inputs.signatureLimbs,
        new this._Fr(inputs.providerId),
        inputs.kidHash,
        randomness,
        useFallback
      )
      .send({ from: this.userAddress });

    return {
      txHash: receipt.txHash?.toString() ?? "submitted",
      provider: state.provider,
    };
  }

  // ── Contract accessors ──────────────────────────────────────────────

  private zkLoginContract: any = null;
  private registryContract: any = null;

  private async getZkLoginContract(): Promise<any> {
    if (this.zkLoginContract) return this.zkLoginContract;

    // Dynamically import the contract artifact
    // The artifact is bundled with the SDK package
    const artifactJson = await import("../artifacts/zk_login-ZkLogin.json", {
      with: { type: "json" },
    });

    const artifact = this._loadContractArtifact(artifactJson.default);
    const address = this._AztecAddress.fromString(this.zkLoginAddress);

    this.zkLoginContract = this._Contract.at(address, artifact, this.wallet);
    return this.zkLoginContract;
  }

  private async getRegistryContract(): Promise<any> {
    if (this.registryContract) return this.registryContract;

    const artifactJson = await import(
      "../artifacts/jwks_registry-JwksRegistry.json",
      { with: { type: "json" } }
    );

    const artifact = this._loadContractArtifact(artifactJson.default);
    const address = this._AztecAddress.fromString(this.registryAddress);

    this.registryContract = this._Contract.at(address, artifact, this.wallet);
    return this.registryContract;
  }
}
