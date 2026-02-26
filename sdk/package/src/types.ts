/**
 * Public types for the @aztec-zklogin/sdk package.
 */

/** Supported OAuth providers. */
export type Provider = "google" | "apple";

/** Network configuration. */
export type Network = "local" | "devnet" | "mainnet";

/** Options passed when creating a ZkLogin instance. */
export interface ZkLoginOptions {
  /** The user's PXE client (must have a registered wallet). */
  pxe: any;
  /** The user's wallet instance. */
  wallet: any;
  /** The user's Aztec address. */
  userAddress: any;
  /** Which network to use. Determines contract addresses and service URL. */
  network?: Network;
  /** Override the OAuth service URL (e.g. for local development). */
  serviceUrl?: string;
  /** Override the ZkLogin contract address. */
  zkLoginAddress?: string;
  /** Override the JwksRegistry contract address. */
  registryAddress?: string;
}

/** Result of a successful bind operation. */
export interface BindResult {
  /** Transaction hash of the bind_account call. */
  txHash: string;
  /** The provider used for binding. */
  provider: Provider;
}

/** State persisted across the OAuth redirect. */
export interface OAuthState {
  /** Random CSRF token for verifying the response. */
  csrf: string;
  /** Nonce hex string embedded in the JWT. */
  nonceHex: string;
  /** Randomness used to derive the nonce. */
  randomness: string;
  /** The provider being used. */
  provider: Provider;
  /** The URL to return to after OAuth. */
  returnUrl: string;
}

/** Deployed contract addresses per network. */
export interface NetworkConfig {
  serviceUrl: string;
  zkLoginAddress: string;
  registryAddress: string;
}
