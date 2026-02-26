/**
 * JWKS Monitor - polls Google and Apple JWKS endpoints
 * and syncs keys to the on-chain JwksRegistry.
 */

import { fetchAndProcessKeys, type ProcessedKey } from "./jwks-fetcher.js";
import { diffKeys, type DiffResult } from "./key-differ.js";
import { submitKey } from "./submitter.js";

// ─── Provider Configuration ─────────────────────────────────────────────────

export interface ProviderConfig {
  providerId: number;
  name: string;
  jwksUrl: string;
}

export const PROVIDERS: ProviderConfig[] = [
  {
    providerId: 1,
    name: "Google",
    jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
  },
  {
    providerId: 2,
    name: "Apple",
    jwksUrl: "https://appleid.apple.com/auth/keys",
  },
];

// ─── Monitor Class ──────────────────────────────────────────────────────────

export interface MonitorDeps {
  contract: any;
  adminAddress: any;
  paymentMethod: any;
  pollIntervalMs: number;
  /** Override providers for testing */
  providers?: ProviderConfig[];
  /** Override key fetcher for testing */
  fetchKeys?: (providerId: number, jwksUrl: string) => Promise<ProcessedKey[]>;
  /** Override key differ for testing */
  diffFn?: (
    fetchedKeys: ProcessedKey[],
    contract: any,
    fromAddress: any
  ) => Promise<DiffResult>;
  /** Override key submitter for testing */
  submitFn?: (
    contract: any,
    adminAddress: any,
    paymentMethod: any,
    key: ProcessedKey
  ) => Promise<void>;
}

export class JwksMonitor {
  private timer: ReturnType<typeof setInterval> | null = null;
  private mutex = false;

  private providers: ProviderConfig[];
  private fetchKeys: typeof fetchAndProcessKeys;
  private diffFn: typeof diffKeys;
  private submitFn: typeof submitKey;

  constructor(private deps: MonitorDeps) {
    this.providers = deps.providers ?? PROVIDERS;
    this.fetchKeys = deps.fetchKeys ?? fetchAndProcessKeys;
    this.diffFn = deps.diffFn ?? diffKeys;
    this.submitFn = deps.submitFn ?? submitKey;
  }

  /**
   * Start the polling loop. Runs an immediate poll, then repeats on interval.
   */
  start(): void {
    console.log(
      `JWKS Monitor started (polling every ${this.deps.pollIntervalMs}ms)`
    );
    // Run initial poll immediately
    this.poll();
    // Schedule repeating polls
    this.timer = setInterval(() => this.poll(), this.deps.pollIntervalMs);
  }

  /**
   * Stop the polling loop.
   */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    console.log("JWKS Monitor stopped");
  }

  /**
   * Execute a single poll cycle: fetch keys from all providers,
   * diff against on-chain state, and submit changes.
   *
   * Protected by a mutex to prevent concurrent polls.
   */
  async poll(): Promise<void> {
    if (this.mutex) {
      console.log("Poll already in progress, skipping");
      return;
    }

    this.mutex = true;
    try {
      console.log("--- Poll cycle start ---");

      // Fetch keys from all providers
      const allFetchedKeys: ProcessedKey[] = [];
      for (const provider of this.providers) {
        try {
          console.log(`Fetching JWKS for ${provider.name}...`);
          const keys = await this.fetchKeys(
            provider.providerId,
            provider.jwksUrl
          );
          console.log(
            `  Found ${keys.length} RSA/RS256 key(s) for ${provider.name}`
          );
          allFetchedKeys.push(...keys);
        } catch (err) {
          console.error(
            `  Failed to fetch keys for ${provider.name}:`,
            err instanceof Error ? err.message : err
          );
        }
      }

      if (allFetchedKeys.length === 0) {
        console.log("No keys fetched, skipping diff/submit");
        console.log("--- Poll cycle end ---");
        return;
      }

      // Diff against on-chain
      const diff = await this.diffFn(
        allFetchedKeys,
        this.deps.contract,
        this.deps.adminAddress
      );

      console.log(
        `Diff result: ${diff.toAdd.length} to add, ` +
          `${diff.toUpdate.length} to update, ` +
          `${diff.unchanged.length} unchanged`
      );

      // Submit new and updated keys
      const keysToSubmit = [...diff.toAdd, ...diff.toUpdate];
      for (const key of keysToSubmit) {
        try {
          await this.submitFn(
            this.deps.contract,
            this.deps.adminAddress,
            this.deps.paymentMethod,
            key
          );
        } catch (err) {
          console.error(
            `  Failed to submit key kid="${key.kid}":`,
            err instanceof Error ? err.message : err
          );
        }
      }

      console.log("--- Poll cycle end ---");
    } finally {
      this.mutex = false;
    }
  }
}
