import type { OAuthState, Provider } from "./types.js";

const STORAGE_KEY = "aztec-zklogin-oauth-state";

/**
 * Generate a random CSRF token.
 */
export function generateCsrf(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Save OAuth state to sessionStorage (survives redirect, cleared on tab close).
 */
export function saveOAuthState(state: OAuthState): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

/**
 * Load and clear OAuth state from sessionStorage.
 * Returns null if no state exists or if the state is invalid.
 */
export function loadOAuthState(): OAuthState | null {
  const raw = sessionStorage.getItem(STORAGE_KEY);
  if (!raw) return null;

  sessionStorage.removeItem(STORAGE_KEY);

  try {
    return JSON.parse(raw) as OAuthState;
  } catch {
    return null;
  }
}

/**
 * Build the URL to redirect to the OAuth service.
 */
export function buildAuthRedirectUrl(params: {
  serviceUrl: string;
  provider: Provider;
  nonce: string;
  redirectUri: string;
  state: string;
}): string {
  const query = new URLSearchParams({
    nonce: params.nonce,
    redirect_uri: params.redirectUri,
    state: params.state,
  });
  return `${params.serviceUrl}/auth/${params.provider}?${query.toString()}`;
}

/**
 * Parse the OAuth callback from the URL fragment.
 * Returns null if no callback data is present.
 *
 * Expected fragment: #id_token=xxx&provider=google&state=yyy
 * Or error: #error=xxx&state=yyy
 */
export function parseOAuthCallback(): {
  idToken?: string;
  provider?: Provider;
  state?: string;
  error?: string;
} | null {
  const hash = window.location.hash;
  if (!hash || hash.length <= 1) return null;

  const params = new URLSearchParams(hash.substring(1));
  const idToken = params.get("id_token") || undefined;
  const provider = (params.get("provider") as Provider) || undefined;
  const state = params.get("state") || undefined;
  const error = params.get("error") || undefined;

  if (!idToken && !error) return null;

  // Clean the fragment from the URL to avoid re-processing
  history.replaceState(null, "", window.location.pathname + window.location.search);

  return { idToken, provider, state, error };
}

/**
 * Decode a JWT and return the header and payload (without verification).
 * Used to extract the kid and claims for proof generation.
 */
export function decodeJwt(jwt: string): {
  header: { alg: string; kid: string; typ?: string };
  payload: Record<string, unknown>;
} {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");

  const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
  const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));

  return { header, payload };
}
