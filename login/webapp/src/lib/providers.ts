/**
 * OAuth Provider Configuration
 *
 * Configures Google and Apple OAuth flows for JWT-based identity binding.
 * Both providers return JWTs signed with RS256 (RSA-SHA256, 2048-bit keys).
 */

export interface OAuthProvider {
  id: number; // Provider ID matching contract: 1=Google, 2=Apple
  name: string;
  authUrl: string;
  jwksUrl: string;
  issuer: string;
  clientId: string; // Set via environment
  scope: string;
  responseType: string;
}

export const GOOGLE_PROVIDER: OAuthProvider = {
  id: 1,
  name: "Google",
  authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
  jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
  issuer: "https://accounts.google.com",
  clientId: import.meta.env?.VITE_GOOGLE_CLIENT_ID ?? "",
  scope: "openid",
  responseType: "id_token",
};

export const APPLE_PROVIDER: OAuthProvider = {
  id: 2,
  name: "Apple",
  authUrl: "https://appleid.apple.com/auth/authorize",
  jwksUrl: "https://appleid.apple.com/auth/keys",
  issuer: "https://appleid.apple.com",
  clientId: import.meta.env?.VITE_APPLE_CLIENT_ID ?? "",
  scope: "openid",
  responseType: "id_token",
};

/**
 * Build the OAuth authorization URL with the given nonce.
 */
export function buildAuthUrl(
  provider: OAuthProvider,
  nonce: string,
  redirectUri: string
): string {
  const params = new URLSearchParams({
    client_id: provider.clientId,
    redirect_uri: redirectUri,
    response_type: provider.responseType,
    scope: provider.scope,
    nonce: nonce,
    // For Google, request the id_token in the URL fragment
    response_mode: "fragment",
  });

  return `${provider.authUrl}?${params.toString()}`;
}

/**
 * Extract the id_token from the OAuth redirect URL fragment.
 */
export function extractIdToken(hash: string): string | null {
  const params = new URLSearchParams(hash.replace("#", ""));
  return params.get("id_token");
}

/**
 * Decode a JWT without verification (to extract header/payload for display).
 * The actual verification happens inside the ZK circuit.
 */
export function decodeJwt(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }
  const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
  const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
  return { header, payload };
}

/**
 * Fetch the current JWKS from a provider and find the key matching the JWT's kid.
 */
export async function fetchSigningKey(
  provider: OAuthProvider,
  kid: string
): Promise<JsonWebKey | null> {
  const response = await fetch(provider.jwksUrl);
  const jwks = await response.json();
  const key = jwks.keys?.find(
    (k: { kid: string }) => k.kid === kid
  );
  return key ?? null;
}
