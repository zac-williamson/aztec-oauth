import type { ServiceConfig } from "./config.js";

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

/**
 * Build the Google OAuth authorization URL.
 *
 * The nonce parameter is included so Google embeds it in the signed id_token.
 * The state parameter encodes the app's redirect_uri so we can forward the
 * JWT back after the callback.
 */
export function buildGoogleAuthUrl(params: {
  config: ServiceConfig;
  nonce: string;
  redirectUri: string;
  state: string;
}): string {
  // Encode the app's redirect_uri and CSRF state together
  // Google will echo this back unchanged in the callback
  const oauthState = Buffer.from(
    JSON.stringify({ s: params.state, r: params.redirectUri })
  )
    .toString("base64url");

  const query = new URLSearchParams({
    client_id: params.config.google.clientId,
    redirect_uri: `${params.config.serviceUrl}/callback/google`,
    response_type: "code",
    scope: "openid",
    nonce: params.nonce,
    state: oauthState,
    // Prompt for account selection every time to prevent silent re-auth
    // with the wrong account
    prompt: "select_account",
  });

  return `${GOOGLE_AUTH_URL}?${query.toString()}`;
}

/**
 * Exchange an authorization code for tokens with Google.
 * Returns the raw id_token (JWT string).
 */
export async function exchangeGoogleCode(params: {
  config: ServiceConfig;
  code: string;
}): Promise<string> {
  const body = new URLSearchParams({
    code: params.code,
    client_id: params.config.google.clientId,
    client_secret: params.config.google.clientSecret,
    redirect_uri: `${params.config.serviceUrl}/callback/google`,
    grant_type: "authorization_code",
  });

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Google token exchange failed: ${response.status} ${text}`);
  }

  const data = (await response.json()) as { id_token?: string };
  if (!data.id_token) {
    throw new Error("No id_token in Google token response");
  }

  return data.id_token;
}

/**
 * Decode the state parameter from Google's callback.
 */
export function decodeOAuthState(state: string): {
  s: string; // CSRF state from client
  r: string; // App's redirect URI
} {
  const decoded = Buffer.from(state, "base64url").toString("utf-8");
  return JSON.parse(decoded);
}
