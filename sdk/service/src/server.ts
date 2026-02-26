import * as http from "node:http";
import { type ServiceConfig, isAllowedOrigin } from "./config.js";
import {
  buildGoogleAuthUrl,
  decodeOAuthState,
  exchangeGoogleCode,
} from "./google.js";

/**
 * Create the OAuth proxy HTTP server.
 *
 * Routes:
 *   GET /auth/google   - Initiate Google OAuth (redirects to Google)
 *   GET /callback/google - Google OAuth callback (exchanges code, redirects to app)
 *   GET /health        - Health check
 */
export function createServer(config: ServiceConfig): http.Server {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const path = url.pathname;

    // CORS preflight for health check
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }

    try {
      if (path === "/health" && req.method === "GET") {
        handleHealth(res);
      } else if (path === "/auth/google" && req.method === "GET") {
        handleAuthGoogle(url, config, res);
      } else if (path === "/callback/google" && req.method === "GET") {
        await handleCallbackGoogle(url, config, res);
      } else {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "not found" }));
      }
    } catch (err) {
      console.error("Request error:", err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "internal server error" }));
    }
  });
}

function handleHealth(res: http.ServerResponse): void {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "ok" }));
}

/**
 * GET /auth/google?nonce=0x...&redirect_uri=https://app.com/page&state=csrf
 *
 * Validates the redirect_uri against the allowed origins list,
 * then redirects to Google OAuth with the nonce embedded.
 */
function handleAuthGoogle(
  url: URL,
  config: ServiceConfig,
  res: http.ServerResponse
): void {
  const nonce = url.searchParams.get("nonce");
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");

  if (!nonce || !redirectUri || !state) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({ error: "missing required params: nonce, redirect_uri, state" })
    );
    return;
  }

  // Validate redirect_uri origin
  if (!isAllowedOrigin(redirectUri, config.allowedOrigins)) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "redirect_uri origin not allowed" }));
    return;
  }

  const googleUrl = buildGoogleAuthUrl({ config, nonce, redirectUri, state });

  res.writeHead(302, { Location: googleUrl });
  res.end();
}

/**
 * GET /callback/google?code=xxx&state=yyy
 *
 * Google redirects here after user authenticates.
 * Exchanges the code for an id_token, then redirects back to the app
 * with the JWT in the URL fragment (keeps it client-side only).
 */
async function handleCallbackGoogle(
  url: URL,
  config: ServiceConfig,
  res: http.ServerResponse
): Promise<void> {
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  // Handle Google OAuth errors (user cancelled, etc.)
  if (error) {
    // Attempt to decode state to get redirect_uri for error redirect
    if (stateParam) {
      try {
        const { s, r } = decodeOAuthState(stateParam);
        const errorUrl = `${r}#error=${encodeURIComponent(error)}&state=${encodeURIComponent(s)}`;
        res.writeHead(302, { Location: errorUrl });
        res.end();
        return;
      } catch {
        // Fall through to generic error
      }
    }
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: `OAuth error: ${error}` }));
    return;
  }

  if (!code || !stateParam) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "missing code or state" }));
    return;
  }

  // Decode state to get app's redirect_uri and CSRF token
  let appRedirectUri: string;
  let csrfState: string;
  try {
    const decoded = decodeOAuthState(stateParam);
    appRedirectUri = decoded.r;
    csrfState = decoded.s;
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "invalid state parameter" }));
    return;
  }

  // Validate redirect_uri origin (defense in depth)
  if (!isAllowedOrigin(appRedirectUri, config.allowedOrigins)) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "redirect_uri origin not allowed" }));
    return;
  }

  // Exchange code for id_token
  let idToken: string;
  try {
    idToken = await exchangeGoogleCode({ config, code });
  } catch (err) {
    console.error("Token exchange failed:", err);
    const errorUrl = `${appRedirectUri}#error=token_exchange_failed&state=${encodeURIComponent(csrfState)}`;
    res.writeHead(302, { Location: errorUrl });
    res.end();
    return;
  }

  // Redirect back to the app with the JWT in the URL fragment.
  // Fragment (#) is never sent to the server, keeping the token client-side.
  const callbackUrl = `${appRedirectUri}#id_token=${encodeURIComponent(idToken)}&provider=google&state=${encodeURIComponent(csrfState)}`;

  res.writeHead(302, { Location: callbackUrl });
  res.end();
}
