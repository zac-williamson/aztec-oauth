export interface ServiceConfig {
  port: number;
  serviceUrl: string;
  google: {
    clientId: string;
    clientSecret: string;
  };
  apple: {
    clientId: string;
    teamId: string;
    keyId: string;
    privateKeyPath: string;
  } | null;
  allowedOrigins: string[];
}

export function loadConfig(): ServiceConfig {
  const env = process.env;

  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    throw new Error("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required");
  }

  const allowedOrigins = (env.ALLOWED_ORIGINS || "http://localhost:5173")
    .split(",")
    .map((s) => s.trim());

  return {
    port: parseInt(env.PORT || "3000", 10),
    serviceUrl: env.SERVICE_URL || `http://localhost:${env.PORT || "3000"}`,
    google: {
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
    },
    apple:
      env.APPLE_CLIENT_ID && env.APPLE_TEAM_ID && env.APPLE_KEY_ID
        ? {
            clientId: env.APPLE_CLIENT_ID,
            teamId: env.APPLE_TEAM_ID,
            keyId: env.APPLE_KEY_ID,
            privateKeyPath: env.APPLE_PRIVATE_KEY_PATH || "",
          }
        : null,
    allowedOrigins,
  };
}

/**
 * Validate that a redirect URI's origin is in the allowed list.
 */
export function isAllowedOrigin(
  redirectUri: string,
  allowedOrigins: string[]
): boolean {
  try {
    const url = new URL(redirectUri);
    return allowedOrigins.some((origin) => url.origin === origin);
  } catch {
    return false;
  }
}
