import { describe, it, expect } from "vitest";
import { buildAuthRedirectUrl, decodeJwt, generateCsrf } from "../src/oauth.js";

describe("generateCsrf", () => {
  it("generates a 64-char hex string", () => {
    const csrf = generateCsrf();
    expect(csrf).toMatch(/^[0-9a-f]{64}$/);
  });

  it("generates unique values", () => {
    const a = generateCsrf();
    const b = generateCsrf();
    expect(a).not.toBe(b);
  });
});

describe("buildAuthRedirectUrl", () => {
  it("builds correct URL with all params", () => {
    const url = buildAuthRedirectUrl({
      serviceUrl: "https://auth.example.com",
      provider: "google",
      nonce: "0xabc123",
      redirectUri: "https://myapp.com/page",
      state: "csrf-token",
    });

    const parsed = new URL(url);
    expect(parsed.origin).toBe("https://auth.example.com");
    expect(parsed.pathname).toBe("/auth/google");
    expect(parsed.searchParams.get("nonce")).toBe("0xabc123");
    expect(parsed.searchParams.get("redirect_uri")).toBe("https://myapp.com/page");
    expect(parsed.searchParams.get("state")).toBe("csrf-token");
  });

  it("handles apple provider", () => {
    const url = buildAuthRedirectUrl({
      serviceUrl: "https://auth.example.com",
      provider: "apple",
      nonce: "0x123",
      redirectUri: "https://myapp.com",
      state: "s",
    });
    expect(url).toContain("/auth/apple");
  });
});

describe("decodeJwt", () => {
  it("decodes a JWT header and payload", () => {
    // Build a minimal JWT (header.payload.signature)
    const header = { alg: "RS256", kid: "test-kid-123", typ: "JWT" };
    const payload = {
      iss: "https://accounts.google.com",
      sub: "user-456",
      nonce: "0xdeadbeef",
    };

    const headerB64 = btoa(JSON.stringify(header))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const payloadB64 = btoa(JSON.stringify(payload))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const jwt = `${headerB64}.${payloadB64}.fake-signature`;

    const decoded = decodeJwt(jwt);
    expect(decoded.header.alg).toBe("RS256");
    expect(decoded.header.kid).toBe("test-kid-123");
    expect(decoded.payload.iss).toBe("https://accounts.google.com");
    expect(decoded.payload.sub).toBe("user-456");
  });

  it("throws on invalid JWT format", () => {
    expect(() => decodeJwt("not-a-jwt")).toThrow("Invalid JWT format");
    expect(() => decodeJwt("a.b")).toThrow("Invalid JWT format");
  });
});
