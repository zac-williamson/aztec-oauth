import { describe, it, expect } from "vitest";
import { buildGoogleAuthUrl, decodeOAuthState } from "../src/google.js";
import type { ServiceConfig } from "../src/config.js";

const mockConfig: ServiceConfig = {
  port: 3000,
  serviceUrl: "http://localhost:3000",
  google: {
    clientId: "test-client-id",
    clientSecret: "test-secret",
  },
  apple: null,
  allowedOrigins: ["http://localhost:5173"],
};

describe("buildGoogleAuthUrl", () => {
  it("builds a valid Google OAuth URL", () => {
    const url = buildGoogleAuthUrl({
      config: mockConfig,
      nonce: "0x1234abcd",
      redirectUri: "http://localhost:5173/bind",
      state: "csrf-token-123",
    });

    const parsed = new URL(url);
    expect(parsed.origin).toBe("https://accounts.google.com");
    expect(parsed.pathname).toBe("/o/oauth2/v2/auth");
    expect(parsed.searchParams.get("client_id")).toBe("test-client-id");
    expect(parsed.searchParams.get("response_type")).toBe("code");
    expect(parsed.searchParams.get("scope")).toBe("openid");
    expect(parsed.searchParams.get("nonce")).toBe("0x1234abcd");
    expect(parsed.searchParams.get("redirect_uri")).toBe(
      "http://localhost:3000/callback/google"
    );
  });

  it("encodes redirect_uri and state in the state param", () => {
    const url = buildGoogleAuthUrl({
      config: mockConfig,
      nonce: "0x1234",
      redirectUri: "http://localhost:5173/bind",
      state: "csrf-token",
    });

    const parsed = new URL(url);
    const stateParam = parsed.searchParams.get("state")!;
    const decoded = decodeOAuthState(stateParam);

    expect(decoded.s).toBe("csrf-token");
    expect(decoded.r).toBe("http://localhost:5173/bind");
  });
});

describe("decodeOAuthState", () => {
  it("round-trips state encoding", () => {
    const encoded = Buffer.from(
      JSON.stringify({ s: "csrf", r: "http://app.com/page" })
    ).toString("base64url");

    const decoded = decodeOAuthState(encoded);
    expect(decoded.s).toBe("csrf");
    expect(decoded.r).toBe("http://app.com/page");
  });

  it("throws on invalid base64", () => {
    expect(() => decodeOAuthState("not-valid!!!")).toThrow();
  });
});
