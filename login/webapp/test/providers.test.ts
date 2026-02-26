/**
 * Unit tests for OAuth provider utilities.
 * These tests are pure logic — no Aztec SDK or browser APIs needed.
 */

import { describe, it, expect } from "vitest";
import {
  GOOGLE_PROVIDER,
  APPLE_PROVIDER,
  buildAuthUrl,
  extractIdToken,
  decodeJwt,
} from "../src/lib/providers";

describe("Providers", () => {
  describe("buildAuthUrl", () => {
    it("includes nonce in Google auth URL", () => {
      const url = buildAuthUrl(GOOGLE_PROVIDER, "0xdeadbeef", "http://localhost:3000");
      expect(url).toContain("nonce=0xdeadbeef");
      expect(url).toContain("accounts.google.com");
      expect(url).toContain("redirect_uri=http%3A%2F%2Flocalhost%3A3000");
    });

    it("includes nonce in Apple auth URL", () => {
      const url = buildAuthUrl(APPLE_PROVIDER, "0xcafe", "http://localhost:3000");
      expect(url).toContain("nonce=0xcafe");
      expect(url).toContain("appleid.apple.com");
    });

    it("includes response_type=id_token", () => {
      const url = buildAuthUrl(GOOGLE_PROVIDER, "nonce123", "http://localhost:3000");
      expect(url).toContain("response_type=id_token");
    });
  });

  describe("extractIdToken", () => {
    it("extracts id_token from URL fragment", () => {
      const hash = "#id_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig&state=abc";
      const token = extractIdToken(hash);
      expect(token).toBe("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig");
    });

    it("returns null if no id_token", () => {
      const hash = "#access_token=abc&state=def";
      const token = extractIdToken(hash);
      expect(token).toBeNull();
    });
  });

  describe("decodeJwt", () => {
    it("decodes header and payload", () => {
      // Manually create a JWT-like string
      const header = { alg: "RS256", kid: "test-key-1" };
      const payload = { sub: "user123", iss: "https://accounts.google.com" };
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
      expect(decoded.header.kid).toBe("test-key-1");
      expect(decoded.payload.sub).toBe("user123");
      expect(decoded.payload.iss).toBe("https://accounts.google.com");
    });

    it("throws for invalid JWT format", () => {
      expect(() => decodeJwt("not-a-jwt")).toThrow("Invalid JWT format");
    });
  });
});
