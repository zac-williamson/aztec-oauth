import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as http from "node:http";
import { createServer } from "../src/server.js";
import type { ServiceConfig } from "../src/config.js";

const mockConfig: ServiceConfig = {
  port: 0, // Let OS assign port
  serviceUrl: "http://localhost:3000",
  google: {
    clientId: "test-client-id",
    clientSecret: "test-secret",
  },
  apple: null,
  allowedOrigins: ["http://localhost:5173"],
};

describe("OAuth Service Server", () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    server = createServer(mockConfig);
    await new Promise<void>((resolve) => {
      server.listen(0, () => {
        const addr = server.address() as { port: number };
        baseUrl = `http://localhost:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("GET /health returns ok", async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe("ok");
  });

  it("GET /auth/google redirects to Google with correct params", async () => {
    const params = new URLSearchParams({
      nonce: "0xdeadbeef",
      redirect_uri: "http://localhost:5173/bind",
      state: "csrf-123",
    });

    const res = await fetch(`${baseUrl}/auth/google?${params}`, {
      redirect: "manual",
    });

    expect(res.status).toBe(302);
    const location = res.headers.get("location")!;
    expect(location).toContain("accounts.google.com");
    expect(location).toContain("nonce=0xdeadbeef");
    expect(location).toContain("client_id=test-client-id");
  });

  it("GET /auth/google rejects missing params", async () => {
    const res = await fetch(`${baseUrl}/auth/google`);
    expect(res.status).toBe(400);
  });

  it("GET /auth/google rejects disallowed redirect_uri", async () => {
    const params = new URLSearchParams({
      nonce: "0x1234",
      redirect_uri: "https://evil.com/steal",
      state: "csrf",
    });

    const res = await fetch(`${baseUrl}/auth/google?${params}`);
    expect(res.status).toBe(403);
  });

  it("GET /callback/google with error redirects with error", async () => {
    const state = Buffer.from(
      JSON.stringify({ s: "csrf", r: "http://localhost:5173/bind" })
    ).toString("base64url");

    const params = new URLSearchParams({
      error: "access_denied",
      state,
    });

    const res = await fetch(`${baseUrl}/callback/google?${params}`, {
      redirect: "manual",
    });

    expect(res.status).toBe(302);
    const location = res.headers.get("location")!;
    expect(location).toContain("http://localhost:5173/bind");
    expect(location).toContain("error=access_denied");
  });

  it("GET /callback/google rejects missing code", async () => {
    const res = await fetch(`${baseUrl}/callback/google`);
    expect(res.status).toBe(400);
  });

  it("returns 404 for unknown routes", async () => {
    const res = await fetch(`${baseUrl}/unknown`);
    expect(res.status).toBe(404);
  });
});
