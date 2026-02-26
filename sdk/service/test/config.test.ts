import { describe, it, expect } from "vitest";
import { isAllowedOrigin } from "../src/config.js";

describe("isAllowedOrigin", () => {
  const allowed = ["http://localhost:5173", "https://myapp.com"];

  it("allows matching origins", () => {
    expect(isAllowedOrigin("http://localhost:5173/some/path", allowed)).toBe(true);
    expect(isAllowedOrigin("https://myapp.com/bind", allowed)).toBe(true);
  });

  it("rejects non-matching origins", () => {
    expect(isAllowedOrigin("https://evil.com/steal", allowed)).toBe(false);
    expect(isAllowedOrigin("http://localhost:3000/", allowed)).toBe(false);
  });

  it("rejects invalid URLs", () => {
    expect(isAllowedOrigin("not-a-url", allowed)).toBe(false);
    expect(isAllowedOrigin("", allowed)).toBe(false);
  });

  it("matches origin exactly, not substring", () => {
    expect(isAllowedOrigin("http://localhost:51730/", allowed)).toBe(false);
    expect(isAllowedOrigin("https://myapp.com.evil.com/", allowed)).toBe(false);
  });
});
