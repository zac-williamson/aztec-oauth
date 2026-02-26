import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Tests run in Node environment by default (no browser polyfills)
    environment: "node",
  },
});
