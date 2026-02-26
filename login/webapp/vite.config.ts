import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import fs from "node:fs";
import path from "node:path";

/**
 * Vite plugin that serves .wasm files from node_modules with the correct
 * MIME type. Required because Aztec SDK packages (@aztec/noir-acvm_js,
 * @aztec/noir-noirc_abi) load WASM via `new URL('file.wasm', import.meta.url)`.
 * When Vite pre-bundles these into .vite/deps/, the relative URL breaks and
 * the dev server returns index.html (SPA fallback) instead of the WASM binary.
 */
function aztecWasmPlugin(): Plugin {
  // Map of known WASM files to their locations in node_modules
  const wasmFiles: Record<string, string> = {
    "acvm_js_bg.wasm": "node_modules/@aztec/noir-acvm_js/web/acvm_js_bg.wasm",
    "noirc_abi_wasm_bg.wasm":
      "node_modules/@aztec/noir-noirc_abi/web/noirc_abi_wasm_bg.wasm",
  };

  return {
    name: "aztec-wasm",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (!req.url?.endsWith(".wasm")) return next();

        const filename = req.url.split("/").pop()!;
        const relativePath = wasmFiles[filename];
        if (!relativePath) return next();

        const absolutePath = path.resolve(process.cwd(), relativePath);
        if (!fs.existsSync(absolutePath)) return next();

        const wasmBytes = fs.readFileSync(absolutePath);
        res.setHeader("Content-Type", "application/wasm");
        res.setHeader("Content-Length", wasmBytes.byteLength);
        res.end(wasmBytes);
      });
    },
  };
}

export default defineConfig({
  plugins: [
    aztecWasmPlugin(),
    react(),
    nodePolyfills({
      include: ["buffer", "crypto", "stream", "util", "process"],
      globals: { Buffer: true, process: true },
    }),
  ],
  server: {
    // Headers needed for bb WASM to work in multithreaded mode
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  },
  optimizeDeps: {
    esbuildOptions: {
      target: "esnext",
    },
  },
  build: {
    target: "esnext",
  },
});
