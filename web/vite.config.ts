import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// In dev, proxy the BFF so the browser talks to a single origin (cookies just work).
// In production the web container's nginx proxies /api and /auth to the BFF Service.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8090", changeOrigin: true },
      "/auth": { target: "http://localhost:8090", changeOrigin: true },
    },
  },
  build: { outDir: "dist" },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/setupTests.ts"],
    css: false,
  },
});
