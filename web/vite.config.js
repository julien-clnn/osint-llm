import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, the frontend (5173) proxies /api to the FastAPI backend (8000), which
// avoids any CORS issue and lets SSE stream without extra configuration.
//
// `--mode demo` (npm run build:demo) builds the backend-less demo: VITE_DEMO=1
// from .env.demo, recorded data from public-demo/, relative asset paths so
// the folder can be uploaded to any static host, under any path.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === "demo" ? "./" : "/",
  publicDir: mode === "demo" ? "public-demo" : "public",
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    // SSE doesn't like being split up; keep the build simple and predictable.
    chunkSizeWarningLimit: 1200,
  },
}));
