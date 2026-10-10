import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, the frontend (5173) proxies /api to the FastAPI backend (8000), which
// avoids any CORS issue and lets SSE stream without extra configuration.
export default defineConfig({
  plugins: [react()],
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
});
