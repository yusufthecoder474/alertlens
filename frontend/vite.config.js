import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig(({ command, mode }) => {
  // Local dev: the browser talks to same-origin /api (see src/api.js);
  // Vite forwards it to the API and strips the /api prefix, mirroring
  // the nginx proxy_pass in frontend/nginx.conf.template. The API
  // requires X-API-Key on every request, so the dev server (Node, not
  // the browser) injects it on proxied requests — the same job nginx
  // does in Docker. The key comes from the dev server's environment;
  // there is no default and no hard-coded key anywhere. The check runs
  // only for `vite dev` (command "serve", mode "development"): Vitest
  // also loads this config with command "serve" but mode "test", and
  // tests/builds never proxy, so they do not need a key.
  let apiKey = "";
  if (command === "serve" && mode !== "test") {
    apiKey = process.env.API_KEY;
    if (!apiKey) {
      throw new Error(
        "API_KEY is required in the environment to run the Vite dev server: " +
          "it injects X-API-Key server-side for proxied /api requests. " +
          "Run `API_KEY=<your key> npm run dev` (the same key the API was started with).",
      );
    }
  }
  return {
    plugins: [react()],
    test: { environment: "jsdom", globals: true, setupFiles: "./src/test-setup.js" },
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: "http://localhost:8000",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ""),
          headers: { "X-API-Key": apiKey },
        },
      },
    },
  };
});
