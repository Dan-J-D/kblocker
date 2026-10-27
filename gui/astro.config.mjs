import { defineConfig } from "astro/config";
import svelte from "@astrojs/svelte";
import tailwindcss from "@tailwindcss/vite";

// Tauri serves the static build from dist/ and points its dev window at :4321
export default defineConfig({
  output: "static",
  integrations: [svelte()],
  server: { port: 4321, host: "127.0.0.1" },
  vite: {
    plugins: [tailwindcss()],
    clearScreen: false,
    envPrefix: ["VITE_", "TAURI_"],
  },
});
