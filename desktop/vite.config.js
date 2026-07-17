import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed dev server port (see src-tauri/tauri.conf.json → build.devUrl) and
// wants to be told about file changes it triggers itself (src-tauri/**) so we don't loop.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    // Never watch Rust build outputs — on Windows the .dll is locked by cargo (EBUSY).
    watch: {
      ignored: [
        "**/src-tauri/**",
        "**/target/**",
        "**/*.dll",
        "**/*.pdb",
        "**/*.exe",
      ],
    },
  },
});
