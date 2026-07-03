import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    pool: "threads",
    hookTimeout: 30000,
    testTimeout: 30000,
    // Exclude node_modules and the dist compilation folder
    exclude: ["**/node_modules/**", "**/dist/**"],
  },
});
