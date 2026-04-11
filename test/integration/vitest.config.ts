import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 120_000, // containers take time to start
    hookTimeout: 120_000,
  },
});
