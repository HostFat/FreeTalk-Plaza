import { defineConfig, devices } from "@playwright/test";

// Run against a Dioxus dev server with the fixture data:
//
//   cd ui
//   dx serve --port 8082 --hot-reload false --watch false \
//     --features example-data,no-sync
//
// Then: cd ui/tests && npm test
//
// `example-data` seeds four boards; `no-sync` keeps the tests off the node.
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 60_000,
  retries: 1,
  fullyParallel: true,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:8082",
    navigationTimeout: 30_000,
    actionTimeout: 10_000,
    trace: "on-first-retry",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile-chrome", use: { ...devices["Pixel 5"] } },
  ],
});
