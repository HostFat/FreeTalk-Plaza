import { defineConfig, devices } from "@playwright/test";

// Local-only integration suite against a running Freenet node and the
// published FreeTalk web container. No webServer: the node must be running.
//
//   $env:PLAZA_REAL_NODE_URL = "http://127.0.0.1:7509/v1/contract/web/<id>/index.html"
//   npx playwright test -c playwright.real-node.config.ts
export default defineConfig({
  testDir: "./real-node",
  timeout: 180_000,
  retries: 0,
  // All tests share one node and one delegate store.
  workers: 1,
  fullyParallel: false,
  use: {
    trace: "on-first-retry",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
