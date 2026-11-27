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
// Playwright starts the server itself unless one is already listening
// (test-e2e.ps1 starts one locally). On CI, `dx` comes from the Nix shell.
const webServerCommand =
  process.env.PLAYWRIGHT_WEB_SERVER_COMMAND ??
  "node ./tests/serve-example.mjs";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  testIgnore: ["real-node/**"],
  timeout: 60_000,
  retries: 1,
  fullyParallel: true,
  reporter: process.env.CI
    ? [["github"], ["list"], ["html", { open: "never" }]]
    : "list",
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:8082",
    navigationTimeout: 30_000,
    actionTimeout: 10_000,
    trace: "on-first-retry",
  },
  webServer: {
    command: webServerCommand,
    cwd: "..",
    // serve-example.mjs builds first and starts the static server afterwards,
    // so this URL is only reachable when the bundle is ready.
    url: "http://localhost:8082/",
    reuseExistingServer: !process.env.CI,
    timeout: 600_000,
    stdout: "pipe",
    stderr: "pipe",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
    { name: "mobile-chrome", use: { ...devices["Pixel 5"] } },
  ],
});
