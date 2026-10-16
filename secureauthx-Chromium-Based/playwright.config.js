// @ts-check
import { defineConfig } from "@playwright/test";

/**
 * SecureAuthX Batch 4 Phase 1 — E2E config.
 *
 * headless MUST stay false. This was not a style choice: standard headless
 * Chromium was directly tested against this extension during the Phase 1
 * design and confirmed NOT to load the unpacked extension's content
 * scripts at all (no service worker registers, the MAIN-world hook never
 * installs). Genuinely headed Chrome, run under a virtual display
 * (xvfb-run — see package.json's "test:e2e" script), is the only
 * confirmed-working combination in this class of environment. Do not
 * "simplify" this back to headless without re-validating extension
 * loading first.
 */
export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "**/*.spec.js",
  timeout: 30_000,
  fullyParallel: false, // each test launches its own full browser + extension; keep this modest and predictable rather than racing several Chromium instances
  retries: 0, // a flaky pass should not be masked in Phase 1 — surface timing problems, don't hide them
  reporter: [["list"]],
  use: {
    headless: false,
    trace: "retain-on-failure",
  },
});
