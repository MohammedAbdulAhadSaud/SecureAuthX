import { chromium } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const EXTENSION_PATH = path.resolve(__dirname, "../../../");

/**
 * Launches a fresh, isolated Chromium instance with the unpacked
 * SecureAuthX extension loaded, and waits for its MV3 service worker to
 * register.
 *
 * headless: false is required -- confirmed during Phase 1 design that
 * standard headless Chromium does not load this extension's content
 * scripts at all in this class of environment. The whole process this
 * runs under must itself be wrapped in `xvfb-run` (see package.json's
 * "test:e2e" script) since there is no real display otherwise.
 *
 * Each call gets its own brand-new temp user-data directory, so tests
 * never share Master Profile state or leak signals between runs.
 */
export async function launchWithExtension() {
  const userDataDir = mkdtempSync(path.join(tmpdir(), "sax-e2e-"));

  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      "--no-sandbox",
      "--disable-setuid-sandbox",
    ],
  });

  let [worker] = context.serviceWorkers();
  if (!worker) {
    worker = await context.waitForEvent("serviceworker", { timeout: 15_000 });
  }
  const extensionId = worker.url().split("/")[2];

  return { context, extensionId, userDataDir };
}
