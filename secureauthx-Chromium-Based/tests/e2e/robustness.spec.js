import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 8216;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("Robustness: malformed data-sax-signals attribute does not crash the extension, and the real signal that follows is still detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    // This page writes invalid JSON into the signal attribute before
    // content.js's drain runs, then makes a real, legitimate timezone
    // call afterward.
    await testPage.goto(server.url("robustness-malformed-attribute.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    // The scan itself completing (not hanging/throwing) is part of what's
    // under test here -- runScanAndReadFingerprintResult already asserts
    // this implicitly by waiting for real data to populate.
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("timezone");
    // No corrupted/garbage technique names should appear.
    expect(result.listText).not.toContain("not valid json");
    expect(result.listText).not.toContain("undefined");
  } finally {
    await context.close();
  }
});

test("Robustness: repeated triggering of the same fingerprint API produces exactly one detected entry, not duplicates", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("timezone-positive.html"), { waitUntil: "load" });
    // Trigger the same API repeatedly -- mirrors a page (or an adversarial
    // one) calling it many times in a loop.
    for (let i = 0; i < 10; i++) {
      await testPage.click("#runBtn");
    }
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    const occurrences = (result.listText.match(/timezone/g) || []).length;
    expect(occurrences).toBe(1);
  } finally {
    await context.close();
  }
});

test("Robustness: signal dedup holds across the document_idle boundary (fires once before, once after, still one entry)", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("timezone-positive.html"), { waitUntil: "load" });
    // One call as early as possible (exercises the pre-document_idle /
    // DOM-attribute catch-up path), then another after a delay long
    // enough for content.js's document_idle listener to certainly have
    // attached (exercises the live-event path). Both should collapse
    // into the same single, deduplicated entry.
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(1000);
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    const occurrences = (result.listText.match(/timezone/g) || []).length;
    expect(occurrences).toBe(1);
  } finally {
    await context.close();
  }
});

test("Robustness: extension/page isolation — the page cannot reach this extension's runtime", async () => {
  // Static check, not just a runtime probe: confirm the manifest declares
  // no externally_connectable surface, which is what would be required
  // for a page to message this extension directly at all.
  const manifestPath = path.resolve(__dirname, "../../manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  expect(manifest.externally_connectable).toBeUndefined();

  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("timezone-positive.html"), { waitUntil: "load" });

    // From the page's own realm, chrome.runtime.sendMessage targeting
    // this specific extension ID should fail (no externally_connectable
    // entry matches this page's origin) -- confirming a page cannot
    // directly invoke privileged extension behavior.
    const canMessageExtension = await testPage.evaluate((extId) => {
      return new Promise((resolve) => {
        try {
          if (!window.chrome || !chrome.runtime || !chrome.runtime.sendMessage) {
            resolve(false);
            return;
          }
          chrome.runtime.sendMessage(extId, { type: "SAX_RUN_FULL_ANALYSIS" }, (response) => {
            // chrome.runtime.lastError set (or no meaningful response) is
            // the expected outcome for an extension with no
            // externally_connectable entry.
            resolve(!chrome.runtime.lastError && !!response);
          });
          setTimeout(() => resolve(false), 2000);
        } catch {
          resolve(false);
        }
      });
    }, extensionId);

    expect(canMessageExtension).toBe(false);
  } finally {
    await context.close();
  }
});

test("Robustness: positive fingerprint results never expose the underlying sensitive value, only the technique name", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("locale-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const actualLanguage = await testPage.evaluate(() => navigator.language);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("locale");
    // The technique name is expected; the actual locale value is not.
    if (actualLanguage) {
      expect(result.listText).not.toContain(actualLanguage);
    }
  } finally {
    await context.close();
  }
});

test("Robustness (Batch 4 Phase 2A): flooding measureText() with 1000 distinct fonts does not crash, hang, or duplicate the fontEnumeration entry", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("robustness-font-flood.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    // 1000 calls should still complete near-instantly given the bounded
    // tracking sets -- if this hangs, that itself is a real defect.
    await testPage.locator("#result").filter({ hasText: "completed" }).waitFor({ timeout: 10_000 });

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("fontEnumeration");
    const occurrences = (result.listText.match(/fontEnumeration/g) || []).length;
    expect(occurrences).toBe(1);
  } finally {
    await context.close();
  }
});

test("Robustness (Batch 4 Phase 2A): malformed Client Hints arguments do not crash the extension, and the real call that follows is still detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("robustness-client-hints-malformed.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.locator("#result").filter({ hasText: "completed" }).waitFor({ timeout: 10_000 });

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("clientHintsHighEntropy");
  } finally {
    await context.close();
  }
});
