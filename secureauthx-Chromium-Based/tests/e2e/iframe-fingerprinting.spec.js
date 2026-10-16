import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

/**
 * Batch 4 Phase 2B — iframe fingerprinting support.
 *
 * Covers the scenarios NOT already covered by the updated
 * tests/e2e/iframe-blindspot.spec.js (same-origin coverage + its top-
 * level control): cross-origin iframes, multiple iframes aggregated
 * together with the main page's own signal, duplicate-technique dedup
 * across frames, and nested iframes.
 */

const PORT = 8220;
const CROSS_ORIGIN_PORT = 8221;
let server;
let crossOriginServer;

test.beforeAll(() => {
  server = serveFixtures(PORT);
  crossOriginServer = serveFixtures(CROSS_ORIGIN_PORT);
});

test.afterAll(() => {
  server.close();
  crossOriginServer.close();
});

test("Sanity check: top-level fingerprint detection is unaffected by all_frames being enabled", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("timezone-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("timezone");
  } finally {
    await context.close();
  }
});

test("Cross-origin iframe: a fingerprinting call inside a different-origin iframe is detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    const crossOriginInnerUrl = crossOriginServer.url("iframe-blindspot-inner.html");
    await testPage.goto(
      `${server.url("iframe-cross-origin-container.html")}?crossOriginSrc=${encodeURIComponent(crossOriginInnerUrl)}`,
      { waitUntil: "load" }
    );

    const innerFrame = testPage.frameLocator("#crossOriginFrame");
    await expect(innerFrame.locator("#result")).toHaveText("call executed inside iframe", { timeout: 10_000 });

    // Confirm this genuinely is cross-origin before trusting the result below.
    const topOrigin = new URL(testPage.url()).origin;
    const iframeOrigin = new URL(crossOriginInnerUrl).origin;
    expect(iframeOrigin).not.toBe(topOrigin);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("timezone");
  } finally {
    await context.close();
  }
});

test("Multiple iframes + main page combined: three distinct techniques from three different sources all appear together", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("iframe-combined-container.html"), { waitUntil: "load" });
    await expect(testPage.locator("#mainResult")).toHaveText("main-page call executed", { timeout: 10_000 });

    // Trigger each iframe's own "Run" button via frameLocator.
    await testPage.frameLocator("#frame1").locator("#runBtn").click();
    await testPage.frameLocator("#frame2").locator("#runBtn").click();
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    // Main page (locale), iframe 1 (canvasFingerprint), iframe 2 (webglExtensionEnumeration).
    expect(result.listText).toContain("locale");
    expect(result.listText).toContain("canvasFingerprint");
    expect(result.listText).toContain("webglExtensionEnumeration");
    expect(result.count).toBe(3);
  } finally {
    await context.close();
  }
});

test("Duplicate technique across frames: two iframes performing the SAME technique are deduplicated to one entry", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("iframe-duplicate-container.html"), { waitUntil: "load" });

    const frames = testPage.frames().filter((f) => f !== testPage.mainFrame());
    for (const frame of frames) {
      await frame.locator("#result").waitFor({ state: "attached", timeout: 10_000 }).catch(() => {});
    }
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("timezone");
    expect(result.count).toBe(1);
    const occurrences = (result.listText.match(/timezone/g) || []).length;
    expect(occurrences).toBe(1);
  } finally {
    await context.close();
  }
});

test("Nested iframes: a fingerprinting call two levels deep is still detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("iframe-nested-outer.html"), { waitUntil: "load" });

    // Navigate down two frame levels to confirm the innermost call actually ran.
    const middleFrame = testPage.frameLocator("iframe");
    const innerFrame = middleFrame.frameLocator("iframe");
    await expect(innerFrame.locator("#result")).toHaveText("call executed inside iframe", { timeout: 10_000 });

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("timezone");
  } finally {
    await context.close();
  }
});
