import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

/**
 * Batch 4 Phase 2B-A / Phase 2B — iframe coverage: history and current
 * status.
 *
 * HISTORICAL RECORD (Phase 2B-A, frozen at the time): this file
 * originally documented a known, intentional coverage gap —
 * SecureAuthX's content scripts did not run inside iframes (`all_frames`
 * was not set in manifest.json), so a fingerprinting call made inside an
 * iframe was invisible to the extension. That state was verified and
 * frozen as Phase 2B-A, and this file's original comment explicitly said
 * the first assertion below was "expected to change" once a future batch
 * implemented iframe support — this is that update, made deliberately,
 * not a silently-broken test.
 *
 * CURRENT STATUS (Phase 2B): `all_frames: true` is now set on both
 * content-script entries in manifest.json, and background.js aggregates
 * fingerprint techniques across all frames of a tab (see
 * `collectCrossFrameFingerprintTechniques` in background.js). The
 * assertion below is UPDATED to reflect this: the same iframe-only
 * fingerprinting call that was previously invisible is now correctly
 * detected. Same-origin iframe coverage specifically (this test uses an
 * iframe served from the SAME origin as its container) is covered here;
 * cross-origin, multi-frame, deduplication, and nested-iframe scenarios
 * are covered in the new tests/e2e/iframe-fingerprinting.spec.js.
 */

const PORT = 8219;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("Phase 2B fix confirmed: a fingerprinting call made inside a SAME-ORIGIN iframe IS now detected (was the Phase 2B-A blind spot)", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("iframe-blindspot-container.html"), { waitUntil: "load" });

    // Confirm the iframe's inner content actually loaded and its
    // fingerprinting call actually executed, so the result below is
    // attributable specifically to iframe detection, not coincidence.
    const innerFrame = testPage.frameLocator("iframe");
    await expect(innerFrame.locator("#result")).toHaveText("call executed inside iframe", { timeout: 10_000 });

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("timezone");
    expect(result.count).toBe(1);
  } finally {
    await context.close();
  }
});

test("Control: the identical fingerprinting call made at the TOP LEVEL (no iframe) is still correctly detected", async () => {
  // Reuses the existing, already-proven timezone-positive.html fixture --
  // no new fixture needed for this half. This rules out "the detector
  // itself is broken" as an explanation for the negative result above:
  // the same exact API call, made at the top level instead of inside an
  // iframe, is detected exactly as it always has been.
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
