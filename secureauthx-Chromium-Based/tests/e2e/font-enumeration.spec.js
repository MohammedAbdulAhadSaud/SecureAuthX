import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

const PORT = 8215;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("Font enumeration positive: 20 measureText() calls (above the >15 threshold) are detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("font-enumeration-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("fontEnumeration");
  } finally {
    await context.close();
  }
});

test("Font enumeration negative: 3 measureText() calls (well under the threshold) are NOT detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("font-enumeration-negative.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).not.toContain("fontEnumeration");
  } finally {
    await context.close();
  }
});

test("Font enumeration negative (Batch 4 Phase 2A false-positive fix): 47 measureText() calls in ONE constant font (word-wrap layout) are NOT detected", async () => {
  // This is the specific case the old ">15 total calls" heuristic would
  // have INCORRECTLY flagged (47 > 15) despite only ever using one font --
  // exactly the false-positive class Phase 2A's distinct-font-aware
  // algorithm exists to fix. This test would have FAILED against the old
  // implementation.
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("font-enumeration-negative-wordwrap.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).not.toContain("fontEnumeration");
  } finally {
    await context.close();
  }
});
