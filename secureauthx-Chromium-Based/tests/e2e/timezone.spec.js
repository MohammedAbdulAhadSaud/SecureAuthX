import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

const PORT = 8213;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("Timezone positive: Intl.DateTimeFormat().resolvedOptions().timeZone is detected as timezone", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("timezone-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("timezone");

    // Data minimization: the actual timezone value must never appear
    // anywhere in the popup's rendered text, only the technique name.
    const systemTimeZone = await testPage.evaluate(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
    if (systemTimeZone && systemTimeZone !== "UTC") {
      expect(result.listText).not.toContain(systemTimeZone);
    }
  } finally {
    await context.close();
  }
});

test("Timezone negative: a page that never reads resolvedOptions() is NOT detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("timezone-negative.html"), { waitUntil: "load" });
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).not.toContain("timezone");
  } finally {
    await context.close();
  }
});
