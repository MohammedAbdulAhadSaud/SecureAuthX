import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

const PORT = 8214;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("Locale positive: navigator.language and navigator.languages are both detected as the single 'locale' technique", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("locale-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("locale");

    // Batch 3 requirement re-verified in real Chrome: navigator.languages
    // shares the "locale" technique rather than introducing a second,
    // separately-weighted entry.
    const localeOccurrences = (result.listText.match(/locale/g) || []).length;
    expect(localeOccurrences).toBe(1);
  } finally {
    await context.close();
  }
});

test("Locale negative: a page that never reads navigator.language(s) is NOT detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("locale-negative.html"), { waitUntil: "load" });
    await testPage.waitForTimeout(300);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).not.toContain("locale");
  } finally {
    await context.close();
  }
});
