import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

const PORT = 8212;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("Audio positive: OfflineAudioContext render-then-read is detected as audioFingerprint", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("audio-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    // Rendering is genuinely async -- wait for the fixture's own
    // completion text rather than a fixed delay.
    await testPage.locator("#summary").filter({ hasText: "Sequence complete" }).waitFor({ timeout: 10_000 });

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("audioFingerprint");
    expect(result.listText).not.toContain("canvasFingerprint");
    expect(result.listText).not.toContain("webglDebugInfo");
  } finally {
    await context.close();
  }
});

test("Audio negative: ordinary AudioContext playback + a manually-created buffer are NOT detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("audio-negative.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).not.toContain("audioFingerprint");
  } finally {
    await context.close();
  }
});
