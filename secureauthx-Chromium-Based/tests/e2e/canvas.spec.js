import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

const PORT = 8210;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("Canvas positive: hidden/tiny/detached canvas reads are detected as canvasFingerprint", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("canvas-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("canvasFingerprint");
    // Cross-contamination check: this page never touches WebGL or Audio.
    expect(result.listText).not.toContain("webglDebugInfo");
    expect(result.listText).not.toContain("audioFingerprint");
  } finally {
    await context.close();
  }
});

test("Canvas negative: a normal, visible, ordinary-sized canvas is NOT detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    // canvas-negative.html draws and reads back automatically on load.
    await testPage.goto(server.url("canvas-negative.html"), { waitUntil: "load" });
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).not.toContain("canvasFingerprint");
  } finally {
    await context.close();
  }
});
