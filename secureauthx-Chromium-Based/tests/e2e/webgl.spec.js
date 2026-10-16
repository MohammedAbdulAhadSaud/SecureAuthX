import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

const PORT = 8211;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("WebGL positive: UNMASKED_VENDOR/RENDERER + debug-info extension request is detected as webglDebugInfo", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("webgl-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("webglDebugInfo");
    expect(result.listText).not.toContain("canvasFingerprint");
    expect(result.listText).not.toContain("audioFingerprint");
  } finally {
    await context.close();
  }
});

test("WebGL negative: ordinary getParameter/getExtension calls are NOT detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    // webgl-negative.html renders and probes ordinary parameters automatically on load.
    await testPage.goto(server.url("webgl-negative.html"), { waitUntil: "load" });
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).not.toContain("webglDebugInfo");
  } finally {
    await context.close();
  }
});
