import { test, expect } from "@playwright/test";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, runScanAndReadFingerprintResult } from "./helpers/popup.js";
import { serveFixtures } from "./helpers/serve-fixtures.js";

const PORT = 8218;
let server;

test.beforeAll(() => {
  server = serveFixtures(PORT);
});

test.afterAll(() => {
  server.close();
});

test("Client Hints positive: requesting model+architecture+platformVersion together is detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("client-hints-positive.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).toContain("clientHintsHighEntropy");

    // Data minimization: the actual returned device values must never
    // appear anywhere in the popup's rendered text.
    const actualArchitecture = await testPage.evaluate(async () => {
      const values = await navigator.userAgentData.getHighEntropyValues(["architecture"]);
      return values.architecture;
    });
    if (actualArchitecture) {
      expect(result.listText).not.toContain(actualArchitecture);
    }
  } finally {
    await context.close();
  }
});

test("Client Hints negative: requesting a single common field (platformVersion) alone is NOT detected", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const testPage = await context.newPage();
    await testPage.goto(server.url("client-hints-negative.html"), { waitUntil: "load" });
    await testPage.click("#runBtn");
    await testPage.waitForTimeout(500);

    const popup = await openPopup(context, extensionId);
    const result = await runScanAndReadFingerprintResult(testPage, popup);

    expect(result.listText).not.toContain("clientHintsHighEntropy");
  } finally {
    await context.close();
  }
});
