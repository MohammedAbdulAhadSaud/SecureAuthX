export const TEST_MASTER_PASSWORD = "E2ETestMasterPassword123!";

/**
 * Opens the real SecureAuthX popup HTML, completes onboarding via actual
 * form interaction if this is a fresh profile, then returns the popup
 * Page for further interaction.
 */
export async function openPopup(context, extensionId) {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);

  const onboarding = popup.locator("#onboarding");
  if (await onboarding.isVisible().catch(() => false)) {
    await popup.fill("#obMaster1", TEST_MASTER_PASSWORD);
    await popup.fill("#obMaster2", TEST_MASTER_PASSWORD);
    await popup.click("#obSaveBtn");
    await popup.locator("#appRoot").waitFor({ state: "visible", timeout: 5_000 });
  }

  return popup;
}

/**
 * Runs the Site Analysis scan for `testPage` and returns the real,
 * user-visible fingerprinting result read from the popup DOM.
 *
 * Two things here are NOT incidental and must not be "cleaned up" without
 * re-testing against real Chrome first:
 *
 * 1. `testPage.bringToFront()` immediately before clicking the tab.
 *    background.js resolves what to analyze via
 *    `chrome.tabs.query({active:true, currentWindow:true})`. Opening the
 *    popup as a normal tab (the only way Playwright can reach it, since it
 *    cannot click a real toolbar icon to spawn a floating popup) makes
 *    that popup tab itself eligible to be "active" -- without this
 *    explicit re-focus, background.js reports "No analyzable page in the
 *    active tab" instead of analyzing the intended page. This was found
 *    empirically during Phase 1 design, not by reading the code alone.
 * 2. Completion is detected by polling for `#dashSecurity`'s text to
 *    change away from its "—" placeholder, NOT by waiting for
 *    `#dashboardLoading` to become hidden. That element's "hidden" class
 *    (and `#dashboardContent`'s) has no matching CSS rule in popup.css --
 *    a pre-existing, cosmetic defect present since before Batch 1 (not
 *    introduced by any batch of this project, confirmed byte-identical
 *    against the original upload) -- so `#dashboardLoading` never
 *    actually becomes hidden. This has been reported separately as a
 *    production defect and is intentionally NOT fixed here; this helper
 *    only adapts to the real, current behavior rather than an assumed
 *    one. Polling actual data content is also a more accurate signal of
 *    "the scan finished" than a visibility class would be anyway.
 * 3. `#fingerprintList` is read via `.textContent()`, not `.innerText()`.
 *    That element lives inside a collapsed (no `open` attribute) native
 *    `<details>`. Chrome's default stylesheet sets non-summary content of
 *    a closed `<details>` to `display:none`, and `.innerText()` respects
 *    that (returns ""), while `.textContent()` returns the real markup
 *    text regardless of collapsed state -- which is what a user would see
 *    the moment they expand that section, i.e. the actual result.
 */
async function waitForScanToComplete(popup) {
  await popup.waitForFunction(
    () => {
      const el = document.getElementById("dashSecurity");
      return !!el && el.textContent.trim() !== "" && el.textContent.trim() !== "—";
    },
    { timeout: 15_000 }
  );
}

async function readFingerprintResult(popup) {
  const fingerprintCountText = await popup.locator("#fingerprintCount").textContent();
  const fingerprintListText = await popup.locator("#fingerprintList").textContent();
  return {
    count: Number.parseInt((fingerprintCountText || "").trim(), 10) || 0,
    listText: fingerprintListText || "",
  };
}

export async function runScanAndReadFingerprintResult(testPage, popup) {
  await testPage.bringToFront();
  await popup.locator('[data-tab="analysis"]').click();
  await waitForScanToComplete(popup);
  return readFingerprintResult(popup);
}

/**
 * Forces a fresh scan even if the dashboard was already loaded once this
 * popup session (mirrors clicking "Re-scan This Page" for real).
 */
export async function rescan(testPage, popup) {
  await testPage.bringToFront();
  await popup.locator("#rescanBtn").click();
  await waitForScanToComplete(popup);
  return readFingerprintResult(popup);
}

