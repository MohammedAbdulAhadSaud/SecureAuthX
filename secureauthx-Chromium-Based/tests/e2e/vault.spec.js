import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { launchWithExtension } from "./helpers/launch-extension.js";
import { openPopup, TEST_MASTER_PASSWORD } from "./helpers/popup.js";
import { serveFixtures, FIXTURES_DIR } from "./helpers/serve-fixtures.js";

/**
 * Phase 3B — formal real-Chrome E2E suite for the local password vault.
 * Real extension, real popup UI, real background service worker, real
 * content scripts. Reuses the shared launch/popup/fixture helpers.
 */

const PORT = 8222;
let server;
test.beforeAll(() => { server = serveFixtures(PORT); });
test.afterAll(() => { server.close(); });

const LOGIN_HTML = fs.readFileSync(path.join(FIXTURES_DIR, "vault-login-target.html"), "utf8");

/* ----------------------------- helpers ----------------------------- */

const send = (popup, message) => popup.evaluate((m) => browser.runtime.sendMessage(m), message);
const getProfileId = (popup) =>
  popup.evaluate(async () => (await browser.storage.local.get("sax_profiles_state")).sax_profiles_state.defaultProfileId);
const readAllStorage = (popup) => popup.evaluate(() => browser.storage.local.get(null));

async function openVaultTab(context, extensionId) {
  const popup = await openPopup(context, extensionId);
  await popup.click('[data-tab="vault"]');
  await popup.locator("#vaultLockedView").waitFor({ state: "visible" });
  return popup;
}

async function unlockViaUi(popup, password = TEST_MASTER_PASSWORD) {
  await popup.fill("#vaultUnlockPassword", password);
  await popup.click("#vaultUnlockBtn");
}

/** Popup on the Vault tab, already unlocked through the real UI. */
async function unlockedVault(context, extensionId) {
  const popup = await openVaultTab(context, extensionId);
  await unlockViaUi(popup);
  await popup.locator("#vaultUnlockedView").waitFor({ state: "visible" });
  return { popup, profileId: await getProfileId(popup) };
}

async function addViaMessage(popup, profileId, item) {
  const r = await send(popup, { type: "SAX_VAULT_ADD_ITEM", profileId, item });
  expect(r.ok, JSON.stringify(r)).toBe(true);
  return r.item;
}

/** Re-opens the Vault tab view while `target` is the focused tab (background.js resolves the active tab). */
async function refreshVaultFor(popup, target) {
  await target.bringToFront();
  await popup.click('[data-tab="passwords"]');
  await target.bringToFront();
  await popup.click('[data-tab="vault"]');
  await popup.locator("#vaultUnlockedView").waitFor({ state: "visible" });
  await popup.waitForTimeout(400);
}

async function openLoginPage(context, url) {
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "load" });
  await page.waitForTimeout(500); // let content scripts reach document_idle
  await page.bringToFront();
  return page;
}

async function mockPage(context, url) {
  await context.route(url, (route) => route.fulfill({ status: 200, contentType: "text/html", body: LOGIN_HTML }));
}

const localLogin = () => `http://localhost:${PORT}/vault-login-target.html`;

/* ============ 1-3. lock state, wrong password, unlock ============ */

test("vault is locked by default, and the background refuses every vault operation while locked", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const popup = await openVaultTab(context, extensionId);
    await expect(popup.locator("#vaultLockedView")).toBeVisible();
    await expect(popup.locator("#vaultUnlockedView")).toBeHidden();

    const profileId = await getProfileId(popup);
    expect((await send(popup, { type: "SAX_VAULT_STATUS", profileId })).unlocked).toBe(false);
    for (const message of [
      { type: "SAX_VAULT_LIST", profileId },
      { type: "SAX_VAULT_GET_ITEM", profileId, itemId: "x" },
      { type: "SAX_VAULT_ADD_ITEM", profileId, item: { site: "a.com", secret: "x" } },
      { type: "SAX_VAULT_MATCHES_FOR_ACTIVE_TAB", profileId },
      { type: "SAX_VAULT_FILL", profileId, itemId: "x" },
    ]) {
      const r = await send(popup, message);
      expect(r.ok, message.type).toBe(false);
    }
  } finally {
    await context.close();
  }
});

test("wrong master password is rejected, shows an error, and the vault stays locked", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const popup = await openVaultTab(context, extensionId);
    await unlockViaUi(popup, "ThisIsDefinitelyTheWrongPassword!");
    await expect(popup.locator("#vaultUnlockError")).toBeVisible();
    await expect(popup.locator("#vaultLockedView")).toBeVisible();
    await expect(popup.locator("#vaultUnlockedView")).toBeHidden();
    const profileId = await getProfileId(popup);
    expect((await send(popup, { type: "SAX_VAULT_STATUS", profileId })).unlocked).toBe(false);
    expect((await send(popup, { type: "SAX_VAULT_LIST", profileId })).ok).toBe(false);
  } finally {
    await context.close();
  }
});

test("correct master password unlocks the vault", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    await expect(popup.locator("#vaultUnlockError")).toBeHidden();
    expect((await send(popup, { type: "SAX_VAULT_STATUS", profileId })).unlocked).toBe(true);
  } finally {
    await context.close();
  }
});

/* ============ 4-5. create credential; list never exposes the secret ============ */

test("creating a credential via the UI lists it without the secret or notes appearing anywhere in the list HTML", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup } = await unlockedVault(context, extensionId);
    await popup.click("details:has(#vaultNewSite) summary");
    await popup.fill("#vaultNewSite", "example.com");
    await popup.fill("#vaultNewUsername", "alice@example.com");
    await popup.fill("#vaultNewSecret", "TopSecretVaultPassword1!");
    await popup.fill("#vaultNewNotes", "PrivateNoteText-42");
    await popup.click("#vaultAddBtn");
    await popup.locator("#vaultItemsList .detail-row").first().waitFor();

    const html = await popup.locator("#vaultItemsList").innerHTML();
    expect(html).toContain("example.com");
    expect(html).toContain("alice@example.com");
    expect(html).not.toContain("TopSecretVaultPassword1!");
    expect(html).not.toContain("PrivateNoteText-42");
    // Whole-document check too: the secret is not rendered anywhere in the popup DOM.
    const fullDom = await popup.content();
    expect(fullDom).not.toContain("PrivateNoteText-42");
  } finally {
    await context.close();
  }
});

test("only list summaries cross the message boundary; the secret appears ONLY in the single GET_ITEM response", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const target = await openLoginPage(context, localLogin());

    await popup.evaluate(() => {
      window.__vaultLog = [];
      const original = browser.runtime.sendMessage.bind(browser.runtime);
      browser.runtime.sendMessage = async (...args) => {
        const response = await original(...args);
        window.__vaultLog.push({ type: args[0] && args[0].type, response: JSON.stringify(response) });
        return response;
      };
    });

    await popup.click("details:has(#vaultNewSite) summary");
    await popup.fill("#vaultNewSite", "localhost");
    await popup.fill("#vaultNewUsername", "boundary-user");
    await popup.fill("#vaultNewSecret", "BoundarySecret-9981!");
    await popup.fill("#vaultNewNotes", "BoundaryNote-7755");
    await popup.click("#vaultAddBtn");
    await popup.fill("#vaultSearchInput", "boundary");
    await popup.waitForTimeout(300);
    await refreshVaultFor(popup, target);
    await target.bringToFront();
    await popup.locator("#vaultMatchesList .vault-fill-btn").first().click();
    await popup.waitForTimeout(600);

    const log = await popup.evaluate(() => window.__vaultLog);
    const types = log.map((e) => e.type);
    for (const expected of ["SAX_VAULT_ADD_ITEM", "SAX_VAULT_LIST", "SAX_VAULT_MATCHES_FOR_ACTIVE_TAB", "SAX_VAULT_FILL"]) {
      expect(types, `expected ${expected} to have been exercised`).toContain(expected);
    }
    for (const entry of log) {
      expect(entry.response, entry.type).not.toContain("BoundarySecret-9981!");
      expect(entry.response, entry.type).not.toContain("BoundaryNote-7755");
    }

    // Positive control: GET_ITEM is the one and only channel that returns a secret, one item at a time.
    const items = await send(popup, { type: "SAX_VAULT_LIST", profileId });
    const one = await send(popup, { type: "SAX_VAULT_GET_ITEM", profileId, itemId: items.items[0].id });
    expect(one.item.secret).toBe("BoundarySecret-9981!");
  } finally {
    await context.close();
  }
});

test("persistent storage holds ciphertext only: no master password, secret, username, notes, label, or site", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    await addViaMessage(popup, profileId, {
      site: "persist-check.example", username: "persist-user-ZZ", secret: "PersistSecret-ZZ-1!",
      notes: "PersistNote-ZZ", accountLabel: "PersistLabel",
    });
    const storage = await readAllStorage(popup);
    const everything = JSON.stringify(storage);
    for (const forbidden of [TEST_MASTER_PASSWORD, "PersistSecret-ZZ-1!", "persist-user-ZZ", "PersistNote-ZZ", "PersistLabel", "persist-check.example"]) {
      expect(everything, forbidden).not.toContain(forbidden);
    }
    expect(Object.keys(storage.sax_vault[profileId]).sort()).toEqual(["ciphertextHex", "ivHex", "saltHex", "version"]);
  } finally {
    await context.close();
  }
});

/* ============ CRUD, search, lock, relock ============ */

test("update, search, and delete work; changes persist across lock and unlock", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const a = await addViaMessage(popup, profileId, { site: "alpha.example", username: "alice", secret: "pw-alpha" });
    await addViaMessage(popup, profileId, { site: "beta.example", username: "bob", secret: "pw-beta" });

    const updated = await send(popup, { type: "SAX_VAULT_UPDATE_ITEM", profileId, itemId: a.id, updates: { username: "alice-renamed", secret: "pw-alpha-2" } });
    expect(updated.ok).toBe(true);
    expect((await send(popup, { type: "SAX_VAULT_UPDATE_ITEM", profileId, itemId: a.id, updates: { secret: "" } })).ok).toBe(false);
    expect((await send(popup, { type: "SAX_VAULT_UPDATE_ITEM", profileId, itemId: "nope", updates: { secret: "x" } })).ok).toBe(false);

    const search = await send(popup, { type: "SAX_VAULT_LIST", profileId, query: "beta" });
    expect(search.items.map((i) => i.site)).toEqual(["beta.example"]);

    await popup.click("#vaultLockBtn");
    await popup.locator("#vaultLockedView").waitFor({ state: "visible" });
    await unlockViaUi(popup);
    await popup.locator("#vaultUnlockedView").waitFor({ state: "visible" });
    const afterRelock = await send(popup, { type: "SAX_VAULT_LIST", profileId });
    expect(afterRelock.items.find((i) => i.id === a.id).username).toBe("alice-renamed");
    expect((await send(popup, { type: "SAX_VAULT_GET_ITEM", profileId, itemId: a.id })).item.secret).toBe("pw-alpha-2");

    await popup.fill("#vaultSearchInput", "");
    await popup.locator('#vaultItemsList .vault-delete-btn[data-id="' + a.id + '"]').click();
    await popup.waitForTimeout(400);
    expect((await send(popup, { type: "SAX_VAULT_LIST", profileId })).items.map((i) => i.site)).toEqual(["beta.example"]);
    expect((await send(popup, { type: "SAX_VAULT_DELETE_ITEM", profileId, itemId: a.id })).ok).toBe(false);
  } finally {
    await context.close();
  }
});

test("manual lock removes the usable decrypted vault: every operation is refused until unlocked again", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const item = await addViaMessage(popup, profileId, { site: "localhost", username: "u", secret: "LockedOutSecret1!" });

    await popup.click("#vaultLockBtn");
    await popup.locator("#vaultLockedView").waitFor({ state: "visible" });
    await expect(popup.locator("#vaultUnlockedView")).toBeHidden();
    expect(await popup.locator("#vaultItemsList").innerHTML()).not.toContain("localhost");

    expect((await send(popup, { type: "SAX_VAULT_STATUS", profileId })).unlocked).toBe(false);
    for (const message of [
      { type: "SAX_VAULT_LIST", profileId },
      { type: "SAX_VAULT_GET_ITEM", profileId, itemId: item.id },
      { type: "SAX_VAULT_FILL", profileId, itemId: item.id },
      { type: "SAX_VAULT_ADD_ITEM", profileId, item: { site: "b.com", secret: "x" } },
      { type: "SAX_VAULT_DELETE_ITEM", profileId, itemId: item.id },
    ]) {
      const r = await send(popup, message);
      expect(r.ok, message.type).toBe(false);
      expect(JSON.stringify(r)).not.toContain("LockedOutSecret1!");
    }

    await unlockViaUi(popup);
    await popup.locator("#vaultUnlockedView").waitFor({ state: "visible" });
    expect((await send(popup, { type: "SAX_VAULT_GET_ITEM", profileId, itemId: item.id })).item.secret).toBe("LockedOutSecret1!");
  } finally {
    await context.close();
  }
});

test("the UI random-password generator produces distinct, 20-character, mixed-class passwords", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup } = await unlockedVault(context, extensionId);
    await popup.click("details:has(#vaultNewSite) summary");
    const seen = new Set();
    for (let i = 0; i < 3; i++) {
      await popup.click("#vaultGenerateBtn");
      await popup.waitForTimeout(150);
      const value = await popup.locator("#vaultNewSecret").inputValue();
      expect(value).toHaveLength(20);
      expect(value).toMatch(/[a-z]/);
      expect(value).toMatch(/[A-Z]/);
      expect(value).toMatch(/[0-9]/);
      expect(value).toMatch(/[^A-Za-z0-9]/);
      seen.add(value);
    }
    expect(seen.size).toBe(3);
  } finally {
    await context.close();
  }
});

/* ============ 7. autofill (user-initiated, exact domain) ============ */

test("autofill is user-initiated only: nothing fills on page load; clicking Fill fills username and password", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    await addViaMessage(popup, profileId, { site: "localhost", username: "user@test.com", secret: "VaultFillSecret1!" });

    const target = await openLoginPage(context, localLogin());
    await target.waitForTimeout(1500); // generous: any auto-fill would have happened by now
    await expect(target.locator("#loginPassword")).toHaveValue("");
    await expect(target.locator("#loginEmail")).toHaveValue("");

    await refreshVaultFor(popup, target);
    await expect(popup.locator("#vaultMatchesBox")).toBeVisible();
    await target.bringToFront();
    await popup.locator("#vaultMatchesList .vault-fill-btn").first().click();
    await popup.waitForTimeout(700);

    await expect(target.locator("#loginPassword")).toHaveValue("VaultFillSecret1!");
    await expect(target.locator("#loginEmail")).toHaveValue("user@test.com");
  } finally {
    await context.close();
  }
});

test("multiple accounts for the same site: only the selected credential is filled", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    await addViaMessage(popup, profileId, { site: "localhost", username: "first@test.com", secret: "FirstSecret-1!", accountLabel: "First" });
    await addViaMessage(popup, profileId, { site: "localhost", username: "second@test.com", secret: "SecondSecret-2!", accountLabel: "Second" });

    const target = await openLoginPage(context, localLogin());
    await refreshVaultFor(popup, target);
    await expect(popup.locator("#vaultMatchesList .vault-fill-btn")).toHaveCount(2);
    await target.bringToFront();
    await popup.locator("#vaultMatchesList .vault-fill-btn").nth(1).click();
    await popup.waitForTimeout(700);

    await expect(target.locator("#loginPassword")).toHaveValue("SecondSecret-2!");
    await expect(target.locator("#loginEmail")).toHaveValue("second@test.com");
  } finally {
    await context.close();
  }
});

/* ============ 8. cross-domain rejection ============ */

test("a credential is never offered or filled on a different hostname (server-side exact match)", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const item = await addViaMessage(popup, profileId, { site: "localhost", username: "u", secret: "OnlyForLocalhost1!" });

    const other = await openLoginPage(context, `http://127.0.0.1:${PORT}/vault-login-target.html`);
    const matches = await send(popup, { type: "SAX_VAULT_MATCHES_FOR_ACTIVE_TAB", profileId });
    expect(matches.items).toEqual([]);

    await other.bringToFront();
    const fill = await send(popup, { type: "SAX_VAULT_FILL", profileId, itemId: item.id });
    expect(fill.ok).toBe(false);
    await expect(other.locator("#loginPassword")).toHaveValue("");
    await expect(other.locator("#loginEmail")).toHaveValue("");
  } finally {
    await context.close();
  }
});

test("exact match means exact: a parent domain or lookalike subdomain does not match", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    await addViaMessage(popup, profileId, { site: "example.test", username: "u", secret: "ExactOnly1!" });
    await mockPage(context, "https://login.example.test/**");
    const page = await openLoginPage(context, "https://login.example.test/login.html");
    const matches = await send(popup, { type: "SAX_VAULT_MATCHES_FOR_ACTIVE_TAB", profileId });
    expect(matches.hostname).toBe("login.example.test");
    expect(matches.items).toEqual([]);
    await page.close();
  } finally {
    await context.close();
  }
});

/* ============ suspicious / insecure destinations ============ */

test("autofill is refused on plain HTTP (non-loopback) but allowed on HTTPS for the same host", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const item = await addViaMessage(popup, profileId, { site: "insecure-login.example", username: "u@test.com", secret: "HttpsOnlySecret1!" });
    await mockPage(context, "http://insecure-login.example/**");
    await mockPage(context, "https://insecure-login.example/**");

    const httpPage = await openLoginPage(context, "http://insecure-login.example/login.html");
    const blocked = await send(popup, { type: "SAX_VAULT_FILL", profileId, itemId: item.id });
    expect(blocked.ok).toBe(false);
    expect(blocked.warning).toBe(true);
    expect(blocked.error).toMatch(/HTTPS/);
    await expect(httpPage.locator("#loginPassword")).toHaveValue("");
    await httpPage.close();

    const httpsPage = await openLoginPage(context, "https://insecure-login.example/login.html");
    const allowed = await send(popup, { type: "SAX_VAULT_FILL", profileId, itemId: item.id });
    expect(allowed.ok, JSON.stringify(allowed)).toBe(true);
    await expect(httpsPage.locator("#loginPassword")).toHaveValue("HttpsOnlySecret1!");
  } finally {
    await context.close();
  }
});

test("autofill is blocked on a lookalike/typosquatted brand domain even if the credential was saved for that exact host", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const item = await addViaMessage(popup, profileId, { site: "paypal-login.example", username: "u@test.com", secret: "PhishedSecret1!" });
    await mockPage(context, "https://paypal-login.example/**");
    const page = await openLoginPage(context, "https://paypal-login.example/login.html");

    const result = await send(popup, { type: "SAX_VAULT_FILL", profileId, itemId: item.id });
    expect(result.ok).toBe(false);
    expect(result.warning).toBe(true);
    await expect(page.locator("#loginPassword")).toHaveValue("");
  } finally {
    await context.close();
  }
});

/* ============ iframe + page isolation ============ */

test("autofill never reaches a login form inside an iframe", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const item = await addViaMessage(popup, profileId, { site: "localhost", username: "u@test.com", secret: "IframeSecret1!" });

    const host = await openLoginPage(context, `http://localhost:${PORT}/vault-iframe-host.html`);
    const inner = host.frameLocator("#inner");
    await expect(inner.locator("#loginPassword")).toBeVisible();

    const result = await send(popup, { type: "SAX_VAULT_FILL", profileId, itemId: item.id });
    expect(result.ok).toBe(false);
    await host.waitForTimeout(500);
    await expect(inner.locator("#loginPassword")).toHaveValue("");
    await expect(inner.locator("#loginEmail")).toHaveValue("");
  } finally {
    await context.close();
  }
});

test("vault messages from a content-script (page-origin) sender are refused, even while unlocked", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const item = await addViaMessage(popup, profileId, { site: "localhost", username: "u", secret: "NotForContentScripts1!" });
    const target = await openLoginPage(context, localLogin());
    const worker = context.serviceWorkers()[0];

    const results = await worker.evaluate(async ({ url, profileId, itemId }) => {
      const tab = (await chrome.tabs.query({})).find((t) => t.url === url);
      const messages = [
        { type: "SAX_VAULT_LIST", profileId },
        { type: "SAX_VAULT_GET_ITEM", profileId, itemId },
        { type: "SAX_VAULT_FILL", profileId, itemId },
      ];
      const out = [];
      for (const m of messages) {
        const r = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: (msg) => chrome.runtime.sendMessage(msg),
          args: [m],
        });
        out.push(r[0].result);
      }
      return out;
    }, { url: localLogin(), profileId, itemId: item.id });

    for (const r of results) {
      expect(r.ok).toBe(false);
      expect(r.error).toBe("Not allowed.");
      expect(JSON.stringify(r)).not.toContain("NotForContentScripts1!");
    }
    await expect(target.locator("#loginPassword")).toHaveValue("");
  } finally {
    await context.close();
  }
});

test("page JavaScript cannot reach the vault: no externally_connectable surface", async () => {
  const manifest = JSON.parse(fs.readFileSync(path.resolve(FIXTURES_DIR, "../../../manifest.json"), "utf8"));
  expect(manifest.externally_connectable).toBeUndefined();
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    await addViaMessage(popup, profileId, { site: "localhost", username: "u", secret: "PageCannotRead1!" });
    const target = await openLoginPage(context, localLogin());
    const reached = await target.evaluate((extId) => new Promise((resolve) => {
      try {
        if (!window.chrome || !chrome.runtime || !chrome.runtime.sendMessage) return resolve(false);
        chrome.runtime.sendMessage(extId, { type: "SAX_VAULT_LIST", profileId: "x" }, (response) => resolve(!chrome.runtime.lastError && !!response));
        setTimeout(() => resolve(false), 1500);
      } catch { resolve(false); }
    }), extensionId);
    expect(reached).toBe(false);
  } finally {
    await context.close();
  }
});

/* ============ 9-10. export / import ============ */

async function exportViaUi(popup) {
  const [download] = await Promise.all([popup.waitForEvent("download"), popup.click("#vaultExportBtn")]);
  const text = fs.readFileSync(await download.path(), "utf8");
  return { text, data: JSON.parse(text) };
}

test("encrypted export contains no plaintext credential data and has the documented shape", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    await addViaMessage(popup, profileId, { site: "export-check.example", username: "export-user-QQ", secret: "ExportSecret-QQ-1!", notes: "ExportNote-QQ" });
    const { text, data } = await exportViaUi(popup);
    for (const forbidden of ["ExportSecret-QQ-1!", "export-user-QQ", "ExportNote-QQ", "export-check.example", TEST_MASTER_PASSWORD]) {
      expect(text, forbidden).not.toContain(forbidden);
    }
    expect(data.format).toBe("secureauthx-vault-export");
    expect(Object.keys(data).sort()).toEqual(["ciphertextHex", "format", "ivHex", "saltHex", "version"]);
  } finally {
    await context.close();
  }
});

test("import rejects wrong password, tampered ciphertext, malformed/wrong-version files, and silent overwrite; the existing vault stays untouched", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    await addViaMessage(popup, profileId, { site: "import-check.example", username: "u", secret: "ImportSecret1!" });
    const { data } = await exportViaUi(popup);
    const before = JSON.stringify((await readAllStorage(popup)).sax_vault[profileId]);
    const imp = (extra) => send(popup, { type: "SAX_VAULT_IMPORT", profileId, masterPassword: TEST_MASTER_PASSWORD, confirmOverwrite: true, ...extra });

    const flip = (hex) => hex.slice(0, -2) + (hex.slice(-2) === "00" ? "01" : "00");
    const rejected = [
      await imp({ exportData: data, masterPassword: "TotallyWrongPassword!" }),
      await imp({ exportData: { ...data, ciphertextHex: flip(data.ciphertextHex) } }),
      await imp({ exportData: { ...data, ivHex: flip(data.ivHex) } }),
      await imp({ exportData: { ...data, version: 999 } }),
      await imp({ exportData: { ...data, format: "something-else" } }),
      await imp({ exportData: { format: "secureauthx-vault-export", version: 1 } }),
      await imp({ exportData: { ...data, ciphertextHex: "not-hex!" } }),
      await imp({ exportData: null }),
      await imp({ exportData: data, masterPassword: "" }),
    ];
    for (const r of rejected) expect(r.ok, JSON.stringify(r)).toBe(false);

    // A valid file + correct password must still not overwrite silently.
    const needsConfirm = await send(popup, { type: "SAX_VAULT_IMPORT", profileId, exportData: data, masterPassword: TEST_MASTER_PASSWORD });
    expect(needsConfirm.ok).toBe(false);
    expect(needsConfirm.needsConfirmation).toBe(true);

    const after = JSON.stringify((await readAllStorage(popup)).sax_vault[profileId]);
    expect(after).toBe(before);
    expect((await send(popup, { type: "SAX_VAULT_LIST", profileId })).items).toHaveLength(1);
  } finally {
    await context.close();
  }
});

test("UI import: wrong password is refused with an alert; the correct password restores a deleted credential", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const item = await addViaMessage(popup, profileId, { site: "restore-check.example", username: "u", secret: "RestoreSecret1!" });
    const { text } = await exportViaUi(popup);

    await send(popup, { type: "SAX_VAULT_DELETE_ITEM", profileId, itemId: item.id });
    expect((await send(popup, { type: "SAX_VAULT_LIST", profileId })).items).toHaveLength(0);

    const alerts = [];
    let password = "WrongPasswordForImport!";
    popup.on("dialog", async (dialog) => {
      if (dialog.type() === "prompt") await dialog.accept(password);
      else if (dialog.type() === "alert") { alerts.push(dialog.message()); await dialog.accept(); }
      else await dialog.accept(); // the explicit "replace existing vault?" confirmation
    });
    const file = { name: "vault.json", mimeType: "application/json", buffer: Buffer.from(text) };

    await popup.setInputFiles("#vaultImportFile", file);
    await expect.poll(() => alerts.length).toBeGreaterThan(0);
    expect(alerts[0]).toMatch(/wrong master password|corrupted/i);
    expect((await send(popup, { type: "SAX_VAULT_LIST", profileId })).items).toHaveLength(0);

    password = TEST_MASTER_PASSWORD;
    await popup.setInputFiles("#vaultImportFile", file);
    await expect(popup.locator("#vaultActionMessage")).toHaveText("Vault imported.");
    const restored = await send(popup, { type: "SAX_VAULT_LIST", profileId });
    expect(restored.items.map((i) => i.site)).toEqual(["restore-check.example"]);
    expect((await send(popup, { type: "SAX_VAULT_GET_ITEM", profileId, itemId: restored.items[0].id })).item.secret).toBe("RestoreSecret1!");
  } finally {
    await context.close();
  }
});

/* ============ MV3 service-worker restart ============ */

test("a real MV3 service-worker stop leaves the vault locked: decrypted state does not survive a restart, ciphertext does", async () => {
  const { context, extensionId } = await launchWithExtension();
  try {
    const { popup, profileId } = await unlockedVault(context, extensionId);
    const item = await addViaMessage(popup, profileId, { site: "restart.example", username: "u", secret: "RestartSecret1!" });
    expect((await send(popup, { type: "SAX_VAULT_STATUS", profileId })).unlocked).toBe(true);

    const cdp = await context.newCDPSession(popup);
    await cdp.send("ServiceWorker.enable");
    await cdp.send("ServiceWorker.stopAllWorkers");
    await popup.waitForTimeout(1500);

    expect((await send(popup, { type: "SAX_VAULT_STATUS", profileId })).unlocked).toBe(false);
    const refused = await send(popup, { type: "SAX_VAULT_GET_ITEM", profileId, itemId: item.id });
    expect(refused.ok).toBe(false);
    expect(JSON.stringify(refused)).not.toContain("RestartSecret1!");

    // The encrypted vault persisted; unlocking again restores it.
    await popup.click('[data-tab="passwords"]');
    await popup.click('[data-tab="vault"]');
    await popup.locator("#vaultLockedView").waitFor({ state: "visible" });
    await unlockViaUi(popup);
    await popup.locator("#vaultUnlockedView").waitFor({ state: "visible" });
    expect((await send(popup, { type: "SAX_VAULT_GET_ITEM", profileId, itemId: item.id })).item.secret).toBe("RestartSecret1!");
  } finally {
    await context.close();
  }
});
