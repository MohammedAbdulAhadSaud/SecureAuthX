import { computeSiteScore, SECURITY_HEADER_NAMES, looksLikeTyposquat } from "../lib/scoring.js";
import { computeFullAnalysis } from "../lib/analysis.js";
import {
  saveSiteMeta, recordAndCheckReuse, cacheScore, getCachedScore,
  getProfilesState, listProfiles, getProfileById, getDefaultProfileId,
  addProfile, renameProfile, deleteProfile, setDefaultProfile, hasAnyProfile,
  recordVisit, getVisitInfo,
  listAccounts, addAccount, setLastSelectedAccount, deleteAccount,
  validateProfileName,
  getVaultRecord, setVaultRecord,
} from "../lib/storage.js";
import { deriveSitePassword, computeMasterVerifier, verifyAgainstVerifier, deriveVaultKey, decryptVaultPayload } from "../lib/crypto.js";
import {
  loadVault, saveVault, addItem, updateItem, deleteItem,
  findItemsForSite, searchItems, toListSummary, generateRandomPassword,
  buildExportPayload, validateImportPayload,
} from "../lib/vault.js";

// Chrome/Edge/Brave/Opera provide the native promise-based `chrome.*` API
// directly usable as `browser` in MV3 service workers; Firefox provides
// `browser` natively. This keeps one codebase working everywhere.
if (typeof browser === "undefined") {
  self.browser = chrome;
}

async function getActiveTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab;
}

/* ===================================================================== *
 * Multi-profile session store — in-memory ONLY.
 *
 * sessions: Map<profileId, { masterPassword: string, timer: number }>
 *
 * KNOWN LIMITATION (documented honestly, see README): MV3 background
 * service workers can be terminated by the browser during idle periods,
 * which wipes this Map early — before the 30-minute inactivity window
 * elapses. This degrades SAFELY (the profile just shows "locked" sooner
 * than expected, never a leak), not insecurely. A keep-alive alarm below
 * reduces how often this happens but cannot fully eliminate it — this is
 * a platform constraint, not a bug in this code.
 * ===================================================================== */

const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes of inactivity
const sessions = new Map();

function clearSession(profileId) {
  const s = sessions.get(profileId);
  if (s?.timer) clearTimeout(s.timer);
  sessions.delete(profileId);
  maybeStopKeepAlive();
}

function scheduleExpiry(profileId) {
  const s = sessions.get(profileId);
  if (!s) return;
  if (s.timer) clearTimeout(s.timer);
  s.timer = setTimeout(() => clearSession(profileId), SESSION_TIMEOUT_MS);
}

function setSession(profileId, masterPassword) {
  sessions.set(profileId, { masterPassword, timer: null });
  scheduleExpiry(profileId);
  ensureKeepAlive();
}

/** Call on every use of a session to reset its 30-minute inactivity clock. */
function touchSession(profileId) {
  if (!sessions.has(profileId)) return;
  scheduleExpiry(profileId);
}

function isUnlocked(profileId) {
  return sessions.has(profileId);
}

/* ------------------------------------------------------------------ *
 * Vault session state (Phase 3B)
 *
 * The decrypted vault payload + its salt are attached as extra fields on
 * the SAME session object setSession() creates -- not a separate map.
 * clearSession()'s existing `sessions.delete(profileId)` therefore wipes
 * the vault together with the master password on manual lock, inactivity
 * timeout, or service-worker restart. As with the master password, this
 * is best-effort removal of the JS reference; JavaScript cannot
 * guarantee memory is zeroed, and this code does not claim it does.
 * ------------------------------------------------------------------ */

function attachVaultToSession(profileId, vaultPayload, vaultSaltHex) {
  const s = sessions.get(profileId);
  if (!s) return false;
  s.vaultPayload = vaultPayload;
  s.vaultSaltHex = vaultSaltHex;
  return true;
}

function getUnlockedVaultSession(profileId) {
  const s = sessions.get(profileId);
  return s && s.vaultPayload ? s : null;
}

/** Vault messages are accepted ONLY from this extension's own pages (popup). A content-script/page-origin sender is refused. */
function isTrustedExtensionPage(sender) {
  try {
    return !!(sender && typeof sender.url === "string" && sender.url.startsWith(browser.runtime.getURL("")));
  } catch {
    return false;
  }
}

/** The ACTIVE TAB's own hostname/protocol -- never anything a page or content script claims. */
async function getActiveTabHost() {
  const tab = await getActiveTab();
  let url = null;
  try { url = tab && tab.url ? new URL(tab.url) : null; } catch { url = null; }
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) return { tab, hostname: "", protocol: "" };
  return { tab, hostname: url.hostname.toLowerCase(), protocol: url.protocol };
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

async function getAllSessionStatuses() {
  const profiles = await listProfiles();
  const status = {};
  for (const p of profiles) status[p.id] = isUnlocked(p.id);
  return status;
}

/* ---- Keep-alive alarm: reduces (does not eliminate) premature SW kill ---- */
const KEEP_ALIVE_ALARM = "sax-keepalive";

function ensureKeepAlive() {
  browser.alarms.get(KEEP_ALIVE_ALARM).then((existing) => {
    if (!existing) browser.alarms.create(KEEP_ALIVE_ALARM, { periodInMinutes: 0.4 });
  });
}
function maybeStopKeepAlive() {
  if (sessions.size === 0) browser.alarms.clear(KEEP_ALIVE_ALARM);
}
browser.alarms.onAlarm.addListener((alarm) => {
  // No-op body: the alarm firing is what keeps the service worker alive;
  // nothing needs to happen here.
  if (alarm.name === KEEP_ALIVE_ALARM) { /* intentional no-op */ }
});

/* ===================================================================== *
 * webRequest-based capture: security response headers + third-party
 * request tally, per tab. (Unchanged from the Dashboard feature.)
 * ===================================================================== */

const tabHeaders = new Map();
const tabRequestStats = new Map();

function resetTabTracking(tabId) {
  tabHeaders.delete(tabId);
  tabRequestStats.set(tabId, { total: 0, thirdPartyDomains: new Set() });
}

function captureMainFrameSecurityHeaders(details) {
  if (details.type !== "main_frame") return;
  // Chrome may omit responseHeaders unless extraHeaders is requested.
  // Never treat a missing list as "all six headers absent."
  if (!Array.isArray(details.responseHeaders)) {
    tabHeaders.set(details.tabId, { captured: false, present: {} });
    return;
  }
  const present = {};
  for (const h of details.responseHeaders) {
    const name = (h.name || "").toLowerCase();
    if (!SECURITY_HEADER_NAMES.includes(name)) continue;
    const value = h.value || "";
    present[name] = present[name] ? `${present[name]}; ${value}` : value;
  }
  tabHeaders.set(details.tabId, { captured: true, present });
}

const headerListenerFilter = { urls: ["<all_urls>"], types: ["main_frame"] };
try {
  browser.webRequest.onHeadersReceived.addListener(
    captureMainFrameSecurityHeaders,
    headerListenerFilter,
    ["responseHeaders", "extraHeaders"]
  );
} catch {
  browser.webRequest.onHeadersReceived.addListener(
    captureMainFrameSecurityHeaders,
    headerListenerFilter,
    ["responseHeaders"]
  );
}

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type === "main_frame") {
      // A new top-level navigation in this tab — reset per-tab tracking
      // instead of accumulating stats across page loads.
      resetTabTracking(details.tabId);
      return;
    }
    const stats = tabRequestStats.get(details.tabId) || { total: 0, thirdPartyDomains: new Set() };
    stats.total += 1;
    try {
      const reqHost = new URL(details.url).hostname;
      const tabUrl = details.initiator || details.documentUrl;
      const pageHost = tabUrl ? new URL(tabUrl).hostname : null;
      if (pageHost && reqHost !== pageHost) stats.thirdPartyDomains.add(reqHost);
    } catch { /* ignore malformed URLs */ }
    tabRequestStats.set(details.tabId, stats);
  },
  { urls: ["<all_urls>"] }
);

async function gatherCookieBreakdown(tab, thirdPartyHosts) {
  let firstPartyCookies = [];
  try { firstPartyCookies = await browser.cookies.getAll({ url: tab.url }); } catch { /* restricted page */ }

  let thirdPartyCount = 0;
  for (const host of (thirdPartyHosts || []).slice(0, 15)) {
    try {
      const c = await browser.cookies.getAll({ domain: host });
      if (c.length > 0) thirdPartyCount++;
    } catch { /* ignore */ }
  }

  const secureCount = firstPartyCookies.filter((c) => c.secure).length;
  const sameSiteCount = firstPartyCookies.filter((c) => c.sameSite && c.sameSite !== "no_restriction").length;

  return {
    total: firstPartyCookies.length,
    secureCount,
    sameSiteCount,
    thirdPartyCount,
    list: firstPartyCookies.map((c) => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite })),
  };
}

function cookiesForScoring(cookieBreakdown) {
  return cookieBreakdown.list.map((c) => ({ secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite }));
}

/**
 * Batch 4 Phase 2B — sweeps every frame of a tab for fingerprint
 * techniques recorded by content.js's own per-frame mirror
 * (window.__saxFrameSignals), using the ALREADY-DECLARED "scripting"
 * permission. No new permission is required: chrome.scripting
 * .executeScript with allFrames:true reaches any frame this extension
 * already has host permission for, which today is every http/https
 * origin -- exactly the same set of origins content_scripts already
 * matches, same-origin or cross-origin, at any nesting depth.
 *
 * Returns a plain array of technique-name strings gathered from every
 * frame this could reach. Never the frame's URL, content, or which frame
 * each one came from -- only the same fixed technique identifiers
 * already used everywhere else in this pipeline.
 *
 * Must never throw: a frame this can't inject into (a restricted scheme,
 * a frame that hasn't loaded content.js yet, a closed tab, etc.) is
 * simply skipped, never treated as a fatal error for the whole analysis.
 */
async function collectCrossFrameFingerprintTechniques(tabId) {
  try {
    const results = await browser.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: () => (typeof window.__saxFrameSignals !== "undefined" ? window.__saxFrameSignals : null),
    });
    const techniques = new Set();
    for (const frameResult of results || []) {
      const data = frameResult && frameResult.result;
      if (data && Array.isArray(data.fingerprintTechniques)) {
        for (const t of data.fingerprintTechniques) {
          if (typeof t === "string") techniques.add(t);
        }
      }
    }
    return Array.from(techniques);
  } catch {
    return [];
  }
}

const BADGE_COLORS = { green: "#22d3a5", yellow: "#ffb648", orange: "#ff8a3d", red: "#ff5c72" };

async function setBadgeForTab(tabId, dashboard) {
  try {
    await browser.action.setBadgeText({ tabId, text: String(dashboard.trustScore) });
    await browser.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[dashboard.color] || "#8a8a8a" });
  } catch { /* action API differences across browsers; non-fatal */ }
}

async function runFullAnalysisForTab(tab, { isAutomaticScan = false } = {}) {
  const response = await browser.tabs.sendMessage(tab.id, { type: "SAX_GET_SIGNALS" });
  const thirdPartyHosts = response.signals.thirdPartyScriptHosts || [];

  const cookieBreakdown = await gatherCookieBreakdown(tab, thirdPartyHosts);
  const headers = tabHeaders.get(tab.id) || { captured: false, present: {} };
  const requestStats = tabRequestStats.get(tab.id) || { total: 0, thirdPartyDomains: new Set() };

  const permissionEvents = (response.signals.permissionEvents || []).map((p) => ({ api: p.api, status: p.status }));

  const signals = { ...response.signals, cookies: cookiesForScoring(cookieBreakdown), headers };

  // Batch 4 Phase 2B: combine the top frame's own fingerprint techniques
  // (from the existing SAX_GET_SIGNALS response above, unchanged) with
  // anything additional found in any OTHER frame (iframes, including
  // cross-origin and nested ones) via the cross-frame sweep. A plain Set
  // union is the entire "aggregation" step -- deduplication across
  // frames falls out of Set semantics for free, and an iframe-sourced
  // technique is not weighted any differently than a top-frame one (see
  // lib/analysis.js -- unchanged, it only ever sees technique names, not
  // which frame reported them). Nothing else here changes: forms,
  // cookies, headers, third-party hosts, mixed content, and
  // permissionEvents all continue to reflect the top frame ONLY, exactly
  // as before this batch.
  const topFrameTechniques = response.signals.fingerprintTechniques || [];
  const crossFrameTechniques = await collectCrossFrameFingerprintTechniques(tab.id);
  const combinedFingerprintTechniques = Array.from(new Set([...topFrameTechniques, ...crossFrameTechniques]));

  const analysis = computeFullAnalysis({
    signals,
    cookieBreakdown,
    fingerprintTechniques: combinedFingerprintTechniques,
    permissionEvents,
  });

  analysis.requestStats = {
    total: requestStats.total,
    thirdPartyDomainCount: requestStats.thirdPartyDomains.size,
    thirdPartyDomains: Array.from(requestStats.thirdPartyDomains).slice(0, 25),
  };
  analysis.storageUsage = response.signals.storageUsage;
  // Persist the evaluated six-header report, not the raw HTTP header map.
  analysis.headers = analysis.headerReport || { captured: headers.captured === true, items: [], clickjacking: null };

  const domain = new URL(tab.url).hostname;
  const origin = new URL(tab.url).origin;
  await cacheScore(origin, analysis);
  await setBadgeForTab(tab.id, analysis.dashboard);

  // Visit reputation + proactive critical alert only fire on the automatic
  // per-page-load scan — not on manual "Re-scan" clicks from the popup,
  // which would otherwise inflate the visit count and re-trigger the
  // banner every time someone reopens the Dashboard tab.
  if (isAutomaticScan) {
    analysis.visitInfo = await recordVisit(domain, analysis.criticalIssue);
    if (analysis.criticalIssue) {
      browser.tabs.sendMessage(tab.id, { type: "SAX_CRITICAL_ALERT", summary: analysis.summary, dashboard: analysis.dashboard }).catch(() => {
        /* content script may not be injected yet on some pages; non-fatal */
      });
    }
  } else {
    analysis.visitInfo = await getVisitInfo(domain);
  }

  return { analysis, origin, passwordFieldCount: response.passwordFieldCount };
}

browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && /^https?:/.test(tab.url || "")) {
    setTimeout(() => {
      runFullAnalysisForTab(tab, { isAutomaticScan: true }).catch(() => { /* page may block content scripts */ });
    }, 400);
  }
});

/* ===================================================================== *
 * Message handlers
 * ===================================================================== */

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // ---------- Fast safety summary for content-script-triggered warnings ----------
  // (before-login banner, payment-page banner). Prefers the cache already
  // populated by the automatic per-page-load scan; only computes fresh if
  // nothing is cached yet (e.g. user interacts unusually fast).
  if (message.type === "SAX_GET_SAFETY_SUMMARY") {
    (async () => {
      try {
        const tab = sender.tab;
        if (!tab || !/^https?:/.test(tab.url || "")) {
          sendResponse({ ok: false, error: "Not an analyzable page." });
          return;
        }
        const origin = new URL(tab.url).origin;
        const cached = await getCachedScore(origin);
        if (cached && cached.summary) {
          sendResponse({ ok: true, summary: cached.summary, dashboard: cached.dashboard, criticalIssue: cached.criticalIssue });
          return;
        }
        const result = await runFullAnalysisForTab(tab, { isAutomaticScan: false });
        sendResponse({ ok: true, summary: result.analysis.summary, dashboard: result.analysis.dashboard, criticalIssue: result.analysis.criticalIssue });
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }

  // ---------- Dashboard: basic score (legacy path, still used) ----------
  if (message.type === "SAX_REQUEST_SCORE") {
    (async () => {
      try {
        const tab = await getActiveTab();
        if (!tab || !tab.id || !/^https?:/.test(tab.url || "")) {
          sendResponse({ ok: false, error: "No scoreable page in the active tab." });
          return;
        }
        const response = await browser.tabs.sendMessage(tab.id, { type: "SAX_GET_SIGNALS" });
        const cookieBreakdown = await gatherCookieBreakdown(tab, response.signals.thirdPartyScriptHosts);
        const headers = tabHeaders.get(tab.id) || { captured: false, present: {} };
        const signals = { ...response.signals, cookies: cookiesForScoring(cookieBreakdown), headers };
        const report = computeSiteScore(signals);
        sendResponse({ ok: true, report, passwordFieldCount: response.passwordFieldCount });
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }

  // ---------- Dashboard: full analysis ----------
  if (message.type === "SAX_RUN_FULL_ANALYSIS") {
    (async () => {
      try {
        const tab = await getActiveTab();
        if (!tab || !tab.id || !/^https?:/.test(tab.url || "")) {
          sendResponse({ ok: false, error: "No analyzable page in the active tab." });
          return;
        }
        const result = await runFullAnalysisForTab(tab);
        sendResponse({ ok: true, ...result });
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }

  // ---------- Fill an already-derived password into the active tab ----------
  if (message.type === "SAX_FORWARD_FILL") {
    (async () => {
      const tab = await getActiveTab();
      const result = await browser.tabs.sendMessage(tab.id, { type: "SAX_FILL_PASSWORD", password: message.password });
      sendResponse(result);
    })();
    return true;
  }

  // ---------- Reuse detection ----------
  if (message.type === "SAX_RECORD_REUSE") {
    (async () => {
      const reusedElsewhere = await recordAndCheckReuse(message.domain, message.reuseHash);
      sendResponse({ reusedElsewhere });
    })();
    return true;
  }

  /* ------------------------------------------------------------------ *
   * Master Profiles: CRUD
   * ------------------------------------------------------------------ */

  if (message.type === "SAX_HAS_ANY_PROFILE") {
    (async () => sendResponse({ hasAny: await hasAnyProfile() }))();
    return true;
  }

  if (message.type === "SAX_LIST_PROFILES") {
    (async () => {
      const state = await getProfilesState();
      const statuses = await getAllSessionStatuses();
      sendResponse({
        profiles: state.profiles.map((p) => ({ id: p.id, name: p.name })), // never expose salt/verifier to the UI layer
        defaultProfileId: state.defaultProfileId,
        sessionStatus: statuses,
      });
    })();
    return true;
  }

  if (message.type === "SAX_ADD_PROFILE") {
    (async () => {
      const { name, masterPassword } = message;
      const validated = validateProfileName(name);
      if (!validated.ok) {
        sendResponse({ ok: false, error: validated.error });
        return;
      }
      if (!masterPassword || masterPassword.length < 8) {
        sendResponse({ ok: false, error: "Use at least 8 characters for the master password." });
        return;
      }
      const { saltHex, verifierHex } = await computeMasterVerifier(masterPassword);
      const profile = await addProfile(validated.name, saltHex, verifierHex);
      sendResponse({ ok: true, profile: { id: profile.id, name: profile.name } });
    })();
    return true;
  }


  if (message.type === "SAX_RENAME_PROFILE") {
    (async () => {
      try {
        const validated = validateProfileName(message.name);
        if (!validated.ok) { sendResponse({ ok: false, error: validated.error }); return; }
        const profile = await renameProfile(message.id, validated.name);
        sendResponse({ ok: true, profile: { id: profile.id, name: profile.name } });
      } catch (err) {
        sendResponse({ ok: false, error: String(err.message || err) });
      }
    })();
    return true;
  }

  /* ------------------------------------------------------------------ *
   * Secure profile deletion — a security-sensitive operation. The
   * master password for the profile being deleted must be re-verified
   * (reusing the same unlock-verification logic, not a second
   * mechanism) before anything is deleted. Deleting the last remaining
   * profile is rejected outright.
   * ------------------------------------------------------------------ */

  if (message.type === "SAX_DELETE_PROFILE") {
    (async () => {
      const { id, masterPassword } = message;
      const profiles = await listProfiles();

      if (profiles.length <= 1) {
        sendResponse({ ok: false, error: "At least one Master Profile must remain." });
        return;
      }

      const profile = await getProfileById(id);
      if (!profile) { sendResponse({ ok: false, error: "Profile not found." }); return; }

      const matches = await verifyAgainstVerifier(masterPassword || "", profile.saltHex, profile.verifierHex);
      if (!matches) {
        sendResponse({ ok: false, error: "Master password doesn't match this profile." });
        return;
      }

      // Correct password confirmed — terminate its session, then delete.
      clearSession(id);
      const state = await deleteProfile(id);
      sendResponse({ ok: true, defaultProfileId: state.defaultProfileId });
    })();
    return true;
  }

  if (message.type === "SAX_SET_DEFAULT_PROFILE") {
    (async () => {
      try {
        await setDefaultProfile(message.id);
        sendResponse({ ok: true });
      } catch (err) {
        sendResponse({ ok: false, error: String(err.message || err) });
      }
    })();
    return true;
  }

  /* ------------------------------------------------------------------ *
   * Account identities — owned by (Master Profile, website). Labels
   * only, never passwords; max 5 per site is enforced in storage.js.
   * ------------------------------------------------------------------ */

  if (message.type === "SAX_LIST_ACCOUNTS") {
    (async () => {
      const { profileId, domain } = message;
      if (!profileId || !domain) { sendResponse({ ok: false, error: "Missing profile or domain." }); return; }
      const result = await listAccounts(profileId, domain);
      sendResponse({ ok: true, ...result });
    })();
    return true;
  }

  if (message.type === "SAX_ADD_ACCOUNT") {
    (async () => {
      const { profileId, domain, name } = message;
      if (!profileId || !domain) { sendResponse({ ok: false, error: "Missing profile or domain." }); return; }
      const result = await addAccount(profileId, domain, name);
      sendResponse(result);
    })();
    return true;
  }

  if (message.type === "SAX_SELECT_ACCOUNT") {
    (async () => {
      const { profileId, domain, name } = message;
      if (!profileId || !domain || !name) { sendResponse({ ok: false, error: "Missing profile, domain, or account." }); return; }
      const result = await setLastSelectedAccount(profileId, domain, name);
      sendResponse(result);
    })();
    return true;
  }

  if (message.type === "SAX_DELETE_ACCOUNT") {
    (async () => {
      const { profileId, domain, name } = message;
      if (!profileId || !domain || !name) { sendResponse({ ok: false, error: "Missing profile, domain, or account." }); return; }
      const result = await deleteAccount(profileId, domain, name);
      sendResponse(result);
    })();
    return true;
  }

  if (message.type === "SAX_DELETE_ACCOUNT") {
    (async () => {
      const { profileId, domain, name } = message;
      if (!profileId || !domain || !name) { sendResponse({ ok: false, error: "Missing profile, domain, or account." }); return; }
      const result = await deleteAccount(profileId, domain, name);
      sendResponse(result);
    })();
    return true;
  }

  /* ------------------------------------------------------------------ *
   * Session unlocking
   * ------------------------------------------------------------------ */

  if (message.type === "SAX_GET_SESSION_STATUS") {
    (async () => sendResponse({ sessionStatus: await getAllSessionStatuses() }))();
    return true;
  }

  if (message.type === "SAX_LOCK_PROFILE") {
    clearSession(message.id);
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "SAX_UNLOCK_PROFILE") {
    (async () => {
      const profile = await getProfileById(message.id);
      if (!profile) { sendResponse({ ok: false, error: "Profile not found." }); return; }
      const matches = await verifyAgainstVerifier(message.masterPassword, profile.saltHex, profile.verifierHex);
      if (!matches) { sendResponse({ ok: false, error: "Master password doesn't match this profile." }); return; }
      setSession(message.id, message.masterPassword);
      sendResponse({ ok: true });
    })();
    return true;
  }

  /* ------------------------------------------------------------------ *
   * Password generation (profile-aware; derivation algorithm unchanged)
   * ------------------------------------------------------------------ */

  if (message.type === "SAX_GENERATE_PASSWORD") {
    (async () => {
      try {
        const { profileId, domain, accountId, masterPassword, rememberSession, derivedLength } = message;
        const profile = await getProfileById(profileId);
        if (!profile) { sendResponse({ ok: false, error: "Profile not found." }); return; }
        if (!domain) { sendResponse({ ok: false, error: "This tab doesn't have a valid web domain." }); return; }
        if (!accountId) { sendResponse({ ok: false, error: "Select an account first." }); return; }

        let effectiveMasterPassword;

        if (isUnlocked(profileId)) {
          effectiveMasterPassword = sessions.get(profileId).masterPassword;
          touchSession(profileId); // using it resets the 30-minute inactivity clock
        } else {
          if (!masterPassword) {
            sendResponse({ ok: false, error: "This profile is locked — enter its master password." });
            return;
          }
          const matches = await verifyAgainstVerifier(masterPassword, profile.saltHex, profile.verifierHex);
          if (!matches) {
            sendResponse({ ok: false, error: "Master password doesn't match this profile." });
            return;
          }
          effectiveMasterPassword = masterPassword;
          if (rememberSession) setSession(profileId, masterPassword);
        }

        const derived = await deriveSitePassword(effectiveMasterPassword, domain, accountId, { length: derivedLength });
        await saveSiteMeta(domain);
        await setLastSelectedAccount(profileId, domain, accountId);
        sendResponse({ ok: true, derived, sessionStatus: await getAllSessionStatuses() });
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }

  /* ==================================================================== *
   * Phase 3B -- local encrypted password vault
   *
   * Data-minimization discipline for this whole section:
   *  - The decrypted vault NEVER crosses a message boundary. Every
   *    list/search/match/unlock/import response goes through
   *    toListSummary(), which strips `secret` and `notes`.
   *  - Exactly ONE handler (SAX_VAULT_GET_ITEM) returns a secret, for
   *    exactly one explicitly-requested item, to a trusted extension page.
   *  - SAX_VAULT_FILL never returns the secret to its caller: it forwards
   *    it straight to the active tab's content script and replies {ok}.
   *  - The vault key (a non-extractable CryptoKey) never leaves
   *    lib/crypto.js call sites in this file and is never messaged.
   *  - Matching/fill always uses the ACTIVE TAB's own hostname, EXACT
   *    match only, re-verified here regardless of what any UI displayed.
   * ==================================================================== */

  if (typeof message.type === "string" && message.type.startsWith("SAX_VAULT_") && !isTrustedExtensionPage(sender)) {
    sendResponse({ ok: false, error: "Not allowed." });
    return true;
  }

  if (message.type === "SAX_VAULT_UNLOCK") {
    (async () => {
      try {
        const profile = await getProfileById(message.profileId);
        if (!profile) { sendResponse({ ok: false, error: "Profile not found." }); return; }
        let effectiveMasterPassword;
        if (isUnlocked(message.profileId)) {
          effectiveMasterPassword = sessions.get(message.profileId).masterPassword;
        } else {
          if (!message.masterPassword) { sendResponse({ ok: false, error: "Enter this profile's master password to unlock the vault." }); return; }
          const matches = await verifyAgainstVerifier(message.masterPassword, profile.saltHex, profile.verifierHex);
          if (!matches) { sendResponse({ ok: false, error: "Master password doesn't match this profile." }); return; }
          effectiveMasterPassword = message.masterPassword;
          setSession(message.profileId, message.masterPassword);
        }
        const { payload, saltHex } = await loadVault(message.profileId, effectiveMasterPassword);
        attachVaultToSession(message.profileId, payload, saltHex);
        touchSession(message.profileId);
        sendResponse({ ok: true, items: payload.items.map(toListSummary) });
      } catch {
        // Deliberately generic: never reveal wrong-password vs corrupted/tampered data.
        sendResponse({ ok: false, error: "Couldn't unlock the vault. Check the master password." });
      }
    })();
    return true;
  }

  if (message.type === "SAX_VAULT_LOCK") {
    clearSession(message.profileId);
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "SAX_VAULT_STATUS") {
    sendResponse({ ok: true, unlocked: !!getUnlockedVaultSession(message.profileId) });
    return true;
  }

  if (message.type === "SAX_VAULT_LIST") {
    const session = getUnlockedVaultSession(message.profileId);
    if (!session) { sendResponse({ ok: false, error: "Vault is locked." }); return true; }
    touchSession(message.profileId);
    const items = message.query ? searchItems(session.vaultPayload, String(message.query)) : session.vaultPayload.items;
    sendResponse({ ok: true, items: items.map(toListSummary) });
    return true;
  }

  if (message.type === "SAX_VAULT_GET_ITEM") {
    const session = getUnlockedVaultSession(message.profileId);
    if (!session) { sendResponse({ ok: false, error: "Vault is locked." }); return true; }
    const item = session.vaultPayload.items.find((i) => i.id === message.itemId);
    if (!item) { sendResponse({ ok: false, error: "Credential not found." }); return true; }
    touchSession(message.profileId);
    sendResponse({ ok: true, item });
    return true;
  }

  if (message.type === "SAX_VAULT_ADD_ITEM") {
    (async () => {
      const session = getUnlockedVaultSession(message.profileId);
      if (!session) { sendResponse({ ok: false, error: "Vault is locked." }); return; }
      const result = addItem(session.vaultPayload, message.item || {});
      if (!result.ok) { sendResponse(result); return; }
      await saveVault(message.profileId, session.masterPassword, session.vaultSaltHex, session.vaultPayload);
      touchSession(message.profileId);
      sendResponse({ ok: true, item: toListSummary(result.item) });
    })();
    return true;
  }

  if (message.type === "SAX_VAULT_UPDATE_ITEM") {
    (async () => {
      const session = getUnlockedVaultSession(message.profileId);
      if (!session) { sendResponse({ ok: false, error: "Vault is locked." }); return; }
      const result = updateItem(session.vaultPayload, message.itemId, message.updates || {});
      if (!result.ok) { sendResponse(result); return; }
      await saveVault(message.profileId, session.masterPassword, session.vaultSaltHex, session.vaultPayload);
      touchSession(message.profileId);
      sendResponse({ ok: true, item: toListSummary(result.item) });
    })();
    return true;
  }

  if (message.type === "SAX_VAULT_DELETE_ITEM") {
    (async () => {
      const session = getUnlockedVaultSession(message.profileId);
      if (!session) { sendResponse({ ok: false, error: "Vault is locked." }); return; }
      const result = deleteItem(session.vaultPayload, message.itemId);
      if (!result.ok) { sendResponse(result); return; }
      await saveVault(message.profileId, session.masterPassword, session.vaultSaltHex, session.vaultPayload);
      touchSession(message.profileId);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message.type === "SAX_VAULT_MATCHES_FOR_ACTIVE_TAB") {
    (async () => {
      const session = getUnlockedVaultSession(message.profileId);
      if (!session) { sendResponse({ ok: false, error: "Vault is locked." }); return; }
      const { hostname } = await getActiveTabHost();
      if (!hostname) { sendResponse({ ok: true, items: [], hostname: "" }); return; }
      touchSession(message.profileId);
      sendResponse({ ok: true, items: findItemsForSite(session.vaultPayload, hostname).map(toListSummary), hostname });
    })();
    return true;
  }

  if (message.type === "SAX_VAULT_FILL") {
    (async () => {
      const session = getUnlockedVaultSession(message.profileId);
      if (!session) { sendResponse({ ok: false, error: "Vault is locked." }); return; }

      const { tab, hostname, protocol } = await getActiveTabHost();
      if (!hostname) { sendResponse({ ok: false, error: "This tab doesn't have a valid web domain." }); return; }

      const item = session.vaultPayload.items.find((i) => i.id === message.itemId);
      if (!item) { sendResponse({ ok: false, error: "Credential not found." }); return; }

      // 1) EXACT hostname match, re-verified here (never trust UI-side filtering).
      if (item.site !== hostname) {
        sendResponse({ ok: false, error: "This credential is saved for a different site than the current page." });
        return;
      }
      // 2) Refuse insecure (plain-HTTP) pages; loopback hosts are the only HTTP exception.
      if (protocol !== "https:" && !(protocol === "http:" && LOOPBACK_HOSTS.has(hostname))) {
        sendResponse({ ok: false, error: "This page isn't using HTTPS. Autofill blocked for safety.", warning: true });
        return;
      }
      // 3) Existing, unmodified lookalike-domain heuristic from scoring.js (read-only use).
      if (looksLikeTyposquat(hostname)) {
        sendResponse({ ok: false, error: "This domain resembles a known brand and may not be legitimate. Autofill blocked for safety.", warning: true });
        return;
      }

      touchSession(message.profileId);
      try {
        if (item.username) {
          await browser.tabs.sendMessage(tab.id, { type: "SAX_FILL_USERNAME", username: item.username }).catch(() => {});
        }
        const fillResult = await browser.tabs.sendMessage(tab.id, { type: "SAX_FILL_PASSWORD", password: item.secret });
        // Only {ok,error} is returned to the caller -- never the credential.
        sendResponse({ ok: !!(fillResult && fillResult.ok), error: fillResult && fillResult.error });
      } catch {
        sendResponse({ ok: false, error: "Couldn't fill this page. Re-open the page and try again." });
      }
    })();
    return true;
  }

  if (message.type === "SAX_VAULT_GENERATE_PASSWORD") {
    try {
      const length = Math.min(Math.max(parseInt(message.length, 10) || 20, 8), 128);
      sendResponse({ ok: true, password: generateRandomPassword(length, message.options || {}) });
    } catch (err) {
      sendResponse({ ok: false, error: String(err) });
    }
    return true;
  }

  if (message.type === "SAX_VAULT_EXPORT") {
    (async () => {
      const record = await getVaultRecord(message.profileId);
      if (!record) { sendResponse({ ok: false, error: "No vault exists yet for this profile." }); return; }
      // Nothing is decrypted to export: the stored record already IS the encrypted export.
      sendResponse({ ok: true, exportData: buildExportPayload(record) });
    })();
    return true;
  }

  if (message.type === "SAX_VAULT_IMPORT") {
    (async () => {
      const validation = validateImportPayload(message.exportData);
      if (!validation.ok) { sendResponse(validation); return; }
      const existing = await getVaultRecord(message.profileId);
      if (existing && !message.confirmOverwrite) {
        sendResponse({ ok: false, error: "A vault already exists for this profile. Confirm overwrite to proceed.", needsConfirmation: true });
        return;
      }
      if (!message.masterPassword) { sendResponse({ ok: false, error: "Enter the master password that encrypted this export file." }); return; }
      try {
        // The password must actually decrypt THIS file's ciphertext before anything is accepted;
        // AES-GCM's auth tag also rejects tampered files here.
        const importedKey = await deriveVaultKey(message.masterPassword, message.exportData.saltHex);
        const importedPayload = await decryptVaultPayload(importedKey, message.exportData.ivHex, message.exportData.ciphertextHex);
        if (!importedPayload || importedPayload.version !== 1 || !Array.isArray(importedPayload.items)) {
          sendResponse({ ok: false, error: "Import file could not be verified." });
          return;
        }
        await setVaultRecord(message.profileId, {
          version: message.exportData.version, saltHex: message.exportData.saltHex,
          ivHex: message.exportData.ivHex, ciphertextHex: message.exportData.ciphertextHex,
        });
        // An already-unlocked session must not keep serving the OLD decrypted vault.
        if (isUnlocked(message.profileId)) attachVaultToSession(message.profileId, importedPayload, message.exportData.saltHex);
        sendResponse({ ok: true, items: importedPayload.items.map(toListSummary) });
      } catch {
        sendResponse({ ok: false, error: "Couldn't import: wrong master password or corrupted file." });
      }
    })();
    return true;
  }
});
