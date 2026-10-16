import { reuseComparisonHash } from "../lib/crypto.js";
import { analyzeStrength } from "../lib/strength.js";
import { listSites, getSettings, saveSettings, MAX_ACCOUNTS_PER_SITE } from "../lib/storage.js";

const $ = (sel) => document.querySelector(sel);

/* Shared inline-SVG icon set — no emoji anywhere in this UI. Every icon
 * uses currentColor so it inherits whatever text/status color it's placed in. */
const ICONS = {
  lock: '<svg class="icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  unlock: '<svg class="icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.7"/></svg>',
  check: '<svg class="icon" viewBox="0 0 24 24" stroke-width="2.5"><path d="M4 12l5 5L20 6"/></svg>',
  warning: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3l10 18H2L12 3z"/><path d="M12 9v5"/><path d="M12 17h.01"/></svg>',
  cross: '<svg class="icon" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  trash: '<svg class="icon" viewBox="0 0 24 24"><path d="M4 7h16M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2m-8 0v12a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2V7"/></svg>',
  dot: (cls) => `<span class="status-dot status-${cls}"></span>`,
};

/* Dashboard trust-tier icon, keyed by dashboard.color (green/yellow/orange/red) */
const TIER_ICON = {
  green: '<svg class="icon icon-lg" viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
  yellow: '<svg class="icon icon-lg" viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M12 8v5"/><path d="M12 16h.01"/></svg>',
  orange: '<svg class="icon icon-lg" viewBox="0 0 24 24"><path d="M12 3l10 18H2L12 3z"/><path d="M12 9v5"/><path d="M12 17h.01"/></svg>',
  red: '<svg class="icon icon-lg" viewBox="0 0 24 24"><path d="M12 3l10 18H2L12 3z"/><path d="M12 9v5"/><path d="M12 17h.01"/></svg>',
};

/* ===================================================================== *
 * Onboarding gate — creates the FIRST Master Profile
 * ===================================================================== */

async function checkOnboarding() {
  const { hasAny } = await browser.runtime.sendMessage({ type: "SAX_HAS_ANY_PROFILE" });
  $("#onboarding").classList.toggle("hidden", hasAny);
  $("#appRoot").classList.toggle("hidden", !hasAny);
  return hasAny;
}

$("#obSaveBtn").addEventListener("click", async () => {
  const name = $("#obProfileName").value.trim() || "Personal";
  const p1 = $("#obMaster1").value;
  const p2 = $("#obMaster2").value;
  const errBox = $("#obError");
  errBox.classList.add("hidden");

  if (!p1 || p1.length < 8) {
    errBox.textContent = "Use at least 8 characters — ideally much more, since this password protects every site under this profile.";
    errBox.classList.remove("hidden");
    return;
  }
  if (p1 !== p2) {
    errBox.textContent = "Passwords don't match.";
    errBox.classList.remove("hidden");
    return;
  }

  const result = await browser.runtime.sendMessage({ type: "SAX_ADD_PROFILE", name, masterPassword: p1 });
  $("#obMaster1").value = "";
  $("#obMaster2").value = "";

  if (!result.ok) {
    errBox.textContent = result.error;
    errBox.classList.remove("hidden");
    return;
  }

  await checkOnboarding();
  await initAfterOnboarding();
});

/* ===================================================================== *
 * Tabs
 * ===================================================================== */

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`#tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "manage") { renderProfilesSettings(); renderSites(); }
    if (btn.dataset.tab === "vault") { initVaultTab(); }
  });
});

/* ===================================================================== *
 * Theme
 * ===================================================================== */

async function initTheme() {
  const settings = await getSettings();
  document.documentElement.setAttribute("data-theme", settings.theme === "light" ? "light" : "dark");
}
$("#themeToggle").addEventListener("click", async () => {
  const current = document.documentElement.getAttribute("data-theme");
  const next = current === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  await saveSettings({ theme: next });
});

/* ===================================================================== *
 * Active tab domain
 * ===================================================================== */

let activeDomain = "";
async function initActiveDomain() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  try { activeDomain = new URL(tab.url).hostname; } catch { activeDomain = ""; }
  $("#siteOrigin").value = activeDomain || "(not a web page)";
}

/* ===================================================================== *
 * Generate tab — profile-aware
 * ===================================================================== */

let profilesCache = [];
let sessionStatusCache = {};
let selectedProfileId = null;

async function refreshProfilesAndStatus() {
  const result = await browser.runtime.sendMessage({ type: "SAX_LIST_PROFILES" });
  profilesCache = result.profiles;
  sessionStatusCache = result.sessionStatus;
  if (!selectedProfileId || !profilesCache.some((p) => p.id === selectedProfileId)) {
    selectedProfileId = result.defaultProfileId || profilesCache[0]?.id || null;
  }
  return result;
}

function renderProfileList() {
  const container = $("#profileList");
  container.innerHTML = profilesCache.map((p) => `
    <label class="account-option-label profile-option ${p.id === selectedProfileId ? "is-selected" : ""}">
      <input type="radio" name="profileRadio" value="${p.id}" ${p.id === selectedProfileId ? "checked" : ""} />
      <span>${p.name}</span>
    </label>
  `).join("");

  container.querySelectorAll('input[name="profileRadio"]').forEach((radio) => {
    radio.addEventListener("change", async (e) => {
      selectedProfileId = e.target.value;
      container.querySelectorAll(".profile-option").forEach((el) => el.classList.remove("is-selected"));
      radio.closest(".profile-option").classList.add("is-selected");
      renderGenerateStatus();
      await reloadAccountsUI();
    });
  });
}

function renderGenerateStatus() {
  const unlocked = !!sessionStatusCache[selectedProfileId];
  const statusIcon = $("#profileStatusIcon");
  statusIcon.innerHTML = unlocked ? ICONS.unlock : ICONS.lock;
  statusIcon.classList.toggle("status-unlocked", unlocked);
  statusIcon.classList.toggle("status-locked", !unlocked);
  $("#profileStatusText").textContent = unlocked ? "Session Unlocked" : "Locked";
  $("#lockedFields").classList.toggle("hidden", unlocked);
  $("#lockSessionBtn").classList.toggle("hidden", !unlocked);
}

$("#lockSessionBtn").addEventListener("click", async () => {
  await browser.runtime.sendMessage({ type: "SAX_LOCK_PROFILE", id: selectedProfileId });
  sessionStatusCache[selectedProfileId] = false;
  renderGenerateStatus();
});

function showGenerateError(msg) {
  hideGenerateSuccess();
  const box = $("#generateError");
  box.innerHTML = `${ICONS.warning} ${msg}`;
  box.classList.remove("hidden");
}

function showAccountError(msg) {
  const box = $("#accountError");
  box.textContent = msg;
  box.classList.remove("hidden");
}

function hideAccountError() {
  $("#accountError").classList.add("hidden");
}

function hideGenerateError() {
  $("#generateError").classList.add("hidden");
}
function showGenerateSuccess(msg) {
  hideGenerateError();
  const box = $("#generateSuccess");
  box.innerHTML = `${ICONS.check} ${msg}`;
  box.classList.remove("hidden");
}
function hideGenerateSuccess() {
  $("#generateSuccess").classList.add("hidden");
}

/* ---- Account identities (per Master Profile + current website) ---- */

let accountsCache = [];
let selectedAccount = null;

async function refreshAccounts() {
  if (!selectedProfileId || !activeDomain) {
    accountsCache = [];
    selectedAccount = null;
    return;
  }
  const result = await browser.runtime.sendMessage({
    type: "SAX_LIST_ACCOUNTS", profileId: selectedProfileId, domain: activeDomain,
  });
  accountsCache = result.ok ? result.accounts : ["Default"];
  selectedAccount = (result.ok && result.lastSelected) || accountsCache[0];
}

function renderAccountList() {
  const container = $("#accountList");
  container.innerHTML = accountsCache.map((name) => `
    <div class="account-option ${name === selectedAccount ? "is-selected" : ""}">
      <label class="account-option-label">
        <input type="radio" name="accountRadio" value="${name}" ${name === selectedAccount ? "checked" : ""} />
        <span>${name}</span>
      </label>
      ${accountsCache.length > 1 ? `<button type="button" class="account-delete-btn" title="Delete account" data-name="${name}">${ICONS.trash}</button>` : ""}
    </div>
  `).join("");

  container.querySelectorAll('input[name="accountRadio"]').forEach((radio) => {
    radio.addEventListener("change", async (e) => {
      selectedAccount = e.target.value;
      container.querySelectorAll(".account-option").forEach((el) => el.classList.remove("is-selected"));
      radio.closest(".account-option").classList.add("is-selected");
      await browser.runtime.sendMessage({
        type: "SAX_SELECT_ACCOUNT", profileId: selectedProfileId, domain: activeDomain, name: selectedAccount,
      });
    });
  });

  container.querySelectorAll(".account-delete-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const result = await browser.runtime.sendMessage({
        type: "SAX_DELETE_ACCOUNT", profileId: selectedProfileId, domain: activeDomain, name: btn.dataset.name,
      });
      if (!result.ok) { showGenerateError(result.error); return; }
      accountsCache = result.accounts;
      selectedAccount = result.lastSelected;
      renderAccountList();
    });
  });

  renderAddAccountAvailability();
}

/** Proactively disable/hide "Add Account" once the cap is reached, instead of only erroring after a click. */
function renderAddAccountAvailability() {
  const atCap = accountsCache.length >= MAX_ACCOUNTS_PER_SITE;

  const addBtn = $("#showAddAccountBtn");
  const note = $("#maxAccountsNote");
  const input = $("#newAccountInput");

  note.classList.toggle("hidden", !atCap);

  addBtn.disabled = atCap;
  addBtn.classList.toggle("disabled", atCap);

  if (atCap) {
    input.classList.add("hidden");
    addBtn.classList.remove("hidden");
  } else {
    // Default state: show button, hide input
    if (!document.activeElement || document.activeElement !== input) {
      input.classList.add("hidden");
      addBtn.classList.remove("hidden");
    }
  }
}
async function reloadAccountsUI() {
  await refreshAccounts();
  renderAccountList();
}

$("#showAddAccountBtn").addEventListener("click", () => {

  // Don't allow adding when the maximum is reached
  if (accountsCache.length >= MAX_ACCOUNTS_PER_SITE) {
    return;
  }

  const input = $("#newAccountInput");

  $("#showAddAccountBtn").classList.add("hidden");
  input.classList.remove("hidden");
  input.value = "";
  input.focus();
});

async function commitNewAccount() {
  hideAccountError();
  const input = $("#newAccountInput");
  const name = input.value.trim();

  input.classList.add("hidden");

  if (!name) {
    renderAddAccountAvailability();
    return;
  }

  const result = await browser.runtime.sendMessage({
    type: "SAX_ADD_ACCOUNT",
    profileId: selectedProfileId,
    domain: activeDomain,
    name,
  });

if (!result.ok) {
  showAccountError(result.error);
  renderAddAccountAvailability();
  return;
}

hideAccountError();

  accountsCache = result.accounts;
  selectedAccount = result.lastSelected;

  input.value = "";

  renderAccountList();
  renderAddAccountAvailability();
}
$("#newAccountInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    commitNewAccount();
  }
});

$("#newAccountInput").addEventListener("blur", () => {
  const input = $("#newAccountInput");

  if (!input.classList.contains("hidden") && !input.value.trim()) {
    input.classList.add("hidden");
    renderAddAccountAvailability();
  }
});
/* ---- Generate & Autofill / Copy — password never touches the DOM ---- */

async function generateDerivedPassword() {
  hideGenerateError();
  hideGenerateSuccess();
  $("#reuseWarning").classList.add("hidden");

  if (!activeDomain) { showGenerateError("This tab doesn't have a valid web domain."); return null; }
  if (!selectedProfileId) { showGenerateError("No Master Profile selected."); return null; }
  if (!selectedAccount) { showGenerateError("Select an account first."); return null; }

  const unlocked = !!sessionStatusCache[selectedProfileId];
  const masterPassword = $("#masterPassword").value;
  const rememberSession = $("#rememberSessionCheckbox").checked;

  if (!unlocked && !masterPassword) { showGenerateError("Enter this profile's master password."); return null; }

  const settings = await getSettings();
  const result = await browser.runtime.sendMessage({
    type: "SAX_GENERATE_PASSWORD",
    profileId: selectedProfileId,
    domain: activeDomain,
    accountId: selectedAccount,
    masterPassword: unlocked ? undefined : masterPassword,
    rememberSession,
    derivedLength: settings.derivedLength,
  });

  $("#masterPassword").value = "";

  if (!result.ok) { showGenerateError(result.error); return null; }

  sessionStatusCache = result.sessionStatus;
  renderGenerateStatus();

  const reuseHash = await reuseComparisonHash(result.derived);
  const reuseResult = await browser.runtime.sendMessage({
    type: "SAX_RECORD_REUSE", domain: activeDomain, reuseHash,
  }).catch(() => null);

  if (reuseResult?.reusedElsewhere?.length > 0) {
    const warningBox = $("#reuseWarning");
    warningBox.innerHTML = `${ICONS.warning} This exact derived password also appears on: ${reuseResult.reusedElsewhere.join(", ")}`;
    warningBox.classList.remove("hidden");
  }

  return result.derived;
}

$("#deriveBtn").addEventListener("click", async () => {
  const derived = await generateDerivedPassword();
  if (!derived) return;

  const fillResult = await browser.runtime.sendMessage({ type: "SAX_FORWARD_FILL", password: derived });
  if (!fillResult?.ok) {
    showGenerateError(fillResult?.error || "Couldn't fill the password field on this page.");
    return;
  }
  showGenerateSuccess("Password autofilled successfully.");
});

$("#copyBtn").addEventListener("click", async () => {
  const derived = await generateDerivedPassword();
  if (!derived) return;

  await navigator.clipboard.writeText(derived);
  showGenerateSuccess("Password copied to clipboard.");
});

/* ===================================================================== *
 * Strength tab
 * ===================================================================== */

$("#strengthInput").addEventListener("input", (e) => {
  const report = analyzeStrength(e.target.value);
  const fill = $("#strengthMeterFill");
  fill.style.width = `${report.score}%`;
  fill.style.background =
    report.score >= 60 ? "var(--accent-2)" : report.score >= 30 ? "var(--warning)" : "var(--danger)";
  $("#strengthLabel").textContent = `${report.label} — ${report.entropyBits} bits estimated entropy`;

  const details = $("#strengthDetails");
  details.innerHTML = "";
  report.issues.forEach((i) => {
    const li = document.createElement("div");
    li.className = "issue";
    li.innerHTML = `${ICONS.cross} ${i}`;
    details.appendChild(li);
  });
  report.suggestions.forEach((s) => {
    const li = document.createElement("div");
    li.className = "suggestion";
    li.innerHTML = `${ICONS.check} ${s}`;
    details.appendChild(li);
  });
});

/* ===================================================================== *
 * Dashboard tab
 * ===================================================================== */

function statusLabel(status) {
  return { active: "Active", requested: "Requested", blocked: "Blocked", "not-requested": "Not Requested", unknown: "Unknown" }[status] || status;
}
function statusIcon(status) {
  const cls = ["active", "requested", "blocked", "not-requested"].includes(status) ? status : "unknown";
  return ICONS.dot(cls);
}

function headerStatusClass(status) {
  if (status === "ok") return "header-present";
  if (status === "invalid") return "header-invalid";
  if (status === "unknown") return "header-unknown";
  return "header-missing";
}

function headerStatusLabel(status) {
  return { ok: "present", missing: "missing", invalid: "invalid", unknown: "unable to determine" }[status] || status;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderDashboard(analysis) {
  const { dashboard, trackers, headers, cookieBreakdown, permissionEvents, fingerprintTechniques, fingerprintReport, requestStats, storageUsage, summary, visitInfo, findings, headerReport, mixedContent, clickjacking } = analysis;

  $("#dashSecurity").textContent = dashboard.securityScore;
  $("#dashPrivacy").textContent = dashboard.privacyScore;
  $("#dashPhishing").textContent = dashboard.phishingRiskScore;
  $("#dashTrust").textContent = dashboard.trustScore;

  const badge = $("#dashRiskBadge");
  badge.textContent = `${dashboard.level.toUpperCase()} — Overall Trust ${dashboard.trustScore}/100`;
  badge.className = `risk-badge ${dashboard.color}`;

  $("#dashSummaryHeadline").innerHTML = `<span class="tier-icon tier-${dashboard.color}">${TIER_ICON[dashboard.color] || TIER_ICON.yellow}</span> ${summary.headline}`;
  $("#dashSummaryBullets").innerHTML = summary.bullets
    .map((b) => `<li class="${b.ok ? "bullet-ok" : "bullet-bad"}">${b.ok ? ICONS.check : ICONS.warning} ${b.text}</li>`)
    .join("");
  $("#dashSummaryAdvice").textContent = summary.advice;

  const visitBox = $("#dashVisitInfo");
  if (visitInfo && visitInfo.visitCount > 1) {
    visitBox.textContent = `You've visited this domain ${visitInfo.visitCount} times.${visitInfo.everFlagged ? " A past visit flagged an issue — stay alert." : " No issues detected on past visits."}`;
  } else {
    visitBox.textContent = "First time SecureAuthX has seen this domain — be a little more cautious than usual.";
  }

  $("#trackerCount").textContent = trackers.length;
  $("#trackerList").innerHTML = trackers.length === 0
    ? "No known trackers detected."
    : trackers.map((t) => `<div class="detail-row"><span>${t.name}</span><span>${t.category}</span></div>`).join("");

  const scoredFindings = (findings || []).filter((f) => f.penalty > 0 || f.id === "clickjacking" || f.id === "headers-unknown");
  $("#findingsCount").textContent = scoredFindings.length;
  $("#findingsList").innerHTML = scoredFindings.length === 0
    ? "No security findings with a score impact on this page."
    : scoredFindings.map((f) => `
        <div class="finding-block">
          <div class="finding-title">${escapeHtml(f.what)}</div>
          <div class="finding-meta">${escapeHtml(f.severity)} · confidence ${escapeHtml(f.confidence)}${f.penalty ? ` · −${escapeHtml(f.penalty)} Security` : ""}</div>
          <div class="finding-why">${escapeHtml(f.why)}</div>
          <div class="finding-evidence">Evidence: ${escapeHtml(f.evidence)}</div>
        </div>
      `).join("");

  const report = headerReport || headers || {};
  const items = report.items || [];
  if (!report.captured && items.length === 0) {
    $("#headerCount").textContent = "unable to determine";
    $("#headerList").innerHTML = `<div class="detail-row"><span>Response headers were not captured</span><span class="header-unknown">unable to determine</span></div>`;
  } else {
    const okCount = items.filter((i) => i.status === "ok").length;
    $("#headerCount").textContent = `${okCount}/6 ok`;
    const cj = clickjacking || report.clickjacking;
    const headerRows = items.map((item) => {
      const cls = headerStatusClass(item.status);
      const icon = item.status === "ok" ? ICONS.check : item.status === "unknown" ? ICONS.warning : ICONS.cross;
      return `<div class="detail-row"><span>${escapeHtml(item.label || item.name)}</span><span class="${cls}" title="${escapeHtml(item.detail || "")}">${icon} ${headerStatusLabel(item.status)}</span></div>`;
    });
    if (cj) {
      headerRows.unshift(`<div class="detail-row"><span>Clickjacking</span><span class="${cj.verdict === "protected" ? "header-present" : cj.verdict === "unable-to-determine" ? "header-unknown" : "header-missing"}">${escapeHtml(cj.label || cj.verdict)}</span></div>`);
    }
    $("#headerList").innerHTML = headerRows.join("");
  }

  $("#cookieCount").textContent = cookieBreakdown.total;
  $("#cookieList").innerHTML = `
    <div class="detail-row"><span>Total cookies</span><span>${cookieBreakdown.total}</span></div>
    <div class="detail-row"><span>Secure flag</span><span>${cookieBreakdown.secureCount}/${cookieBreakdown.total}</span></div>
    <div class="detail-row"><span>SameSite set</span><span>${cookieBreakdown.sameSiteCount}/${cookieBreakdown.total}</span></div>
    <div class="detail-row"><span>Third-party services with cookies</span><span>${cookieBreakdown.thirdPartyCount}</span></div>
    <div class="detail-row"><span>localStorage keys</span><span>${storageUsage?.localStorageKeys ?? "—"}</span></div>
    <div class="detail-row"><span>sessionStorage keys</span><span>${storageUsage?.sessionStorageKeys ?? "—"}</span></div>
  `;

  $("#permissionList").innerHTML = permissionEvents.map((p) => `
    <div class="detail-row"><span>${statusIcon(p.status)} ${p.api}</span><span class="status-${p.status}">${statusLabel(p.status)}</span></div>
  `).join("");

  // Batch 3: "Risk level" is no longer recomputed here from raw technique
  // count with its own (previously inconsistent) thresholds — it now
  // reflects the SAME tiered evidence classification analysis.js already
  // used to compute the Privacy-score penalty, via fingerprintReport.tier.
  $("#fingerprintCount").textContent = fingerprintTechniques.length;
  const FINGERPRINT_TIER_TO_RISK_LABEL = { none: "Low", informational: "Low", weak: "Low", moderate: "Medium", strong: "High" };
  const fpRisk = FINGERPRINT_TIER_TO_RISK_LABEL[fingerprintReport?.tier] || "Low";
  $("#fingerprintList").innerHTML = `
    <div class="detail-row"><span>Risk level</span><span>${fpRisk}</span></div>
    ${fingerprintTechniques.length === 0
      ? '<div class="detail-row"><span>No fingerprinting techniques detected</span><span></span></div>'
      : fingerprintTechniques.map((t) => `<div class="detail-row"><span>${t}</span><span>detected</span></div>`).join("")}
  `;

  const mixed = mixedContent || {};
  $("#networkList").innerHTML = `
    <div class="detail-row"><span>Total sub-resource requests</span><span>${requestStats?.total ?? "—"}</span></div>
    <div class="detail-row"><span>External domains contacted</span><span>${requestStats?.thirdPartyDomainCount ?? "—"}</span></div>
    <div class="detail-row"><span>Active mixed content (script/iframe/CSS)</span><span>${mixed.activeCount ?? 0}</span></div>
    <div class="detail-row"><span>Passive mixed content (image/audio/video)</span><span>${mixed.passiveCount ?? 0}</span></div>
  `;

  $("#dashboardLoading").classList.add("hidden");
  $("#dashboardContent").classList.remove("hidden");
}

async function runDashboardAnalysis() {
  $("#dashboardLoading").classList.remove("hidden");
  $("#dashboardLoading").textContent = "Running automatic analysis…";
  $("#dashboardContent").classList.add("hidden");

  const result = await browser.runtime.sendMessage({ type: "SAX_RUN_FULL_ANALYSIS" });
  if (!result.ok) {
    $("#dashboardLoading").textContent = result.error || "Couldn't analyze this page.";
    return;
  }
  renderDashboard(result.analysis);
}

$("#rescanBtn").addEventListener("click", runDashboardAnalysis);

let dashboardLoadedOnce = false;
document.querySelector('[data-tab="analysis"]').addEventListener("click", () => {
  if (!dashboardLoadedOnce) { dashboardLoadedOnce = true; runDashboardAnalysis(); }
});

/* ===================================================================== *
 * Saved sites tab
 * ===================================================================== */

async function renderSites() {
  const sites = await listSites();
  const container = $("#sitesList");
  container.innerHTML = "";
  $("#sitesCountBadge").textContent = sites.length;
  if (sites.length === 0) {
    container.innerHTML = `<p class="footnote">No sites saved yet. Generate a password for a site to save it here.</p>`;
    return;
  }
  sites.forEach((site) => {
    const row = document.createElement("div");
    row.className = "site-row";
    row.innerHTML = `
      <div>
        <div>${site.domain}</div>
        <div class="site-meta">Last used ${new Date(site.lastUsed).toLocaleString()}</div>
      </div>
    `;
    container.appendChild(row);
  });
}

/* ===================================================================== *
 * Settings tab — Master Profiles management
 * ===================================================================== */

async function renderProfilesSettings() {
  const result = await refreshProfilesAndStatus();
  const container = $("#profilesList");
  container.innerHTML = "";

  result.profiles.forEach((p) => {
    const isDefault = p.id === result.defaultProfileId;
    const unlocked = !!result.sessionStatus[p.id];

    const row = document.createElement("div");
    row.className = "profile-row";
    row.innerHTML = `
      <div class="profile-name-wrap">
        <span class="profile-session-dot ${unlocked ? "unlocked" : "locked"}" title="${unlocked ? "Unlocked this session" : "Locked"}"></span>
        <button class="default-star ${isDefault ? "is-default" : ""}" title="${isDefault ? "Default profile" : "Set as default"}">
          <svg class="icon star-outline" viewBox="0 0 24 24" stroke-width="1.6"><path d="M12 3l2.6 5.9L21 9.6l-4.8 4.2L17.6 21 12 17.6 6.4 21l1.4-7.2L3 9.6l6.4-.7L12 3z"/></svg>
          <svg class="icon star-filled" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M12 3l2.6 5.9L21 9.6l-4.8 4.2L17.6 21 12 17.6 6.4 21l1.4-7.2L3 9.6l6.4-.7L12 3z"/></svg>
        </button>
        <span class="profile-name-display">${p.name}</span>
      </div>
      <div class="profile-actions">
        <button class="mini-btn rename-btn">Rename</button>
        <button class="mini-btn danger delete-btn">Delete</button>
      </div>
    `;

    row.querySelector(".default-star").addEventListener("click", async () => {
      await browser.runtime.sendMessage({ type: "SAX_SET_DEFAULT_PROFILE", id: p.id });
      renderProfilesSettings();
    });

    row.querySelector(".rename-btn").addEventListener("click", () => {
      const nameSpan = row.querySelector(".profile-name-display");
      const input = document.createElement("input");
      input.className = "rename-input";
      input.value = p.name;
      nameSpan.replaceWith(input);
      input.focus();
      input.select();

      async function commit() {
        const newName = input.value.trim();
        if (newName && newName !== p.name) {
          await browser.runtime.sendMessage({ type: "SAX_RENAME_PROFILE", id: p.id, name: newName });
        }
        renderProfilesSettings();
      }
      input.addEventListener("blur", commit);
      input.addEventListener("keydown", (e) => { if (e.key === "Enter") input.blur(); });
    });

    row.querySelector(".delete-btn").addEventListener("click", () => {
      if (result.profiles.length <= 1) {
        showGenerateError("At least one Master Profile must remain.");
        return;
      }
      openDeleteProfileModal(p);
    });

    container.appendChild(row);
  });
}

/* ---- Secure Profile Deletion — always re-verifies that profile's master password ---- */

let profilePendingDeletion = null;

function openDeleteProfileModal(profile) {
  profilePendingDeletion = profile;
  $("#deleteProfileName").textContent = profile.name;
  $("#deleteProfilePassword").value = "";
  $("#deleteProfileError").classList.add("hidden");
  $("#deleteProfileModal").classList.remove("hidden");
  $("#deleteProfilePassword").focus();
}

function closeDeleteProfileModal() {
  profilePendingDeletion = null;
  $("#deleteProfileModal").classList.add("hidden");
}

$("#deleteProfileCancelBtn").addEventListener("click", closeDeleteProfileModal);

$("#deleteProfileConfirmBtn").addEventListener("click", async () => {
  if (!profilePendingDeletion) return;
  const masterPassword = $("#deleteProfilePassword").value;
  const errBox = $("#deleteProfileError");
  errBox.classList.add("hidden");

  if (!masterPassword) {
    errBox.textContent = "Enter this profile's master password.";
    errBox.classList.remove("hidden");
    return;
  }

  const result = await browser.runtime.sendMessage({
    type: "SAX_DELETE_PROFILE", id: profilePendingDeletion.id, masterPassword,
  });

  if (!result.ok) {
    errBox.textContent = result.error;
    errBox.classList.remove("hidden");
    return;
  }

  closeDeleteProfileModal();
  await renderProfilesSettings();
  // The deleted profile may have been selected in the Password Manager tab.
  selectedProfileId = null;
  await refreshProfilesAndStatus();
  renderProfileList();
  renderGenerateStatus();
  await reloadAccountsUI();
});

$("#showAddProfileBtn").addEventListener("click", () => {
  $("#addProfilePanel").classList.remove("hidden");
  $("#showAddProfileBtn").classList.add("hidden");
});

$("#addProfileCancelBtn").addEventListener("click", () => {
  $("#addProfilePanel").classList.add("hidden");
  $("#showAddProfileBtn").classList.remove("hidden");
  $("#newProfileName").value = "";
  $("#newProfilePw1").value = "";
  $("#newProfilePw2").value = "";
  $("#addProfileError").classList.add("hidden");
});

$("#addProfileSaveBtn").addEventListener("click", async () => {
  const name = $("#newProfileName").value.trim();
  const p1 = $("#newProfilePw1").value;
  const p2 = $("#newProfilePw2").value;
  const errBox = $("#addProfileError");
  errBox.classList.add("hidden");

  if (!name) { errBox.textContent = "Enter a profile name."; errBox.classList.remove("hidden"); return; }
  if (!p1 || p1.length < 8) { errBox.textContent = "Use at least 8 characters."; errBox.classList.remove("hidden"); return; }
  if (p1 !== p2) { errBox.textContent = "Passwords don't match."; errBox.classList.remove("hidden"); return; }

  const result = await browser.runtime.sendMessage({ type: "SAX_ADD_PROFILE", name, masterPassword: p1 });
  if (!result.ok) { errBox.textContent = result.error; errBox.classList.remove("hidden"); return; }

  $("#addProfileCancelBtn").click(); // reset the form
  await renderProfilesSettings();
  await refreshProfilesAndStatus();
  renderProfileList();
});

/* ===================================================================== *
 * Vault (Phase 3B) -- minimal functional UI; the final redesign is a
 * later phase. Vault data is rendered with textContent/DOM APIs only
 * (never innerHTML), and a fetched secret is never held longer than the
 * single action (copy) that requested it. List/match rows never contain
 * secrets: they are built from summaries that background.js strips.
 * ===================================================================== */

function showVaultError(el, message) {
  el.textContent = message;
  el.classList.remove("hidden");
}

function setVaultMessage(text) {
  $("#vaultActionMessage").textContent = text || "";
}

function makeVaultButton(label, className, itemId) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.dataset.id = itemId;
  return button;
}

function renderVaultItemRow(item, { showFillButton }) {
  const row = document.createElement("div");
  row.className = "detail-row";
  const label = document.createElement("span");
  label.textContent = `${item.site}${item.accountLabel ? ` (${item.accountLabel})` : ""}${item.username ? ` \u2014 ${item.username}` : ""}`;
  const actions = document.createElement("span");
  actions.className = "field-row";
  actions.style.gap = "4px";
  if (showFillButton) actions.appendChild(makeVaultButton("Fill", "secondary-btn vault-fill-btn", item.id));
  actions.appendChild(makeVaultButton("Copy", "secondary-btn vault-copy-btn", item.id));
  actions.appendChild(makeVaultButton("Delete", "danger-btn vault-delete-btn", item.id));
  row.append(label, actions);
  return row;
}

function wireVaultItemButtons(container) {
  container.querySelectorAll(".vault-fill-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const result = await browser.runtime.sendMessage({ type: "SAX_VAULT_FILL", profileId: selectedProfileId, itemId: btn.dataset.id });
      setVaultMessage(result.ok ? "Filled." : (result.error || "Couldn't fill this page."));
    });
  });
  container.querySelectorAll(".vault-copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      // Explicitly user-initiated. Fetches this ONE item's secret on demand.
      // No automatic clipboard clearing: see the Phase 3B report for why
      // that needs a new permission and is therefore not implemented.
      const result = await browser.runtime.sendMessage({ type: "SAX_VAULT_GET_ITEM", profileId: selectedProfileId, itemId: btn.dataset.id });
      if (!result.ok) { setVaultMessage(result.error); return; }
      await navigator.clipboard.writeText(result.item.secret);
      setVaultMessage("Copied to clipboard. Clear it yourself when you're done: it is not cleared automatically.");
    });
  });
  container.querySelectorAll(".vault-delete-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await browser.runtime.sendMessage({ type: "SAX_VAULT_DELETE_ITEM", profileId: selectedProfileId, itemId: btn.dataset.id });
      await renderVaultList($("#vaultSearchInput").value);
      await renderVaultMatchesForActiveTab();
    });
  });
}

async function renderVaultList(query) {
  const list = $("#vaultItemsList");
  const result = await browser.runtime.sendMessage({ type: "SAX_VAULT_LIST", profileId: selectedProfileId, query });
  list.replaceChildren();
  if (!result.ok) { list.textContent = result.error; return; }
  if (result.items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "footnote";
    empty.textContent = query ? "No saved credentials match that search." : "No saved credentials yet.";
    list.appendChild(empty);
    return;
  }
  for (const item of result.items) list.appendChild(renderVaultItemRow(item, { showFillButton: false }));
  wireVaultItemButtons(list);
}

async function renderVaultMatchesForActiveTab() {
  const box = $("#vaultMatchesBox");
  const list = $("#vaultMatchesList");
  const result = await browser.runtime.sendMessage({ type: "SAX_VAULT_MATCHES_FOR_ACTIVE_TAB", profileId: selectedProfileId });
  list.replaceChildren();
  if (!result.ok || result.items.length === 0) { box.classList.add("hidden"); return; }
  box.classList.remove("hidden");
  for (const item of result.items) list.appendChild(renderVaultItemRow(item, { showFillButton: true }));
  wireVaultItemButtons(list);
}

async function showVaultUnlocked() {
  $("#vaultLockedView").classList.add("hidden");
  $("#vaultUnlockedView").classList.remove("hidden");
  setVaultMessage("");
  await renderVaultMatchesForActiveTab();
  await renderVaultList("");
}

async function initVaultTab() {
  if (!selectedProfileId) return;
  $("#vaultUnlockError").classList.add("hidden");
  const status = await browser.runtime.sendMessage({ type: "SAX_VAULT_STATUS", profileId: selectedProfileId });
  if (status.unlocked) {
    await showVaultUnlocked();
  } else {
    $("#vaultLockedView").classList.remove("hidden");
    $("#vaultUnlockedView").classList.add("hidden");
  }
}

$("#vaultUnlockBtn").addEventListener("click", async () => {
  $("#vaultUnlockError").classList.add("hidden");
  const result = await browser.runtime.sendMessage({
    type: "SAX_VAULT_UNLOCK", profileId: selectedProfileId, masterPassword: $("#vaultUnlockPassword").value,
  });
  $("#vaultUnlockPassword").value = "";
  if (!result.ok) { showVaultError($("#vaultUnlockError"), result.error); return; }
  await showVaultUnlocked();
});

$("#vaultLockBtn").addEventListener("click", async () => {
  await browser.runtime.sendMessage({ type: "SAX_VAULT_LOCK", profileId: selectedProfileId });
  $("#vaultItemsList").replaceChildren();
  $("#vaultMatchesList").replaceChildren();
  await initVaultTab();
});

$("#vaultSearchInput").addEventListener("input", (e) => { renderVaultList(e.target.value); });

$("#vaultGenerateBtn").addEventListener("click", async () => {
  const result = await browser.runtime.sendMessage({ type: "SAX_VAULT_GENERATE_PASSWORD", length: 20 });
  if (result.ok) $("#vaultNewSecret").value = result.password;
});

$("#vaultAddBtn").addEventListener("click", async () => {
  $("#vaultAddError").classList.add("hidden");
  const item = {
    site: $("#vaultNewSite").value, username: $("#vaultNewUsername").value, secret: $("#vaultNewSecret").value,
    accountLabel: $("#vaultNewAccountLabel").value, notes: $("#vaultNewNotes").value,
  };
  const result = await browser.runtime.sendMessage({ type: "SAX_VAULT_ADD_ITEM", profileId: selectedProfileId, item });
  if (!result.ok) { showVaultError($("#vaultAddError"), result.error); return; }
  for (const id of ["#vaultNewSite", "#vaultNewUsername", "#vaultNewSecret", "#vaultNewAccountLabel", "#vaultNewNotes"]) $(id).value = "";
  await renderVaultList("");
  await renderVaultMatchesForActiveTab();
});

$("#vaultExportBtn").addEventListener("click", async () => {
  const result = await browser.runtime.sendMessage({ type: "SAX_VAULT_EXPORT", profileId: selectedProfileId });
  if (!result.ok) { setVaultMessage(result.error); return; }
  const blob = new Blob([JSON.stringify(result.exportData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "secureauthx-vault-export.json";
  a.click();
  URL.revokeObjectURL(url);
});

$("#vaultImportBtn").addEventListener("click", () => $("#vaultImportFile").click());

$("#vaultImportFile").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  let exportData;
  try { exportData = JSON.parse(await file.text()); } catch { alert("That file isn't valid JSON."); return; }
  const masterPassword = prompt("Enter the master password that encrypted this export file:");
  if (!masterPassword) return;
  let result = await browser.runtime.sendMessage({ type: "SAX_VAULT_IMPORT", profileId: selectedProfileId, exportData, masterPassword });
  if (result.needsConfirmation) {
    if (!confirm("A vault already exists for this profile. Importing will REPLACE it. Continue?")) return;
    result = await browser.runtime.sendMessage({ type: "SAX_VAULT_IMPORT", profileId: selectedProfileId, exportData, masterPassword, confirmOverwrite: true });
  }
  if (!result.ok) { alert(result.error); return; }
  setVaultMessage("Vault imported.");
  await renderVaultList("");
  await renderVaultMatchesForActiveTab();
});

/* ===================================================================== *
 * Init
 * ===================================================================== */

async function initAfterOnboarding() {
  await initTheme();
  await initActiveDomain();
  await refreshProfilesAndStatus();
  renderProfileList();
  renderGenerateStatus();
  await reloadAccountsUI();
  await renderSites();
}

(async function init() {
  const onboarded = await checkOnboarding();
  if (onboarded) await initAfterOnboarding();
})();
