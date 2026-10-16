/**
 * SecureAuthX — content.js
 *
 * Responsibilities:
 *  1. Detect password fields and inject a small SecureAuthX icon beside
 *     each one (positioned via a shadow-DOM overlay, so we never touch
 *     the host page's own DOM structure/styles).
 *  2. On icon click: show the inline account-selection panel, prompt for
 *     the master password if the profile is locked, and ask the
 *     background script to derive (master + domain + account identity).
 *  3. Fill the derived password back into the field and show a brief
 *     confirmation. The master password is only ever held in a local JS
 *     variable for the duration of this flow, and the derived password
 *     is never displayed or logged.
 *  4. Also answers signal-gathering / fill requests from the popup
 *     (used by the popup's own Generate tab).
 */
 
 let activePanel = null;
let activePanelField = null;

(function () {
  // ---------------- Signals from page-hook.js (MAIN world) ----------------
  //
  // Batch 4 Phase 2B: this block is placed FIRST, and unconditionally, so
  // it runs the same way whether this content script instance is in the
  // top frame or a sub-frame (all_frames is now enabled in manifest.json
  // for iframe fingerprinting coverage). Every OTHER responsibility of
  // this file (autofill panel injection, form/mixed-content collection,
  // message handling) is top-frame-only -- see the `isTopFrame` early
  // return immediately after this block. Filling a password into a
  // frame other than the top-level page's own would be a real security
  // concern, and a phishing/critical-alert banner inside a third-party
  // iframe would be meaningless -- gating everything else to the top
  // frame avoids both, as a direct consequence of this ordering, not a
  // separate check that has to be kept in sync.

  const fingerprintTechniques = new Set();
  const activePermissionCalls = new Set(); // apis the page actually invoked this page load

  // Batch 4 Phase 2B: mirrors this FRAME's own current fingerprint
  // technique list into a plain property on this content script's own
  // (isolated-world) `window` object. This is NOT the page-hook.js
  // MAIN-world buffer bug from before -- this property is read back by
  // background.js via `chrome.scripting.executeScript` targeting THIS
  // SAME isolated world, in THIS SAME frame, which is a valid, working
  // channel (unlike a cross-world `window` property, this never needs to
  // cross the MAIN/isolated boundary at all). Contains ONLY the fixed
  // technique-identifier strings already used everywhere else in this
  // pipeline -- no page content, no URLs, no per-technique values.
  function updateFrameSignalsMirror() {
    window.__saxFrameSignals = { fingerprintTechniques: Array.from(fingerprintTechniques) };
  }

  function handleSaxSignal(detail) {
    const { category, technique } = detail || {};
    if (category === "fingerprint") fingerprintTechniques.add(technique);
    if (category === "permission") activePermissionCalls.add(technique);
    updateFrameSignalsMirror();
  }

  window.addEventListener("sax:signal", (e) => handleSaxSignal(e.detail));

  // Batch 3 fix (corrected): this content script (isolated world) only
  // attaches its listener at document_idle, which is AFTER page-hook.js
  // (MAIN world) has already been running since document_start. Any
  // signal dispatched before this listener existed would otherwise be
  // silently lost.
  //
  // A `window.__saxSignalBuffer` property does NOT work as a catch-up
  // channel here: MAIN and isolated worlds have separate JavaScript
  // global objects, so a property page-hook.js sets on ITS `window` is
  // simply absent on THIS script's `window` -- it is not a shared value
  // at all. The DOM, however, is genuinely shared between the two
  // worlds, so page-hook.js records the same "category:technique"
  // identifiers already carried by the live event into a DOM attribute
  // on `document.documentElement` instead. That attribute is read once,
  // here, to recover anything missed before this exact listener existed.
  // Each frame has its OWN `document.documentElement`, so this
  // drain-on-startup correctly recovers only THIS frame's own early
  // signals, never another frame's.
  //
  // Malformed or missing attribute data must never break this content
  // script -- content.js runs on every page, including ones this
  // extension does not control -- so every step is defensively guarded
  // and any failure simply means nothing is drained, not a thrown error.
  try {
    const raw = document.documentElement.getAttribute("data-sax-signals");
    if (raw) {
      const bufferedKeys = JSON.parse(raw);
      if (Array.isArray(bufferedKeys)) {
        for (const key of bufferedKeys) {
          if (typeof key !== "string") continue;
          const separatorIndex = key.indexOf(":");
          if (separatorIndex === -1) continue;
          handleSaxSignal({
            category: key.slice(0, separatorIndex),
            technique: key.slice(separatorIndex + 1),
          });
        }
      }
    }
  } catch {
    // Malformed attribute data (or no documentElement, or JSON.parse
    // failure) must never break the rest of this content script.
  } finally {
    try { document.documentElement.removeAttribute("data-sax-signals"); } catch { /* ignore */ }
  }

  // Batch 4 Phase 2B: everything below this point (autofill panel
  // injection, password-field detection, form/mixed-content/tracker
  // collection, and all message handling including SAX_GET_SIGNALS) is
  // TOP-FRAME-ONLY. A sub-frame's content script instance stops here --
  // it has already done the one thing it needs to do (listen for and
  // mirror this frame's own fingerprint signals) and returns without
  // registering a runtime.onMessage listener at all. This means
  // background.js's existing `browser.tabs.sendMessage(tab.id, {type:
  // "SAX_GET_SIGNALS"})` continues to be answered by the top frame only,
  // exactly as before all_frames was enabled -- not because of a
  // same-frame runtime check, but structurally, because no other frame's
  // content script ever reaches the code that would respond to it.
  const isTopFrame = window === window.top;
  if (!isTopFrame) return;

  const trackedFields = new Map(); // passwordField -> icon element
  // Shared inline-SVG icon set for this content script — no emoji anywhere
  // in the injected UI. Kept as a plain object since this file is a
  // classic content script (not an ES module), so it can't import popup.js's copy.
  const ICONS = {
    lock: '<svg class="icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
    unlock: '<svg class="icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.7"/></svg>',
    check: '<svg class="icon" viewBox="0 0 24 24" stroke-width="2.5"><path d="M4 12l5 5L20 6"/></svg>',
    warning: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3l10 18H2L12 3z"/><path d="M12 9v5"/><path d="M12 17h.01"/></svg>',
    cross: '<svg class="icon" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    trash: '<svg class="icon" viewBox="0 0 24 24"><path d="M4 7h16M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2m-8 0v12a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2V7"/></svg>',
    plus: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
  };
  // Kept in sync with MAX_ACCOUNTS_PER_SITE in lib/storage.js. Content
  // scripts can't import that module (not loaded as an ES module), so
  // this is the one place that constant has to be duplicated.
  const MAX_ACCOUNTS_PER_SITE = 5;

  function findPasswordFields() {
    return Array.from(document.querySelectorAll('input[type="password"]'));
  }

  // ---------------- Shadow-DOM overlay (icons + modal) ----------------

  const host = document.createElement("div");
  host.style.all = "initial";
  document.documentElement.appendChild(host);
  const shadow = host.attachShadow({ mode: "open" });

  const style = document.createElement("style");
  style.textContent = `
    .sax-icon {
      position: fixed; width: 22px; height: 22px; border-radius: 50%;
      background: #e5e5e5; color: #000000; font-size: 12px; font-weight: 700;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer; z-index: 2147483647; box-shadow: 0 1px 4px rgba(0,0,0,.3);
      font-family: sans-serif; transition: transform .12s;
    }
    .sax-icon:hover { transform: scale(1.1); }
    .sax-panel {
      position: fixed; z-index: 2147483647; width: 260px;
      background: #161616; color: #f2f2f2; border: 1px solid #2e2e2e;
      border-radius: 12px; padding: 14px; font-family: sans-serif; font-size: 12.5px;
      box-shadow: 0 10px 28px rgba(0,0,0,.45);
      animation: sax-fade-in .12s ease-out;
    }
    @keyframes sax-fade-in { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
    .sax-panel .sax-title { font-weight: 700; margin-bottom: 10px; display: flex; align-items: center; gap: 6px; }
    .sax-panel .sax-dot { width: 8px; height: 8px; border-radius: 50%; background: #22d3a5; box-shadow: 0 0 6px #22d3a5; }
    .sax-panel .sax-close {
      margin-left: auto; width: 20px; height: 20px; border-radius: 50%;
      background: transparent; border: none; color: #a3a3a3; font-size: 13px;
      cursor: pointer; display: flex; align-items: center; justify-content: center; padding: 0;
    }
    .sax-panel .sax-close:hover { background: #2e2e2e; color: #f2f2f2; }
    .sax-panel label { display: block; font-size: 10.5px; color: #a3a3a3; margin-bottom: 4px; margin-top: 8px; }
   .sax-panel select,
.sax-panel input[type="password"],
.sax-panel input[type="text"] {
    width: 100%;
    box-sizing: border-box;
    background: #000000;
    color: #f2f2f2;
    border: 1px solid #2e2e2e;
    border-radius: 7px;
    padding: 7px 8px;
    font-size: 12.5px;
}
    .sax-status-row { display: flex; align-items: center; gap: 6px; font-weight: 600; margin: 6px 0; }
    .icon { width: 13px; height: 13px; vertical-align: -2px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; flex-shrink: 0; }
    .status-locked { color: #a3a3a3; }
    .status-unlocked { color: #22d3a5; }
    .sax-checkbox-row { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #a3a3a3; margin: 8px 0; cursor: pointer; }
    .sax-account-list {
      display: grid; grid-template-columns: 1fr 1fr; gap: 5px; margin: 4px 0 8px;
    }
    .sax-account-row {
      display: flex; align-items: center; justify-content: space-between; gap: 2px;
      border: 1px solid #2e2e2e; border-radius: 7px; background: #000000;
    }
    .sax-account-row:has(input:checked) { border-color: #ffffff; background: rgba(255,255,255,0.08); }
    .sax-account-row .sax-checkbox-row { flex: 1; min-width: 0; padding: 6px 7px; margin: 0; font-size: 11.5px; }
    .sax-account-row .sax-checkbox-row span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sax-account-delete {
    width: 20px;
    height: 20px;

    flex: 0 0 20px;

    display: flex;
    align-items: center;
    justify-content: center;

    padding: 0;
    margin-left: 4px;

    background: none;
    border: none;
    border-radius: 5px;

    color: #a3a3a3;
    cursor: pointer;

    opacity: 0;
    transition: opacity .15s, background .15s, color .15s;
}

.sax-account-row:hover .sax-account-delete {
    opacity: .7;
}

.sax-account-delete:hover {
    opacity: 1;
    color: #ff5c72;
    background: rgba(255,92,114,.12);
}
    .sax-account-delete:hover { opacity: 1; color: #ff5c72; }
    .sax-max-accounts-note { font-size: 10.5px; color: #a3a3a3; padding: 2px 0 4px; }
    .sax-panel .go,
.sax-panel .lock {
    border: none;
    border-radius: 7px;
    padding: 8px 10px;
    font-size: 12px;
    cursor: pointer;
    font-weight: 600;
    margin-top: 8px;
    width: 100%;
    transition: opacity .1s;
}
.sax-panel button {
    border: none;
    border-radius: 7px;
    cursor: pointer;
    transition: opacity .1s;
}
    .sax-panel .go { background: #ffffff; color: #000000; }
    .sax-panel .lock { background: transparent; color: #ff5c72; border: 1px solid #ff5c72; }
    .sax-panel .add-link { background: none; color: #a3a3a3; text-decoration: underline; font-weight: 400; font-size: 11px; padding: 4px 0; }
    .sax-panel .err { color: #ff5c72; margin-top: 6px; font-size: 11.5px; }
    .sax-account-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; }

    .sax-account-delete:hover { opacity: 1; color: #ff5c72; background: rgba(255,92,114,.12); }
    .sax-toast {
      position: fixed; z-index: 2147483647; background: #22d3a5; color: #000000;
      padding: 6px 10px; border-radius: 6px; font-family: sans-serif; font-size: 12px; font-weight: 700;
      animation: sax-fade-in .12s ease-out;
    }
    .sax-banner {
      position: fixed; z-index: 2147483647; width: 280px;
      background: #161616; border-radius: 12px; padding: 14px;
      font-family: sans-serif; font-size: 12.5px; color: #f2f2f2;
      box-shadow: 0 10px 28px rgba(0,0,0,.45);
      animation: sax-fade-in .15s ease-out;
    }
    .sax-banner.loud { border: 2px solid #ff5c72; }
    .sax-banner.quiet { border: 1px solid #22d3a5; }
    .sax-banner .sax-banner-head { display: flex; align-items: center; gap: 8px; font-weight: 700; margin-bottom: 8px; font-size: 13px; }
    .sax-banner .sax-banner-close {
      margin-left: auto; width: 20px; height: 20px; border-radius: 50%;
      background: transparent; border: none; color: #a3a3a3; font-size: 13px;
      cursor: pointer; display: flex; align-items: center; justify-content: center; padding: 0;
    }
    .sax-banner .sax-banner-close:hover { background: #2e2e2e; color: #f2f2f2; }
    .sax-banner ul { list-style: none; margin: 0 0 8px; padding: 0; }
    .sax-banner li { display: flex; gap: 6px; margin-bottom: 4px; align-items: flex-start; line-height: 1.4; }
    .sax-banner .sax-banner-advice { font-size: 11.5px; color: #a3a3a3; margin-top: 4px; }
    .sax-banner.loud .sax-banner-advice { color: #ff9aa8; font-weight: 600; }
  `;
  shadow.appendChild(style);

  function positionNear(el, field) {
    const r = field.getBoundingClientRect();
    el.style.top = `${r.top + r.height / 2 - (el.offsetHeight || 22) / 2}px`;
    el.style.left = `${r.right + 6}px`;
  }

  function showToast(html, nearEl) {
    const toast = document.createElement("div");
    toast.className = "sax-toast";
    toast.innerHTML = html;
    shadow.appendChild(toast);
    const r = nearEl.getBoundingClientRect();
    toast.style.top = `${r.top - 28}px`;
    toast.style.left = `${r.left}px`;
    setTimeout(() => toast.remove(), 1800);
  }

  function fillField(field, value) {
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    nativeSetter.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /* ==================================================================== *
   * Safe Browsing Assistant banners — "Smart Warnings" design:
   * loud (persistent, must-dismiss) only for orange/red criticalIssue
   * results; quiet (brief, auto-dismissing) for green/yellow. This is
   * deliberate — interrupting for every minor issue is what makes real
   * users tune out security warnings entirely.
   * ==================================================================== */

  const TIER_ICON = {
    green: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
    yellow: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M12 8v5"/><path d="M12 16h.01"/></svg>',
    orange: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3l10 18H2L12 3z"/><path d="M12 9v5"/><path d="M12 17h.01"/></svg>',
    red: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3l10 18H2L12 3z"/><path d="M12 9v5"/><path d="M12 17h.01"/></svg>',
  };
  const TIER_COLOR = { green: "#16a37a", yellow: "#ffb648", orange: "#ff8a3d", red: "#ff5c72" };

  function renderSafetyBanner({ summary, dashboard, criticalIssue, label, anchorEl }) {
    document.querySelectorAll(".sax-banner-active").forEach((b) => b.remove());

    const banner = document.createElement("div");
    banner.className = `sax-banner sax-banner-active ${criticalIssue ? "loud" : "quiet"}`;
    const tierColor = dashboard ? (TIER_COLOR[dashboard.color] || TIER_COLOR.yellow) : TIER_COLOR.yellow;
    const tierIcon = dashboard ? (TIER_ICON[dashboard.color] || TIER_ICON.yellow) : TIER_ICON.yellow;
    banner.innerHTML = `
      <div class="sax-banner-head">
        <span style="color:${tierColor}; display:inline-flex;">${tierIcon}</span>
        <span>SecureAuthX — ${label}</span>
        ${criticalIssue ? `<button class="sax-banner-close" title="Close">${ICONS.cross}</button>` : ""}
      </div>
      <ul>
        ${summary.bullets.map((b) => `<li><span>${b.ok ? ICONS.check : ICONS.warning}</span><span>${b.text}</span></li>`).join("")}
      </ul>
      <div class="sax-banner-advice">${summary.advice}</div>
    `;
    shadow.appendChild(banner);

    if (anchorEl) {
      const r = anchorEl.getBoundingClientRect();
      banner.style.top = `${Math.max(6, r.top - 10)}px`;
      banner.style.left = `${Math.max(6, r.right + 10)}px`;
    } else {
banner.style.top = "16px";
banner.style.right = "16px";
banner.style.left = "auto";
}

    if (criticalIssue) {
      const closeBtn = banner.querySelector(".sax-banner-close");
      closeBtn.addEventListener("click", () => banner.remove());
      function escHandler(e) {
        if (e.key === "Escape") {
          banner.remove();
          document.removeEventListener("keydown", escHandler, true);
        }
      }
      document.addEventListener("keydown", escHandler, true);
    } else {
      setTimeout(() => banner.remove(), 4000);
    }
  }

  // Payment-field detection: common autocomplete tokens and name/id
  // patterns used by real checkout forms. Heuristic, not exhaustive.
  function isPaymentField(el) {
    const autocomplete = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (["cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-name"].includes(autocomplete)) return true;
    const probe = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""}`.toLowerCase();
    return /card[-_ ]?number|cc[-_]?number|cvv|cvc|card[-_ ]?holder|expiry|exp[-_ ]?date/.test(probe);
  }

  function findPaymentFields() {
    return Array.from(document.querySelectorAll("input")).filter(isPaymentField);
  }

  // Tracks which triggers have already shown a banner this page load, so
  // refocusing the same field repeatedly doesn't spam banners.
  const bannerShownFor = new Set();

  async function maybeShowFieldBanner(field, label) {
    const key = `${label}:${field}`;
    if (bannerShownFor.has(key)) return;
    bannerShownFor.add(key);

    const result = await browser.runtime.sendMessage({ type: "SAX_GET_SAFETY_SUMMARY" });
    if (!result.ok) return; // fail silently — this is a proactive nicety, not a critical path
    renderSafetyBanner({ summary: result.summary, dashboard: result.dashboard, criticalIssue: result.criticalIssue, label, anchorEl: field });
  }

  // Proactive alert pushed unsolicited from background.js when the automatic
  // per-page-load scan finds a critical issue (e.g. fake-login lookalike
  // domain) — shown immediately, not gated on the user focusing anything.
  browser.runtime.onMessage.addListener((message) => {
    if (message.type === "SAX_CRITICAL_ALERT" && !bannerShownFor.has("proactive")) {
      bannerShownFor.add("proactive");
      renderSafetyBanner({ summary: message.summary, dashboard: message.dashboard, criticalIssue: true, label: "Warning", anchorEl: null });
    }
  });

  /**
   * The inline dropdown panel (Features 3, 5, 6, 8): profile selector,
   * live locked/unlocked status for the selected profile, conditional
   * master-password field, "unlock for this session" checkbox, Generate,
   * and Lock Session. No browser alert()/confirm() dialogs are used —
   * all feedback renders inline in the panel.
   */
async function openDerivePanel(field, icon) {
    if (activePanel) {
        activePanel.remove();
        activePanel = null;
        activePanelField = null;
    }

    const panel = document.createElement("div");
    panel.className = "sax-panel sax-panel-active";

    activePanel = panel;
    activePanelField = field;
    panel.innerHTML = `<div class="sax-title"><span class="sax-dot"></span>SecureAuthX<button class="sax-close" title="Close">${ICONS.cross}</button></div><div class="sax-body">Loading profiles…</div>`;
    shadow.appendChild(panel);
const r = field.getBoundingClientRect();   // <-- use the password field, not the icon

const PANEL_WIDTH = 260;
const GAP = 12;

// Position to the right of the password field
let left = r.right + GAP;

// If there isn't enough room, place it on the left
if (left + PANEL_WIDTH > window.innerWidth) {
    left = r.left - PANEL_WIDTH - GAP;
}

// Keep it inside the viewport
left = Math.max(10, Math.min(left, window.innerWidth - PANEL_WIDTH - 10));

// Align with the password field
const panelHeight = panel.offsetHeight || 250;
let top = r.top + (r.height - panelHeight) / 2;

// Prevent it from going off-screen vertically
top = Math.max(
    10,
    Math.min(top, window.innerHeight - panelHeight - 10)
);

panel.style.left = `${left}px`;
panel.style.top = `${top}px`;
    // ---- Close mechanics: close (×) button, click outside, Escape key ----
function closePanel() {
    if (activePanel === panel) {
        activePanel = null;
        activePanelField = null;
    }

    panel.remove();

    document.removeEventListener("click", outsideClickHandler, true);
    document.removeEventListener("keydown", escHandler, true);
}
    function outsideClickHandler(e) {
      const path = e.composedPath();
      if (!path.includes(panel) && !path.includes(icon)) closePanel();
    }
    function escHandler(e) {
      if (e.key === "Escape") closePanel();
    }
    panel.querySelector(".sax-close").addEventListener("click", closePanel);
    // Defer attaching the outside-click listener by a tick so the same
    // click that opened the panel (via the icon) doesn't instantly close it.
    setTimeout(() => {
      document.addEventListener("click", outsideClickHandler, true);
      document.addEventListener("keydown", escHandler, true);
    }, 0);

    const listResult = await browser.runtime.sendMessage({ type: "SAX_LIST_PROFILES" });
    if (!listResult.profiles || listResult.profiles.length === 0) {
      panel.querySelector(".sax-body").innerHTML =
        `Set up your first Master Profile in the SecureAuthX popup first.`;
      return;
    }

    let selectedId = listResult.defaultProfileId || listResult.profiles[0].id;
    let sessionStatus = listResult.sessionStatus;
    const domain = window.location.hostname;
    let accounts = [];
    let selectedAccount = null;

    async function loadAccounts() {
      const result = await browser.runtime.sendMessage({ type: "SAX_LIST_ACCOUNTS", profileId: selectedId, domain });
      accounts = result.ok ? result.accounts : ["Default"];
      selectedAccount = (result.ok && result.lastSelected) || accounts[0];
    }

    function accountListHtml() {
      return accounts.map((name) => `
        <div class="sax-account-row">
          <label class="sax-checkbox-row" style="margin:2px 0;flex:1;">
            <input type="radio" name="sax-account" value="${name}" ${name === selectedAccount ? "checked" : ""} />
            <span>${name}</span>
          </label>
${accounts.length > 1 ? `
<button
    type="button"
    class="sax-account-delete"
    data-name="${name}">
    ${ICONS.trash}
</button>
` : ""}
        </div>
      `).join("");
    }

    function renderBody() {
      const unlocked = !!sessionStatus[selectedId];
      const body = panel.querySelector(".sax-body");
      body.innerHTML = `
        <label>Master Profile</label>
        <select class="sax-profile-select">
          ${listResult.profiles.map((p) => `<option value="${p.id}" ${p.id === selectedId ? "selected" : ""}>${p.name}</option>`).join("")}
        </select>

        <div class="sax-status-row">
          <span class="${unlocked ? 'status-unlocked' : 'status-locked'}">${unlocked ? ICONS.unlock : ICONS.lock}</span>
          <span>${unlocked ? "Session Unlocked" : "Locked"}</span>
        </div>

        <label>Account</label>
        <div class="sax-account-list">${accountListHtml()}</div>
        <div class="sax-add-account-row">
          ${accounts.length >= MAX_ACCOUNTS_PER_SITE
            ? `<div class="sax-max-accounts-note">Maximum of ${MAX_ACCOUNTS_PER_SITE} accounts reached for this site.</div>`
            : `<button class="add-link sax-show-add-account">${ICONS.plus} Add Account</button>
               <input type="text" class="sax-new-account-input" style="display:none;" maxlength="40" placeholder="Account name" />`
          }
        </div>

        ${unlocked ? "" : `
          <label>Master Password</label>
          <input type="password" class="sax-master-input" autocomplete="off" />
          <label class="sax-checkbox-row"><input type="checkbox" class="sax-remember-checkbox" /> Unlock for this browser session</label>
        `}

        <button class="go">Generate &amp; Autofill</button>
        ${unlocked ? `<button class="lock">${ICONS.lock} Lock Session</button>` : ""}
        <button class="add-link">+ Add another profile (opens SecureAuthX popup)</button>
        <div class="err" style="display:none"></div>
      `;

      body.querySelector(".sax-profile-select").addEventListener("change", async (e) => {
        selectedId = e.target.value;
        await loadAccounts();
        renderBody();
      });

      body.querySelectorAll('input[name="sax-account"]').forEach((radio) => {
        radio.addEventListener("change", async (e) => {
          selectedAccount = e.target.value;
          await browser.runtime.sendMessage({ type: "SAX_SELECT_ACCOUNT", profileId: selectedId, domain, name: selectedAccount });
        });
      });

      body.querySelectorAll(".sax-account-delete").forEach((delBtn) => {
        delBtn.addEventListener("click", async () => {
          const result = await browser.runtime.sendMessage({ type: "SAX_DELETE_ACCOUNT", profileId: selectedId, domain, name: delBtn.dataset.name });
          if (!result.ok) {
            const errBox = panel.querySelector(".err");
            errBox.textContent = result.error;
            errBox.style.display = "block";
            return;
          }
          accounts = result.accounts;
          selectedAccount = result.lastSelected;
          renderBody();
        });
      });

      const showAddBtn = body.querySelector(".sax-show-add-account");
      const newAccountInput = body.querySelector(".sax-new-account-input");
      if (showAddBtn && newAccountInput) {
        showAddBtn.addEventListener("click", () => {
          showAddBtn.style.display = "none";
          newAccountInput.style.display = "block";
          newAccountInput.focus();
        });
        async function commitNewAccount() {
          const name = newAccountInput.value.trim();
          if (!name) { newAccountInput.style.display = "none"; showAddBtn.style.display = ""; return; }
          const result = await browser.runtime.sendMessage({ type: "SAX_ADD_ACCOUNT", profileId: selectedId, domain, name });
          if (!result.ok) {
            const errBox = panel.querySelector(".err");
            errBox.textContent = result.error;
            errBox.style.display = "block";
            return;
          }
          accounts = result.accounts;
          selectedAccount = result.lastSelected;
          renderBody();
        }
        newAccountInput.addEventListener("keydown", (e) => { if (e.key === "Enter") commitNewAccount(); });
      }

      body.querySelectorAll(".add-link").forEach((btn) => {
        if (btn === showAddBtn) return;
        btn.addEventListener("click", () => {
          showToast("Open the SecureAuthX toolbar icon, then Profiles, to add a profile", field);
        });
      });

      body.querySelector(".go").addEventListener("click", doGenerate);

      const lockBtn = body.querySelector(".lock");
      if (lockBtn) {
        lockBtn.addEventListener("click", async () => {
          await browser.runtime.sendMessage({ type: "SAX_LOCK_PROFILE", id: selectedId });
          sessionStatus[selectedId] = false;
          renderBody();
        });
      }

      const masterInput = body.querySelector(".sax-master-input");
      if (masterInput) {
        masterInput.focus();
        masterInput.addEventListener("keydown", (e) => { if (e.key === "Enter") doGenerate(); });
      }
    }

    async function doGenerate() {
      const errBox = panel.querySelector(".err");
      errBox.style.display = "none";

      if (!selectedAccount) {
        errBox.textContent = "Select an account first.";
        errBox.style.display = "block";
        return;
      }

      const unlocked = !!sessionStatus[selectedId];
      const masterInput = panel.querySelector(".sax-master-input");
      const rememberCheckbox = panel.querySelector(".sax-remember-checkbox");
      const masterPassword = masterInput ? masterInput.value : undefined;

      if (!unlocked && !masterPassword) {
        errBox.textContent = "Enter this profile's master password.";
        errBox.style.display = "block";
        return;
      }

      const result = await browser.runtime.sendMessage({
        type: "SAX_GENERATE_PASSWORD",
        profileId: selectedId,
        domain,
        accountId: selectedAccount,
        masterPassword: unlocked ? undefined : masterPassword,
        rememberSession: rememberCheckbox ? rememberCheckbox.checked : false,
      });

      if (masterInput) masterInput.value = "";

      if (!result.ok) {
        errBox.textContent = result.error;
        errBox.style.display = "block";
        return;
      }

      sessionStatus = result.sessionStatus;
      fillField(field, result.derived);
      closePanel();
      showToast(ICONS.check + " Password autofilled successfully", field);
    }

    await loadAccounts();
    renderBody();
  }

  function attachIcon(field) {
    if (trackedFields.has(field)) return;
    const icon = document.createElement("div");
    icon.className = "sax-icon";
    icon.textContent = "S";
    icon.title = "Derive password with SecureAuthX";
    shadow.appendChild(icon);
    trackedFields.set(field, icon);
    positionNear(icon, field);

icon.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();

    if (activePanel) {
        activePanel.remove();
        activePanel = null;
        activePanelField = null;
        return;
    }

    openDerivePanel(field, icon);
});
  }

  function scanForPasswordFields() {
    findPasswordFields().forEach(attachIcon);
  }

function repositionAll() {
    trackedFields.forEach((icon, field) => {
        if (!document.contains(field)) {
            icon.remove();
            trackedFields.delete(field);
            closeActivePanel();
            return;
        }

        positionNear(icon, field);
    });
}

  scanForPasswordFields();
  new MutationObserver(scanForPasswordFields).observe(document.documentElement, { childList: true, subtree: true });
function closeActivePanel() {
    if (!activePanel) return;

    activePanel.remove();
    activePanel = null;
    activePanelField = null;
}

window.addEventListener("scroll", () => {
    repositionAll();
    closeActivePanel();
}, true);

window.addEventListener("resize", () => {
    repositionAll();
    closeActivePanel();
});

  const PERMISSION_QUERY_NAMES = {
    geolocation: "geolocation",
    camera: "camera",
    microphone: "microphone",
    notifications: "notifications",
    clipboard: "clipboard-read",
  };

  async function gatherPermissionStates() {
    const results = [];
    for (const [api, queryName] of Object.entries(PERMISSION_QUERY_NAMES)) {
      let state = "unknown";
      try {
        if (navigator.permissions && navigator.permissions.query) {
          const status = await navigator.permissions.query({ name: queryName });
          state = status.state; // 'granted' | 'denied' | 'prompt'
        }
      } catch {
        state = "unknown"; // some names unsupported in some browsers (e.g. Firefox lacks several)
      }

      let displayStatus;
      if (activePermissionCalls.has(api)) displayStatus = "active";
      else if (state === "denied") displayStatus = "blocked";
      else if (state === "granted") displayStatus = "requested"; // previously granted, not invoked this visit
      else displayStatus = "not-requested";

      results.push({ api, status: displayStatus });
    }
    // fullscreen has no Permissions-API query name; only report if actively invoked.
    if (activePermissionCalls.has("fullscreen")) results.push({ api: "fullscreen", status: "active" });
    return results;
  }

  function gatherStorageUsage() {
    let localKeys = 0, sessionKeys = 0;
    try { localKeys = localStorage.length; } catch { /* blocked by page policy */ }
    try { sessionKeys = sessionStorage.length; } catch { /* blocked by page policy */ }
    return { localStorageKeys: localKeys, sessionStorageKeys: sessionKeys };
  }

  // ---------------- Signals + messages for the popup ----------------

  function gatherFormSignals() {
    // Batch 2: also report the form action's HOSTNAME (structural only —
    // e.g. "accounts.example.com") so scoring.js can classify same-site
    // vs. known-identity-provider vs. unrelated destinations. Per the
    // data-minimization requirement, this is ONLY the hostname: never the
    // full action URL, query string, fragment, request method/body, or
    // any field/input value. Nothing password- or token-related is read
    // here — this function never touches the password field itself.
    const forms = Array.from(document.forms).filter((f) => f.querySelector('input[type="password"]'));
    const pageOrigin = window.location.origin;
    return forms.map((f) => {
      let actionUrl;
      try {
        actionUrl = new URL(f.action || window.location.href, window.location.href);
      } catch {
        actionUrl = new URL(window.location.href);
      }
      return {
        actionIsHttps: actionUrl.protocol === "https:",
        actionSameOrigin: actionUrl.origin === pageOrigin,
        actionHostname: actionUrl.hostname,
      };
    });
  }

  function gatherThirdPartyScriptHosts() {
    const pageHost = window.location.hostname;
    const hosts = new Set();
    document.querySelectorAll("script[src]").forEach((s) => {
      try {
        const u = new URL(s.src, window.location.href);
        if (u.hostname !== pageHost) hosts.add(u.hostname);
      } catch { /* ignore malformed src */ }
    });
    return Array.from(hosts);
  }

  function mixedContentEvidenceUrl(raw) {
    if (!raw) return null;
    try {
      const u = new URL(raw, window.location.href);
      if (u.protocol !== "http:") return null;
      return `${u.origin}${u.pathname}`;
    } catch {
      return null;
    }
  }

  function collectMixedFromSelector(selector, attrForLink) {
    const urls = [];
    document.querySelectorAll(selector).forEach((el) => {
      const raw = el.tagName === "LINK" || attrForLink === "href"
        ? (el.getAttribute("href") || el.getAttribute("src") || "")
        : (el.getAttribute("src") || "");
      const evidence = mixedContentEvidenceUrl(raw);
      if (evidence) urls.push(evidence);
    });
    return urls;
  }

  // Active mixed content can execute or restyle the page. Passive mixed
  // content (media) is weaker. Query strings are stripped from evidence.
  function gatherMixedContent() {
    if (window.location.protocol !== "https:") {
      return { activeCount: 0, passiveCount: 0, activeEvidence: [], passiveEvidence: [] };
    }
    const active = collectMixedFromSelector("script[src], iframe[src], link[rel='stylesheet'][href]");
    const passive = collectMixedFromSelector("img[src], audio[src], video[src], source[src]");
    return {
      activeCount: active.length,
      passiveCount: passive.length,
      activeEvidence: active.slice(0, 8),
      passiveEvidence: passive.slice(0, 8),
    };
  }

  async function collectSignals() {
    const mixedContent = gatherMixedContent();
    return {
      isHttps: window.location.protocol === "https:",
      hostname: window.location.hostname,
      forms: gatherFormSignals(),
      thirdPartyScriptHosts: gatherThirdPartyScriptHosts(),
      mixedContent,
      mixedContentCount: mixedContent.activeCount,
      storageUsage: gatherStorageUsage(),
      fingerprintTechniques: Array.from(fingerprintTechniques),
      permissionEvents: await gatherPermissionStates(),
    };
  }

  let lastFocusedPasswordField = null;
  document.addEventListener("focusin", (e) => {
    const el = e.target;
    if (!el || el.tagName !== "INPUT") return;

    if (el.type === "password") {
      lastFocusedPasswordField = el;
      maybeShowFieldBanner(el, "Login Page");
    } else if (isPaymentField(el)) {
      maybeShowFieldBanner(el, "Payment Page");
    }
  }, true);

  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SAX_GET_SIGNALS") {
      collectSignals().then((signals) => {
        sendResponse({ signals, passwordFieldCount: findPasswordFields().length });
      });
      return true; // async response
    }
    if (message.type === "SAX_FILL_PASSWORD") {
      const field = lastFocusedPasswordField || findPasswordFields()[0];
      if (!field) {
        sendResponse({ ok: false, error: "No password field found on this page." });
        return true;
      }
      fillField(field, message.password);
      sendResponse({ ok: true });
      return true;
    }
    if (message.type === "SAX_FILL_USERNAME") {
      // Phase 3B: fills a vault credential's username. Scoped to the SAME
      // <form> as the password field SAX_FILL_PASSWORD targets (or the
      // document if it has no form), reusing fillField() unchanged. Like
      // every handler in this listener it exists only in the TOP frame.
      const passwordField = lastFocusedPasswordField || findPasswordFields()[0];
      if (!passwordField) { sendResponse({ ok: false, error: "No password field found on this page." }); return true; }
      const scope = passwordField.closest("form") || document;
      const candidates = scope.querySelectorAll('input[type="email"], input[autocomplete="username"], input[name*="user" i], input[name*="email" i], input[type="text"]');
      const usernameField = Array.from(candidates).find((el) => el !== passwordField && el.type !== "password" && el.type !== "hidden" && !el.disabled && !el.readOnly);
      if (!usernameField) { sendResponse({ ok: false, error: "No username field found." }); return true; }
      fillField(usernameField, message.username);
      sendResponse({ ok: true });
      return true;
    }
  });
})();
