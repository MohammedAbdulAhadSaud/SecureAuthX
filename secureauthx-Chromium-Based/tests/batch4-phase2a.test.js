/**
 * SecureAuthX — Batch 4 Phase 2A test suite
 *
 * Covers the three approved additions:
 *   1. Font Enumeration improvement (distinct-font-aware, in page-hook.js)
 *   2. WebGL getSupportedExtensions() detection (page-hook.js)
 *   3. Client Hints high-entropy detection (page-hook.js)
 * plus their tier classification in lib/analysis.js.
 *
 * The page-hook.js portions are tested against the REAL, unmodified
 * source via Node's vm module — the same pattern established in
 * tests/batch3-signal-buffer.test.js — using two genuinely separate JS
 * realms (this test's realm and the vm context) sharing only a fake DOM
 * element, mirroring Chrome's actual MAIN/isolated world split.
 *
 * Run with:  node --test tests/batch4-phase2a.test.js
 */

import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { computeFullAnalysis } from "../lib/analysis.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pageHookSource = fs.readFileSync(path.join(__dirname, "../content/page-hook.js"), "utf8");

// ---------------------------------------------------------------------
// Shared MAIN-world realm builder (extends the Batch 3 pattern with
// WebGL, Canvas 2D, and userAgentData stand-ins needed for this batch's
// three hooks; audio/canvas-fingerprint/notification/webrtc stand-ins are
// intentionally omitted since they're unrelated to what's under test
// here and already covered by their own frozen Batch 3 test file).
// ---------------------------------------------------------------------
function createFakeDocumentElement() {
  const attrs = new Map();
  return {
    getAttribute(name) { return attrs.has(name) ? attrs.get(name) : null; },
    setAttribute(name, value) { attrs.set(name, String(value)); },
    removeAttribute(name) { attrs.delete(name); },
  };
}

function createMainWorldContext(sharedDocumentElement, { withUserAgentData = true } = {}) {
  const listeners = [];

  const webglProto = {
    getParameter() { return null; },
    getExtension() { return null; },
    getSupportedExtensions() { return ["OES_texture_float", "ANGLE_instanced_arrays"]; },
  };
  const webgl2Proto = {
    getParameter() { return null; },
    getExtension() { return null; },
    getSupportedExtensions() { return ["OES_texture_float"]; },
  };
  const canvas2dProto = {
    measureText(str) { return { width: (str || "").length * 5 }; },
  };
  const uaDataProto = {
    getHighEntropyValues() { return Promise.resolve({}); },
  };

  const sandbox = {};
  sandbox.window = sandbox; // window === globalThis, matching a real page realm
  sandbox.document = { documentElement: sharedDocumentElement, contains: () => true };
  sandbox.navigator = {};
  if (withUserAgentData) {
    sandbox.navigator.userAgentData = Object.create(uaDataProto);
  }
  sandbox.WebGLRenderingContext = { prototype: webglProto };
  sandbox.WebGL2RenderingContext = { prototype: webgl2Proto };
  sandbox.CanvasRenderingContext2D = { prototype: canvas2dProto };
  sandbox.HTMLCanvasElement = { prototype: {} };
  sandbox.CustomEvent = class CustomEvent {
    constructor(type, init) { this.type = type; this.detail = init && init.detail; }
  };
  sandbox.dispatchEvent = (event) => listeners.filter((l) => l.type === event.type).forEach((l) => l.cb(event));
  sandbox.addEventListener = (type, cb) => listeners.push({ type, cb });

  return { ctx: vm.createContext(sandbox), webglProto, webgl2Proto, canvas2dProto };
}

function loadPageHookInto(ctx) {
  vm.runInContext(pageHookSource, ctx, { filename: "page-hook.js" });
}

function signalsIn(docEl) {
  const raw = docEl.getAttribute("data-sax-signals");
  return raw ? JSON.parse(raw) : [];
}

// ---------------------------------------------------------------------
// A. WebGL getSupportedExtensions()
// ---------------------------------------------------------------------

test("real page-hook.js: getSupportedExtensions() on WebGL1 is detected as webglExtensionEnumeration", () => {
  const docEl = createFakeDocumentElement();
  const { ctx, webglProto } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`WebGLRenderingContext.prototype.getSupportedExtensions()`, ctx);

  assert.ok(signalsIn(docEl).includes("fingerprint:webglExtensionEnumeration"));
});

test("real page-hook.js: getSupportedExtensions() on WebGL2 is also detected", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`WebGL2RenderingContext.prototype.getSupportedExtensions()`, ctx);

  assert.ok(signalsIn(docEl).includes("fingerprint:webglExtensionEnumeration"));
});

test("real page-hook.js: ordinary named getExtension() calls do NOT trigger webglExtensionEnumeration", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`WebGLRenderingContext.prototype.getExtension("OES_texture_float")`, ctx);

  assert.ok(!signalsIn(docEl).includes("fingerprint:webglExtensionEnumeration"));
});

test("real page-hook.js: getSupportedExtensions() does not affect the existing webglDebugInfo technique", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`WebGLRenderingContext.prototype.getSupportedExtensions()`, ctx);

  assert.ok(!signalsIn(docEl).includes("fingerprint:webglDebugInfo"));
});

// ---------------------------------------------------------------------
// B. Client Hints high-entropy detection
// ---------------------------------------------------------------------

test("real page-hook.js: requesting 2+ high-entropy hints is detected as clientHintsHighEntropy", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`navigator.userAgentData.getHighEntropyValues(["model", "architecture"])`, ctx);

  assert.ok(signalsIn(docEl).includes("fingerprint:clientHintsHighEntropy"));
});

test("real page-hook.js: requesting a single common hint alone is NOT detected", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`navigator.userAgentData.getHighEntropyValues(["platformVersion"])`, ctx);

  assert.ok(!signalsIn(docEl).includes("fingerprint:clientHintsHighEntropy"));
});

test("real page-hook.js: a malformed (non-array) argument does not throw and is not detected", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  assert.doesNotThrow(() => {
    vm.runInContext(`navigator.userAgentData.getHighEntropyValues("not-an-array")`, ctx);
    vm.runInContext(`navigator.userAgentData.getHighEntropyValues(undefined)`, ctx);
    vm.runInContext(`navigator.userAgentData.getHighEntropyValues(null)`, ctx);
  });
  assert.ok(!signalsIn(docEl).includes("fingerprint:clientHintsHighEntropy"));
});

test("real page-hook.js: no crash when navigator.userAgentData does not exist (non-Chromium browsers)", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl, { withUserAgentData: false });
  assert.doesNotThrow(() => loadPageHookInto(ctx));
});

// ---------------------------------------------------------------------
// C. Font Enumeration improvement
// ---------------------------------------------------------------------

function measureManyFonts(ctx, { fontCount, text }) {
  vm.runInContext(
    `
    (function () {
      const fakeCtx = Object.create(CanvasRenderingContext2D.prototype);
      for (let i = 0; i < ${fontCount}; i++) {
        fakeCtx.font = "14px TestFont" + i;
        fakeCtx.measureText(${JSON.stringify(text)});
      }
    })();
    `,
    ctx
  );
}

function measureManyWordsOneFont(ctx, words) {
  vm.runInContext(
    `
    (function () {
      const fakeCtx = Object.create(CanvasRenderingContext2D.prototype);
      fakeCtx.font = "16px Arial";
      const words = ${JSON.stringify(words)};
      for (const w of words) { fakeCtx.measureText(w); }
    })();
    `,
    ctx
  );
}

test("real page-hook.js: 20 distinct fonts + the same probe string IS detected (positive case, unchanged)", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  measureManyFonts(ctx, { fontCount: 20, text: "mmmmmmmmmmlli" });

  assert.ok(signalsIn(docEl).includes("fingerprint:fontEnumeration"));
});

test("real page-hook.js: exactly 15 distinct fonts (boundary) does NOT fire", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  measureManyFonts(ctx, { fontCount: 15, text: "mmmmmmmmmmlli" });

  assert.ok(!signalsIn(docEl).includes("fingerprint:fontEnumeration"));
});

test("real page-hook.js: 16 distinct fonts (boundary) fires", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  measureManyFonts(ctx, { fontCount: 16, text: "mmmmmmmmmmlli" });

  assert.ok(signalsIn(docEl).includes("fingerprint:fontEnumeration"));
});

test("real page-hook.js: THE FALSE-POSITIVE FIX — 30+ measureText calls in ONE font does NOT fire (would have under the old >15-call-count heuristic)", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  const words = "the quick brown fox jumps over the lazy dog while several other unrelated words continue filling this paragraph so the wrapping algorithm keeps measuring distinct substrings well past thirty total calls".split(" ");
  assert.ok(words.length > 15, "test setup sanity check: must exceed the OLD threshold to prove the fix");
  measureManyWordsOneFont(ctx, words);

  assert.ok(!signalsIn(docEl).includes("fingerprint:fontEnumeration"));
});

test("real page-hook.js: many distinct fonts BUT also many distinct strings does NOT fire", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(
    `
    (function () {
      const fakeCtx = Object.create(CanvasRenderingContext2D.prototype);
      for (let i = 0; i < 20; i++) {
        fakeCtx.font = "14px TestFont" + i;
        fakeCtx.measureText("distinct string number " + i);
      }
    })();
    `,
    ctx
  );

  assert.ok(!signalsIn(docEl).includes("fingerprint:fontEnumeration"));
});

test("real page-hook.js: font enumeration tracking is bounded (500 distinct fonts does not hang or grow unboundedly, and still fires once)", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  const start = Date.now();
  measureManyFonts(ctx, { fontCount: 500, text: "mmmmmmmmmmlli" });
  const elapsedMs = Date.now() - start;

  assert.ok(signalsIn(docEl).includes("fingerprint:fontEnumeration"));
  assert.ok(elapsedMs < 2000, `expected bounded tracking to stay fast, took ${elapsedMs}ms`);
  // Exactly one entry — report()'s own dedup must still hold regardless of call volume.
  assert.equal(signalsIn(docEl).filter((s) => s === "fingerprint:fontEnumeration").length, 1);
});

test("real page-hook.js: font/string values never appear anywhere in the stored signal data", () => {
  const docEl = createFakeDocumentElement();
  const { ctx } = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  measureManyFonts(ctx, { fontCount: 20, text: "mmmmmmmmmmlli" });

  const raw = docEl.getAttribute("data-sax-signals");
  assert.ok(!raw.includes("TestFont"));
  assert.ok(!raw.includes("mmmmmmmmmmlli"));
});

// ---------------------------------------------------------------------
// D. Tier classification (lib/analysis.js) — new techniques only
// ---------------------------------------------------------------------

function baseSignals(overrides = {}) {
  return {
    isHttps: true, hostname: "example.com", forms: [], thirdPartyScriptHosts: [],
    mixedContent: { activeCount: 0, passiveCount: 0, activeEvidence: [], passiveEvidence: [] },
    cookies: [],
    headers: { captured: true, present: {
      "content-security-policy": "default-src 'self'", "strict-transport-security": "max-age=63072000",
      "x-frame-options": "DENY", "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()",
    } },
    ...overrides,
  };
}
function bundle(fingerprintTechniques) {
  return {
    signals: baseSignals(),
    cookieBreakdown: { total: 0, secureCount: 0, sameSiteCount: 0, thirdPartyCount: 0, list: [] },
    fingerprintTechniques,
    permissionEvents: [],
  };
}

test("webglExtensionEnumeration alone classifies as weak tier, matching sibling entropy techniques", () => {
  const a = computeFullAnalysis(bundle(["webglExtensionEnumeration"]));
  assert.equal(a.fingerprintReport.tier, "weak");
  assert.equal(a.fingerprintReport.penalty, 6);
});

test("clientHintsHighEntropy alone classifies as weak tier, matching sibling entropy techniques", () => {
  const a = computeFullAnalysis(bundle(["clientHintsHighEntropy"]));
  assert.equal(a.fingerprintReport.tier, "weak");
  assert.equal(a.fingerprintReport.penalty, 6);
});

test("new techniques combine with existing ones using the SAME unchanged combination math", () => {
  const a = computeFullAnalysis(bundle(["webglExtensionEnumeration", "clientHintsHighEntropy"]));
  assert.equal(a.fingerprintReport.tier, "moderate");
  assert.equal(a.fingerprintReport.penalty, 18); // identical to any other 2-entropy-technique combination
});

test("existing technique tiers/weights are completely unchanged by this batch", () => {
  const timezoneOnly = computeFullAnalysis(bundle(["timezone"]));
  const canvasOnly = computeFullAnalysis(bundle(["canvasFingerprint"]));
  const threeOld = computeFullAnalysis(bundle(["canvasFingerprint", "webglDebugInfo", "audioFingerprint"]));

  assert.equal(timezoneOnly.fingerprintReport.penalty, 2);
  assert.equal(canvasOnly.fingerprintReport.penalty, 6);
  assert.equal(threeOld.fingerprintReport.penalty, 30);
});

test("fingerprinting from the new techniques still never affects Security or Phishing Risk", () => {
  const a = computeFullAnalysis(bundle(["webglExtensionEnumeration", "clientHintsHighEntropy", "fontEnumeration"]));
  assert.equal(a.dashboard.securityScore, 100);
  assert.equal(a.dashboard.phishingRiskScore, 0);
});

// ---------------------------------------------------------------------
// E. Regression — existing behavior from earlier batches is untouched
// ---------------------------------------------------------------------

test("regression: clean baseline site is unaffected by any Phase 2A change", () => {
  const a = computeFullAnalysis(bundle([]));
  assert.equal(a.dashboard.securityScore, 100);
  assert.equal(a.dashboard.privacyScore, 100);
  assert.equal(a.dashboard.phishingRiskScore, 0);
  assert.equal(a.dashboard.trustScore, 100);
});
