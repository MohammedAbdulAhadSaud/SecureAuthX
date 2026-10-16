/**
 * SecureAuthX — Batch 3 test suite (fingerprinting evidence hierarchy)
 *
 * Pure unit tests over computeFullAnalysis — no DOM/browser APIs needed,
 * since the tiering/scoring logic itself lives entirely in lib/analysis.js
 * as plain functions over a "fingerprintTechniques" string array. The
 * page-hook.js DOM-dependent detection logic (canvas visibility checks,
 * WebGL argument inspection, OfflineAudioContext render-then-read
 * tracking) is NOT covered here — it requires a real browser environment
 * and is covered by the manual Chrome test plan instead (see Batch 3
 * audit section J / the implementation report).
 *
 * Run with:  node --test tests/batch3.test.js
 */

import test from "node:test";
import assert from "node:assert/strict";

import { computeFullAnalysis } from "../lib/analysis.js";

// ---------------------------------------------------------------------
// Test helpers (mirrors tests/batch2.test.js's fullBundle pattern)
// ---------------------------------------------------------------------

function baseSignals(overrides = {}) {
  return {
    isHttps: true,
    hostname: "example.com",
    forms: [],
    thirdPartyScriptHosts: [],
    mixedContent: { activeCount: 0, passiveCount: 0, activeEvidence: [], passiveEvidence: [] },
    cookies: [],
    headers: { captured: true, present: {
      "content-security-policy": "default-src 'self'",
      "strict-transport-security": "max-age=63072000",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "permissions-policy": "geolocation=()",
    } },
    ...overrides,
  };
}

function fullBundle({ fingerprintTechniques = [], signalsOverrides = {} } = {}) {
  return {
    signals: baseSignals(signalsOverrides),
    cookieBreakdown: { total: 0, secureCount: 0, sameSiteCount: 0, thirdPartyCount: 0, list: [] },
    fingerprintTechniques,
    permissionEvents: [],
  };
}

// ---------------------------------------------------------------------
// A. Individual signal tiers
// ---------------------------------------------------------------------

test("no fingerprint techniques -> tier 'none', no Privacy penalty", () => {
  const analysis = computeFullAnalysis(fullBundle());
  assert.equal(analysis.fingerprintReport.tier, "none");
  assert.equal(analysis.fingerprintReport.penalty, 0);
  assert.equal(analysis.dashboard.privacyScore, 100);
});

test("timezone alone -> informational tier, minimal penalty", () => {
  const analysis = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["timezone"] }));
  assert.equal(analysis.fingerprintReport.tier, "informational");
  assert.equal(analysis.fingerprintReport.penalty, 2);
  assert.equal(analysis.dashboard.privacyScore, 98);
});

test("locale alone -> informational tier, minimal penalty", () => {
  const analysis = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["locale"] }));
  assert.equal(analysis.fingerprintReport.tier, "informational");
  assert.equal(analysis.fingerprintReport.penalty, 2);
});

test("timezone + locale together -> still informational, capped low", () => {
  const analysis = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["timezone", "locale"] }));
  assert.equal(analysis.fingerprintReport.tier, "informational");
  assert.equal(analysis.fingerprintReport.penalty, 4); // capped, not 2+2 uncapped growth beyond this
  assert.equal(analysis.dashboard.privacyScore, 96);
});

test("canvasFingerprint alone -> weak tier", () => {
  const analysis = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["canvasFingerprint"] }));
  assert.equal(analysis.fingerprintReport.tier, "weak");
  assert.equal(analysis.fingerprintReport.penalty, 6);
  assert.equal(analysis.dashboard.privacyScore, 94);
});

test("webglDebugInfo alone -> weak tier", () => {
  const analysis = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["webglDebugInfo"] }));
  assert.equal(analysis.fingerprintReport.tier, "weak");
  assert.equal(analysis.fingerprintReport.penalty, 6);
});

test("audioFingerprint alone -> weak tier", () => {
  const analysis = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["audioFingerprint"] }));
  assert.equal(analysis.fingerprintReport.tier, "weak");
  assert.equal(analysis.fingerprintReport.penalty, 6);
});

test("fontEnumeration alone -> weak tier", () => {
  const analysis = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["fontEnumeration"] }));
  assert.equal(analysis.fingerprintReport.tier, "weak");
  assert.equal(analysis.fingerprintReport.penalty, 6);
});

// ---------------------------------------------------------------------
// B. Combination evidence hierarchy
// ---------------------------------------------------------------------

test("two entropy-producing techniques together -> moderate tier, more than double one alone", () => {
  const analysis = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["canvasFingerprint", "webglDebugInfo"] }));
  assert.equal(analysis.fingerprintReport.tier, "moderate");
  assert.equal(analysis.fingerprintReport.penalty, 18);
  assert.ok(analysis.fingerprintReport.penalty > 6 * 2, "combination should be scored above a flat per-technique sum");
  assert.equal(analysis.dashboard.privacyScore, 82);
});

test("three entropy-producing techniques together -> strong tier, at the cap", () => {
  const analysis = computeFullAnalysis(fullBundle({
    fingerprintTechniques: ["canvasFingerprint", "webglDebugInfo", "audioFingerprint"],
  }));
  assert.equal(analysis.fingerprintReport.tier, "strong");
  assert.equal(analysis.fingerprintReport.penalty, 30);
  assert.equal(analysis.dashboard.privacyScore, 70);
});

test("all six techniques together -> still capped at 30, not higher", () => {
  const analysis = computeFullAnalysis(fullBundle({
    fingerprintTechniques: ["canvasFingerprint", "webglDebugInfo", "audioFingerprint", "fontEnumeration", "timezone", "locale"],
  }));
  assert.equal(analysis.fingerprintReport.tier, "strong");
  assert.equal(analysis.fingerprintReport.penalty, 30);
  assert.equal(analysis.dashboard.privacyScore, 70);
});

test("evidence hierarchy is monotonic: none < informational < weak < moderate < strong", () => {
  const none = computeFullAnalysis(fullBundle({ fingerprintTechniques: [] })).fingerprintReport.penalty;
  const informational = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["timezone"] })).fingerprintReport.penalty;
  const weak = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["canvasFingerprint"] })).fingerprintReport.penalty;
  const moderate = computeFullAnalysis(fullBundle({ fingerprintTechniques: ["canvasFingerprint", "webglDebugInfo"] })).fingerprintReport.penalty;
  const strong = computeFullAnalysis(fullBundle({
    fingerprintTechniques: ["canvasFingerprint", "webglDebugInfo", "audioFingerprint"],
  })).fingerprintReport.penalty;

  assert.ok(none < informational);
  assert.ok(informational < weak);
  assert.ok(weak < moderate);
  assert.ok(moderate < strong);
});

// ---------------------------------------------------------------------
// C. Category separation: fingerprinting must never touch Security or
//    Phishing Risk, and must reach Trust only through Privacy's existing
//    30% weight.
// ---------------------------------------------------------------------

test("fingerprinting never affects Security score, regardless of tier", () => {
  const clean = computeFullAnalysis(fullBundle({ fingerprintTechniques: [] })).dashboard.securityScore;
  const strong = computeFullAnalysis(fullBundle({
    fingerprintTechniques: ["canvasFingerprint", "webglDebugInfo", "audioFingerprint", "fontEnumeration"],
  })).dashboard.securityScore;
  assert.equal(clean, 100);
  assert.equal(strong, 100);
});

test("fingerprinting never affects Phishing Risk, regardless of tier", () => {
  const clean = computeFullAnalysis(fullBundle({ fingerprintTechniques: [] })).dashboard.phishingRiskScore;
  const strong = computeFullAnalysis(fullBundle({
    fingerprintTechniques: ["canvasFingerprint", "webglDebugInfo", "audioFingerprint", "fontEnumeration"],
  })).dashboard.phishingRiskScore;
  assert.equal(clean, 0);
  assert.equal(strong, 0);
});

test("fingerprinting reaches Trust only via Privacy's existing 30% weight", () => {
  // Security=100, phishingSafetyForTrust=100 (both untouched by fingerprinting
  // per the tests above), Privacy=70 at the "strong" tier (penalty 30).
  // Trust = 100*0.5 + 70*0.3 + 100*0.2 = 50 + 21 + 20 = 91.
  const analysis = computeFullAnalysis(fullBundle({
    fingerprintTechniques: ["canvasFingerprint", "webglDebugInfo", "audioFingerprint"],
  }));
  assert.equal(analysis.dashboard.privacyScore, 70);
  assert.equal(analysis.dashboard.trustScore, 91);
});

// ---------------------------------------------------------------------
// D. Regression: Batch 1/2 behavior must be unaffected by Batch 3
// ---------------------------------------------------------------------

test("regression: clean baseline site unaffected by Batch 3 changes", () => {
  const analysis = computeFullAnalysis(fullBundle());
  assert.equal(analysis.dashboard.securityScore, 100);
  assert.equal(analysis.dashboard.privacyScore, 100);
  assert.equal(analysis.dashboard.phishingRiskScore, 0);
  assert.equal(analysis.dashboard.trustScore, 100);
});

test("regression: plain-HTTP page Trust cap (Batch 1) is unaffected by fingerprinting changes", () => {
  const analysis = computeFullAnalysis(fullBundle({
    signalsOverrides: { isHttps: false, hostname: "http.badssl.com", headers: { captured: false } },
  }));
  assert.equal(analysis.dashboard.trustScore, 40);
  assert.equal(analysis.dashboard.level, "High Risk");
});
