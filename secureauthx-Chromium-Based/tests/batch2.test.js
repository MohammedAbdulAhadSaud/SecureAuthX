/**
 * SecureAuthX — Batch 2 test suite
 *
 * Pure unit tests, no DOM / no browser APIs required — computeSiteScore
 * and computeFullAnalysis are plain functions over a plain "signals"
 * object, so they can be exercised directly with node:test.
 *
 * Run with:  node --test tests/batch2.test.js
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  computeSiteScore,
  getRegistrableDomain,
  isSameRegistrableDomain,
  isKnownIdentityProvider,
  classifyHttpsFormDestination,
  looksLikeTyposquat,
} from "../lib/scoring.js";
import { computeFullAnalysis } from "../lib/analysis.js";

// ---------------------------------------------------------------------
// Test helpers
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

function form({ https = true, sameOrigin = false, hostname = "" } = {}) {
  return { actionIsHttps: https, actionSameOrigin: sameOrigin, actionHostname: hostname };
}

function fullBundle(signalsOverrides = {}) {
  return {
    signals: baseSignals(signalsOverrides),
    cookieBreakdown: { total: 0, secureCount: 0, sameSiteCount: 0, thirdPartyCount: 0, list: [] },
    fingerprintTechniques: [],
    permissionEvents: [],
  };
}

// ---------------------------------------------------------------------
// A. Registrable-domain helper
// ---------------------------------------------------------------------

test("registrable domain: simple two-label domain", () => {
  assert.equal(getRegistrableDomain("example.com"), "example.com");
  assert.equal(getRegistrableDomain("www.example.com"), "example.com");
  assert.equal(getRegistrableDomain("login.accounts.example.com"), "example.com");
});

test("registrable domain: known multi-label public suffix", () => {
  assert.equal(getRegistrableDomain("example.co.uk"), "example.co.uk");
  assert.equal(getRegistrableDomain("www.example.co.uk"), "example.co.uk");
  assert.equal(getRegistrableDomain("shop.example.com.au"), "example.com.au");
});

test("registrable domain: unrecognized multi-label suffix falls back to last two labels (documented limitation)", () => {
  // Not a full PSL — a suffix we don't recognize (e.g. a hypothetical
  // "co.zz") falls back to last-two-labels, which is the safe direction
  // to err in (it will NOT falsely treat two different sites as related).
  assert.equal(getRegistrableDomain("example.co.zz"), "co.zz");
});

test("isSameRegistrableDomain: subdomains of the same site match", () => {
  assert.equal(isSameRegistrableDomain("www.example.com", "login.example.com"), true);
  assert.equal(isSameRegistrableDomain("login.example.com", "accounts.example.com"), true);
});

test("isSameRegistrableDomain: unrelated domains do not match", () => {
  assert.equal(isSameRegistrableDomain("example.com", "example.net"), false);
  assert.equal(isSameRegistrableDomain("example.com", "evilexample.com"), false);
});

test("isSameRegistrableDomain: co.uk sites are not confused with each other", () => {
  assert.equal(isSameRegistrableDomain("example.co.uk", "attacker.co.uk"), false);
  assert.equal(isSameRegistrableDomain("www.example.co.uk", "shop.example.co.uk"), true);
});

// ---------------------------------------------------------------------
// B. Identity provider allowlist (domain-boundary aware)
// ---------------------------------------------------------------------

test("identity provider: exact known hosts match", () => {
  assert.equal(isKnownIdentityProvider("accounts.google.com"), true);
  assert.equal(isKnownIdentityProvider("appleid.apple.com"), true);
  assert.equal(isKnownIdentityProvider("login.microsoftonline.com"), true);
});

test("identity provider: wildcard tenant subdomains match", () => {
  assert.equal(isKnownIdentityProvider("acme-corp.okta.com"), true);
  assert.equal(isKnownIdentityProvider("tenant.auth0.com"), true);
  assert.equal(isKnownIdentityProvider("okta.com"), true);
});

test("identity provider: lookalike apex domains do NOT match (no substring matching)", () => {
  assert.equal(isKnownIdentityProvider("evilokta.com"), false);
  assert.equal(isKnownIdentityProvider("okta.com.evil.tk"), false);
  assert.equal(isKnownIdentityProvider("notauth0.com"), false);
  assert.equal(isKnownIdentityProvider("myaccounts.google.com.attacker.net"), false);
});

// ---------------------------------------------------------------------
// C. Form destination classification
// ---------------------------------------------------------------------

test("classifyHttpsFormDestination: same-origin", () => {
  assert.equal(classifyHttpsFormDestination(form({ sameOrigin: true, hostname: "example.com" }), "example.com"), "same-origin");
});

test("classifyHttpsFormDestination: same-site (subdomain)", () => {
  assert.equal(classifyHttpsFormDestination(form({ hostname: "login.example.com" }), "www.example.com"), "same-site");
  assert.equal(classifyHttpsFormDestination(form({ hostname: "accounts.example.com" }), "login.example.com"), "same-site");
});

test("classifyHttpsFormDestination: known identity provider", () => {
  assert.equal(classifyHttpsFormDestination(form({ hostname: "accounts.google.com" }), "example.com"), "known-identity-provider");
  assert.equal(classifyHttpsFormDestination(form({ hostname: "login.microsoftonline.com" }), "example.com"), "known-identity-provider");
  assert.equal(classifyHttpsFormDestination(form({ hostname: "tenant.okta.com" }), "example.com"), "known-identity-provider");
  assert.equal(classifyHttpsFormDestination(form({ hostname: "tenant.auth0.com" }), "example.com"), "known-identity-provider");
});

test("classifyHttpsFormDestination: lookalike identity-provider domain is unrelated, not trusted", () => {
  assert.equal(classifyHttpsFormDestination(form({ hostname: "evilokta.com" }), "example.com"), "unrelated-https");
});

test("classifyHttpsFormDestination: unrelated https destination", () => {
  assert.equal(classifyHttpsFormDestination(form({ hostname: "totally-different-site.com" }), "example.com"), "unrelated-https");
});

// ---------------------------------------------------------------------
// D. computeSiteScore: form destination categories stay OUT of Security
// ---------------------------------------------------------------------

test("Security score: same-origin password form has no penalty", () => {
  const report = computeSiteScore(baseSignals({ forms: [form({ sameOrigin: true, hostname: "example.com" })] }));
  assert.equal(report.flags.formDestinationCategory, "same-origin");
  assert.equal(report.flags.crossOriginForm, false);
  assert.equal(report.score, 100);
});

test("Security score: same-site (subdomain) form has no penalty", () => {
  const report = computeSiteScore(baseSignals({
    hostname: "www.example.com",
    forms: [form({ hostname: "login.example.com" })],
  }));
  assert.equal(report.flags.formDestinationCategory, "same-site");
  assert.equal(report.flags.crossOriginForm, false);
  assert.equal(report.score, 100);
});

test("Security score: known identity provider form has no penalty", () => {
  const report = computeSiteScore(baseSignals({
    hostname: "example.com",
    forms: [form({ hostname: "accounts.google.com" })],
  }));
  assert.equal(report.flags.formDestinationCategory, "known-identity-provider");
  assert.equal(report.flags.crossOriginForm, false);
  assert.equal(report.score, 100);
});

test("Security score: unrelated https destination has NO Security penalty (moved to Phishing/Identity)", () => {
  const report = computeSiteScore(baseSignals({
    hostname: "example.com",
    forms: [form({ hostname: "totally-different-site.com" })],
  }));
  assert.equal(report.flags.formDestinationCategory, "unrelated-https");
  assert.equal(report.flags.crossOriginForm, true);
  // Batch 1 used to subtract 15 here; Batch 2 keeps Security untouched and
  // reflects this in Phishing Risk / Trust instead (see section E below).
  assert.equal(report.score, 100);
});

test("Security score: HTTP destination still penalizes Security (transport issue, unchanged)", () => {
  const report = computeSiteScore(baseSignals({
    hostname: "example.com",
    forms: [form({ https: false, hostname: "example.com" })],
  }));
  assert.equal(report.flags.insecureLoginForm, true);
  assert.equal(report.flags.formDestinationCategory, "http");
  assert.equal(report.score, 70); // 100 - 30, same as Batch 1
});

// ---------------------------------------------------------------------
// E. computeFullAnalysis: Phishing Risk / Trust, per Batch 2 spec items #9-10
// ---------------------------------------------------------------------

test("Phishing: same-origin password form -> zero phishing risk", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({ forms: [form({ sameOrigin: true, hostname: "example.com" })] }));
  assert.equal(dashboard.phishingRiskScore, 0);
});

test("Phishing: www.example.com -> login.example.com is not penalized", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "www.example.com",
    forms: [form({ hostname: "login.example.com" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 0);
});

test("Phishing: login.example.com -> accounts.example.com is not penalized", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "login.example.com",
    forms: [form({ hostname: "accounts.example.com" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 0);
});

test("Phishing: example.com -> accounts.google.com is not penalized", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "accounts.google.com" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 0);
});

test("Phishing: example.com -> login.microsoftonline.com is not penalized", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "login.microsoftonline.com" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 0);
});

test("Phishing: example.com -> tenant.okta.com is not penalized", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "tenant.okta.com" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 0);
});

test("Phishing: example.com -> tenant.auth0.com is not penalized", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "tenant.auth0.com" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 0);
});

test("Phishing: example.com -> evilokta.com IS flagged (not a real provider match)", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "evilokta.com" })],
  }));
  assert.ok(dashboard.phishingRiskScore > 0, "evilokta.com should not be trusted as Okta");
});

test("Phishing: legitimate-looking unrelated HTTPS destination gets a MODERATE (not extreme) warning", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "some-other-real-site.com" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 30);
  assert.ok(dashboard.phishingRiskScore < 60, "unrelated-https alone should stay moderate, not extreme");
});

test("Phishing: suspicious unrelated HTTPS credential destination (same score path as above; severity comes from combination, see lookalike tests)", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "totally-unrelated-domain.info" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 30);
});

test("Phishing: HTTP credential destination is NOT double-counted as phishing", () => {
  const { dashboard, securityReport } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ https: false, hostname: "example.com" })],
  }));
  assert.equal(securityReport.flags.insecureLoginForm, true);
  // Security already reflects this (-30). Phishing Risk must stay 0 —
  // otherwise the same HTTP issue is counted in both places.
  assert.equal(dashboard.phishingRiskScore, 0);
});

test("Phishing: IP hostname alone (no login form) is low/moderate, not extreme", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({ hostname: "203.0.113.7", forms: [] }));
  assert.equal(dashboard.phishingRiskScore, 20);
});

test("Phishing: suspicious TLD alone (no login form) is low", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({ hostname: "freestuff.top", forms: [] }));
  assert.equal(dashboard.phishingRiskScore, 5);
});

test("Phishing: punycode alone (no other suspicious evidence) is low/informational", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({ hostname: "xn--exmple-cua.com", forms: [] }));
  assert.equal(dashboard.phishingRiskScore, 5);
});

test("Phishing: strong lookalike WITHOUT credential context is moderate, not extreme", () => {
  const { dashboard, securityReport } = computeFullAnalysis(fullBundle({ hostname: "paypal-secure.xyz", forms: [] }));
  assert.equal(securityReport.flags.spoofDomain, true);
  // suspiciousTld also fires for .xyz here, so include its low contribution.
  assert.equal(dashboard.phishingRiskScore, 30); // 25 (moderate lookalike alone) + 5 (suspicious tld)
  assert.ok(dashboard.phishingRiskScore < 60, "a bare lookalike with no form on the page should not be extreme");
});

test("Phishing: strong lookalike + password form (same-origin) escalates above the no-context case", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "paypal-secure.com",
    forms: [form({ sameOrigin: true, hostname: "paypal-secure.com" })],
  }));
  assert.equal(dashboard.phishingRiskScore, 45);
});

test("Phishing: strong lookalike + suspicious credential destination is substantially stronger still", () => {
  const noForm = computeFullAnalysis(fullBundle({ hostname: "paypal-secure.com", forms: [] })).dashboard.phishingRiskScore;
  const withFormOnly = computeFullAnalysis(fullBundle({
    hostname: "paypal-secure.com",
    forms: [form({ sameOrigin: true, hostname: "paypal-secure.com" })],
  })).dashboard.phishingRiskScore;
  const withSuspiciousDestination = computeFullAnalysis(fullBundle({
    hostname: "paypal-secure.com",
    forms: [form({ hostname: "unrelated-collector.info" })],
  })).dashboard.phishingRiskScore;

  assert.ok(withFormOnly > noForm, "adding a password form should raise risk over the bare-lookalike case");
  assert.ok(
    withSuspiciousDestination > withFormOnly,
    "lookalike + password form + suspicious destination should score higher than lookalike + password form alone"
  );
  assert.equal(withSuspiciousDestination, 100); // 70 (escalated spoof) + 30 (unrelated destination), clamped
});

// ---------------------------------------------------------------------
// F. Trust cap: only genuinely suspicious destinations get the severe cap
// ---------------------------------------------------------------------

test("Trust cap: same-site / known-provider destinations do NOT trigger the old severe cap", () => {
  const sameSite = computeFullAnalysis(fullBundle({
    hostname: "www.example.com",
    forms: [form({ hostname: "login.example.com" })],
  })).dashboard.trustScore;
  const provider = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "accounts.google.com" })],
  })).dashboard.trustScore;

  assert.ok(sameSite > 35, `expected no severe cap for same-site, got trust=${sameSite}`);
  assert.ok(provider > 35, `expected no severe cap for known provider, got trust=${provider}`);
});

test("Trust cap: unrelated-https destination still receives a meaningful cap", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    hostname: "example.com",
    forms: [form({ hostname: "unrelated-collector.info" })],
  }));
  assert.ok(dashboard.trustScore <= 35, `expected the unrelated-destination cap to apply, got trust=${dashboard.trustScore}`);
});

// ---------------------------------------------------------------------
// G. Lookalike/brand matching: domain-boundary-aware, fewer false positives
// ---------------------------------------------------------------------

test("lookalike: cross-label concatenation is no longer a false positive", () => {
  // Under the old whole-hostname (dots stripped) matching, "net" + "flix-
  // something" would concatenate into "...netflixsomething..." and
  // falsely match the "netflix" brand token — even though "netflix" only
  // exists because two unrelated, independently-controlled DNS labels
  // happen to sit next to each other. Checking each label independently
  // (this label is "flix-something", stripped to "flixsomething" — no
  // "netflix" in it) removes that false-positive source.
  assert.equal(looksLikeTyposquat("net.flix-something.info"), null);
});

test("lookalike: brand-as-a-label is still caught regardless of position (subdomain impersonation)", () => {
  const hit = looksLikeTyposquat("paypal.attacker-domain.com");
  assert.ok(hit && hit.brand === "paypal", "a brand name used as its own subdomain label should still be flagged");
});

test("lookalike: known false-positive words still excluded when NOT the first label (bug fix)", () => {
  // Before Batch 2, the exception lists only ever checked the first DNS
  // label, so "purchase.com" was excluded but "www.purchase.com" was not
  // (the whole-hostname substring check would still fire). Per-label
  // exception checking fixes this.
  assert.equal(looksLikeTyposquat("www.purchase.com"), null);
  assert.equal(looksLikeTyposquat("shop.purchase.com"), null);
  assert.equal(looksLikeTyposquat("purchase.com"), null);
});

test("lookalike: existing exception list entries still pass clean (regression)", () => {
  assert.equal(looksLikeTyposquat("grapple.com"), null);
  assert.equal(looksLikeTyposquat("chasm.com"), null);
  assert.equal(looksLikeTyposquat("steamship.com"), null);
  assert.equal(looksLikeTyposquat("outlookindia.com"), null);
});

test("lookalike: real brand domains are never flagged (regression)", () => {
  assert.equal(looksLikeTyposquat("paypal.com"), null);
  assert.equal(looksLikeTyposquat("www.paypal.com"), null);
  assert.equal(looksLikeTyposquat("accounts.google.com"), null);
});

test("lookalike: obvious typosquat substitutions are still caught (regression)", () => {
  assert.ok(looksLikeTyposquat("faceb00k.com"));
  assert.ok(looksLikeTyposquat("paypal-login-secure.xyz"));
  assert.ok(looksLikeTyposquat("arnazon.com")); // rn -> m visual substitution
});

// ---------------------------------------------------------------------
// H. Existing Batch 1 regression cases (must be unaffected by Batch 2)
// ---------------------------------------------------------------------

test("regression: known-good baseline site scores identically to the Batch 1 manual test", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({}));
  assert.equal(dashboard.securityScore, 100); // clean baseline in this harness (no header penalties injected)
  assert.equal(dashboard.phishingRiskScore, 0);
  assert.equal(dashboard.trustScore, 100);
});

test("regression: plain-HTTP page (http.badssl.com-style) is still capped at 40 Trust / High Risk", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({ isHttps: false, hostname: "http.badssl.com", headers: { captured: false } }));
  assert.equal(dashboard.trustScore, 40);
  assert.equal(dashboard.level, "High Risk");
});

test("regression: SameSite=None without Secure still caps Trust at 50", () => {
  const { dashboard } = computeFullAnalysis(fullBundle({
    cookies: [{ secure: false, httpOnly: true, sameSite: "no_restriction" }],
  }));
  assert.equal(dashboard.trustScore, 50);
});
