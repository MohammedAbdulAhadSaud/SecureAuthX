/**
 * SecureAuthX — analysis.js
 *
 * Combines security score (scoring.js), tracker matches (trackers.js),
 * cookie breakdown, permission/fingerprinting signals from the content
 * script, and produces the Dashboard's four headline numbers:
 * Security Score, Privacy Score, Phishing Risk, Overall Trust Score.
 *
 * IMPORTANT HONESTY NOTE (see README "AI Assistant"): the "explanation"
 * text generated here is template-based local logic, NOT a live call to
 * an LLM. It's labeled "Explanation" in the UI rather than "AI Summary"
 * for that reason. Wiring a real LLM call (e.g. the Anthropic API) to
 * generate this text instead is a documented, straightforward future
 * step — see README — but shipping a fake "AI" label on deterministic
 * template text would be misleading, so this build doesn't do that.
 */

import { computeSiteScore } from "./scoring.js";
import { matchTrackers } from "./trackers.js";

const TRACKER_CATEGORY_WEIGHT = {
  Advertising: 4,
  "Session Recording": 5,
  Analytics: 2,
  "Tag Management": 1,
  "Support/Chat (tracking-capable)": 2,
  "Error Monitoring (not user-tracking)": 0,
};

// -----------------------------------------------------------------------
// Batch 3 — fingerprinting evidence hierarchy.
//
// Not every reported technique proves the same thing. Individual signals
// are tiered by how much they actually indicate deliberate fingerprint
// collection, rather than being counted flatly:
//
//   "informational" — timezone/locale detection. This is the standard,
//     textbook way ordinary sites localize dates, numbers, and UI text;
//     the overwhelming majority of real-world calls are entirely benign.
//     Carries almost no weight, even in combination with each other.
//
//   "weak" (entropy-producing) — canvas/WebGL/audio/font-enumeration
//     signals. As of Batch 3, page-hook.js only reports these for the
//     SPECIFIC fingerprint-shaped usage pattern (a hidden/offscreen
//     canvas, the WEBGL_debug_renderer_info extension, an OfflineAudio-
//     Context render-then-read, or excessive measureText calls) rather
//     than any ordinary API touch — see page-hook.js comments for why
//     each one was narrowed. Even so, any ONE of these alone can still
//     have an innocent explanation (documented per-technique in
//     page-hook.js), so a single one is scored as "weak" evidence.
//
// It's specifically the CO-OCCURRENCE of multiple entropy-producing
// techniques that starts to resemble a deliberate multi-vector fingerprint
// collector (the pattern real fingerprinting libraries use) — so that
// combination is scored well above the linear sum of the parts, rather
// than just adding flat per-technique penalties together as Batch 1/2
// did.
// -----------------------------------------------------------------------
const FINGERPRINT_TECHNIQUE_TIER = {
  timezone: "informational",
  locale: "informational",
  canvasFingerprint: "weak",
  webglDebugInfo: "weak",
  audioFingerprint: "weak",
  fontEnumeration: "weak",
  // Batch 4 Phase 2A additions — classified "weak", matching their
  // sibling entropy-producing techniques above. This does NOT change the
  // tier or weight of any pre-existing technique; it only classifies the
  // two brand-new ones introduced in this batch.
  webglExtensionEnumeration: "weak",
  clientHintsHighEntropy: "weak",
};

// Entropy-technique count -> penalty. 1-2 are scored per-combination
// (not simply added technique-by-technique); 3 or more jumps to the cap,
// since at that point there are very few honest explanations left for a
// single page.
const ENTROPY_COMBINATION_PENALTY = { 0: 0, 1: 6, 2: 18 };
const MAX_FINGERPRINT_PENALTY = 30;

function classifyFingerprintEvidence(fingerprintTechniques) {
  const techniques = Array.isArray(fingerprintTechniques) ? fingerprintTechniques : [];
  const entropyTechniques = techniques.filter((t) => FINGERPRINT_TECHNIQUE_TIER[t] === "weak");
  const informationalTechniques = techniques.filter((t) => FINGERPRINT_TECHNIQUE_TIER[t] === "informational");
  const entropyCount = entropyTechniques.length;

  const entropyPenalty = entropyCount >= 3 ? MAX_FINGERPRINT_PENALTY : (ENTROPY_COMBINATION_PENALTY[entropyCount] || 0);
  // Informational signals contribute a very small amount each, capped low
  // — even ALL of them together should never look like real evidence on
  // their own.
  const informationalPenalty = Math.min(4, informationalTechniques.length * 2);
  const penalty = Math.min(MAX_FINGERPRINT_PENALTY, entropyPenalty + informationalPenalty);

  let tier = "none";
  if (entropyCount >= 3) tier = "strong";
  else if (entropyCount === 2) tier = "moderate";
  else if (entropyCount === 1) tier = "weak";
  else if (informationalTechniques.length > 0) tier = "informational";

  return { tier, penalty, entropyTechniques, informationalTechniques, allTechniques: techniques };
}

function computePrivacyScore({ trackers, cookieBreakdown, fingerprintTechniques, permissionEvents }) {
  let score = 100;
  const reasons = [];

  if (trackers.length > 0) {
    const penalty = trackers.reduce((sum, t) => sum + (TRACKER_CATEGORY_WEIGHT[t.category] ?? 2), 0);
    score -= Math.min(40, penalty);
    reasons.push({ severity: trackers.length >= 5 ? "high" : "medium", text: `${trackers.length} known tracker(s) detected: ${trackers.map((t) => t.name).join(", ")}.` });
  }

  if (cookieBreakdown.thirdPartyCount > 0) {
    score -= Math.min(20, cookieBreakdown.thirdPartyCount * 3);
    reasons.push({ severity: "medium", text: `${cookieBreakdown.thirdPartyCount} third-party service(s) have cookies associated with this browsing profile.` });
  }

  const fingerprintReport = classifyFingerprintEvidence(fingerprintTechniques);
  if (fingerprintReport.allTechniques.length > 0) {
    score -= fingerprintReport.penalty;
    const severity = fingerprintReport.tier === "strong" ? "high" : fingerprintReport.tier === "moderate" ? "medium" : "low";
    reasons.push({
      severity,
      text: `Fingerprinting-related API usage detected (${fingerprintReport.tier} evidence): ${fingerprintReport.allTechniques.join(", ")}.`,
    });
  }

  const activePermissions = permissionEvents.filter((p) => p.status === "active");
  if (activePermissions.length > 0) {
    score -= activePermissions.length * 10;
    reasons.push({ severity: "high", text: `Page actively invoked sensitive permission(s): ${activePermissions.map((p) => p.api).join(", ")}.` });
  }

  score = Math.max(0, Math.min(100, score));
  return { score, reasons, fingerprintReport };
}

function riskColor(score) {
  if (score >= 80) return { level: "Safe", color: "green" };
  if (score >= 60) return { level: "Moderate", color: "yellow" };
  if (score >= 40) return { level: "High Risk", color: "orange" };
  return { level: "Critical", color: "red" };
}

/**
 * "Safe Browsing Assistant" — turns the raw scores into the plain-language,
 * bulleted format ordinary users actually understand, instead of a bare
 * number. Still fully rule-based/local (see honesty note above) — the
 * headline/advice are picked from the same color tier already used for the
 * trust badge, and bullets are built directly from the structured flags in
 * scoring.js (never from re-parsing generated text). Icon/visual choices for
 * this tier are a UI concern and are left to the caller (popup.js), which
 * already receives dashboard.color to key off of.
 */
const SUMMARY_BY_COLOR = {
  green: {
    headline: "This website appears safe.",
    advice: "You can continue browsing normally.",
  },
  yellow: {
    headline: "This website appears mostly safe.",
    advice: "You can continue browsing normally, but keep the items below in mind.",
  },
  orange: {
    headline: "This website may not be safe.",
    advice: "Be cautious — avoid entering passwords or payment details until you're sure.",
  },
  red: {
    headline: "This website may not be safe.",
    advice: "Avoid entering passwords or payment details on this page.",
  },
};

function generateSafetySummary({ securityReport, privacyReport, trackers, dashboard, capReason }) {
  const tier = SUMMARY_BY_COLOR[dashboard.color] || SUMMARY_BY_COLOR.yellow;
  const flags = securityReport.flags;
  const bullets = [];

  if (capReason) {
    bullets.push({ ok: false, text: `Critical: ${capReason}.` });
  }

  bullets.push({
    ok: !flags.httpsMissing,
    text: flags.httpsMissing ? "Connection is NOT encrypted (plain HTTP)." : "Connection is encrypted (HTTPS).",
  });

  if (flags.insecureLoginForm) {
    bullets.push({ ok: false, text: "Login form sends data insecurely." });
  }
  // Batch 2: form-destination bullets reflect the classified category —
  // only the genuinely unrelated case is shown as a warning; same-site
  // (subdomain) and known-identity-provider destinations are shown as
  // informational/OK, keeping the signal visible without alarming the
  // user over an ordinary SSO or multi-subdomain pattern.
  if (flags.formDestinationCategory === "unrelated-https") {
    bullets.push({ ok: false, text: "A password form submits credentials to an unrelated external domain." });
  } else if (flags.formDestinationCategory === "same-site") {
    bullets.push({ ok: true, text: "A password form submits to a related subdomain of this site." });
  } else if (flags.formDestinationCategory === "known-identity-provider") {
    bullets.push({ ok: true, text: "A password form submits to a recognized identity provider (SSO)." });
  }
  if (flags.mixedContentActive) {
    bullets.push({ ok: false, text: "Page loads active mixed content (script, iframe, or stylesheet over HTTP)." });
  } else if (flags.mixedContentPassive) {
    bullets.push({ ok: false, text: "Page loads passive mixed content (image/audio/video over HTTP)." });
  }
  if (flags.ipHostname) {
    bullets.push({ ok: false, text: "Site is identified by a raw IP address, not a domain name." });
  }
  if (flags.punycodeHostname) {
    bullets.push({ ok: false, text: "Hostname uses punycode encoding, which can visually mimic other domains." });
  }
  if (flags.spoofDomain) {
    bullets.push({ ok: false, text: "Domain resembles a known brand — possible fake site." });
  }
  if (flags.sameSiteNoneInsecureCookies) {
    bullets.push({ ok: false, text: "Some cookies use an invalid, high-risk SameSite/Secure combination." });
  }
  if (flags.nonHttpOnlyCookies) {
    bullets.push({ ok: false, text: "Some cookies are readable by page JavaScript (missing HttpOnly)." });
  }

  bullets.push({
    ok: trackers.length === 0,
    text: trackers.length > 0 ? `${trackers.length} tracker(s) detected.` : "No known trackers detected.",
  });

  if (!flags.headersCaptured) {
    bullets.push({ ok: false, text: "Security headers could not be determined for this page." });
  } else {
    const items = securityReport.headerReport?.items || [];
    const failed = items.filter((i) => {
      if (i.status === "ok") return false;
      if (i.name === "x-frame-options" && (flags.clickjackingVerdict === "protected" || flags.clickjackingVerdict === "partially-protected")) {
        return false;
      }
      return i.status === "missing" || i.status === "invalid";
    });
    bullets.push({
      ok: failed.length === 0,
      text: failed.length > 0
        ? `${failed.length} recommended security header(s) missing or invalid.`
        : "Checked security headers look OK (CSP, HSTS, framing, MIME, Referrer-Policy, Permissions-Policy).",
    });
  }

  const cj = flags.clickjackingVerdict;
  if (cj === "unable-to-determine") {
    bullets.push({ ok: false, text: "Clickjacking protection: unable to determine." });
  } else if (cj === "protected") {
    bullets.push({ ok: true, text: "Clickjacking protections are in place (X-Frame-Options and/or CSP frame-ancestors)." });
  } else if (cj === "partially-protected") {
    bullets.push({ ok: false, text: "Clickjacking protection is only partial." });
  } else if (cj === "potentially-frameable") {
    bullets.push({ ok: false, text: "Page may be embeddable in a third-party iframe (clickjacking)." });
  }

  return { headline: tier.headline, advice: tier.advice, bullets };
}

/**
 * @param {object} bundle
 * @param {object} bundle.signals - from content script (SAX_GET_SIGNALS), includes headers/cookies merged in by background
 * @param {object} bundle.cookieBreakdown - { total, secureCount, sameSiteCount, thirdPartyCount, list }
 * @param {string[]} bundle.fingerprintTechniques - deduped technique names seen this page load
 * @param {{api:string,status:string}[]} bundle.permissionEvents - status: 'active' | 'requested'
 */
export function computeFullAnalysis(bundle) {
  const { signals, cookieBreakdown, fingerprintTechniques, permissionEvents } = bundle;

  const securityReport = computeSiteScore(signals);
  const trackers = matchTrackers(signals.thirdPartyScriptHosts || []);
  const privacyReport = computePrivacyScore({ trackers, cookieBreakdown, fingerprintTechniques, permissionEvents });

  // Phishing risk, computed from the STRUCTURED FLAGS scoring.js returns —
  // not by regex-matching its generated sentences. (An earlier version did
  // the latter and had a real bug: the HTTPS-missing reason text didn't
  // match the regex, so a plain-HTTP page like http://http.badssl.com/
  // scored a false 100/100 on phishing risk.)
  const flags = securityReport.flags;

  // Phishing Risk (display): higher = more risk.
  // Identity-only portion (hostname heuristics, and now form-destination
  // heuristics too — Batch 2) is what Trust uses; none of it is also
  // subtracted inside Security, so Trust never averages the same issue
  // twice. See scoring.js computeSiteScore for the Security-side half of
  // this separation.
  const hasPasswordForm = Array.isArray(signals.forms) && signals.forms.length > 0;
  const hasSuspiciousCredentialDestination = flags.formDestinationCategory === "unrelated-https";

  // Batch 2: weak, context-free identity signals are kept low so a SINGLE
  // ambiguous signal — a cheap TLD, a bare IP, plain IDN/punycode encoding
  // — can't by itself dominate the headline Phishing Risk number. They
  // still show up as evidence in findings/summary regardless of weight.
  let identityPenalty = 0;
  if (flags.ipHostname) identityPenalty += 20; // low/moderate alone
  if (flags.suspiciousTld) identityPenalty += 5; // low alone
  if (flags.punycodeHostname) identityPenalty += 5; // low/informational alone

  // Lookalike/spoof-domain match: moderate on its own — a heuristic hit
  // with no credential context on the page could still be coincidental —
  // escalating when there's an actual password form, and escalating
  // further still when that form's own destination is itself unrelated/
  // suspicious. This is the "combination should be substantially
  // stronger" behavior from the Batch 2 spec: a bare lookalike hostname
  // with no login anywhere on the page no longer scores the same as an
  // active credential-harvesting page.
  if (flags.spoofDomain) {
    if (hasPasswordForm && hasSuspiciousCredentialDestination) {
      identityPenalty += 70;
    } else if (hasPasswordForm) {
      identityPenalty += 45;
    } else {
      identityPenalty += 25;
    }
  }

  // Form-destination penalty: only a genuinely unrelated HTTPS destination
  // contributes here (see scoring.js classifyHttpsFormDestination). Same-
  // origin, same-site/subdomain, and known-identity-provider destinations
  // contribute nothing — they're expected, everyday patterns (SSO,
  // multi-subdomain apps), not phishing signals.
  //
  // HTTP destinations are a transport-security issue, already reflected
  // in the Security score (insecureLoginForm, -30) and in the Trust cap
  // below — they are deliberately NOT ALSO counted as phishing here, so
  // "the page uses plain HTTP" doesn't get counted three times over.
  let formPhishingPenalty = 0;
  if (hasSuspiciousCredentialDestination) formPhishingPenalty += 30;
  // Mixed content is a Security finding only — not phishing.

  const phishingRiskScore = Math.min(100, identityPenalty + formPhishingPenalty);
  const phishingSafetyForTrust = Math.max(0, 100 - identityPenalty - formPhishingPenalty);

  // Weighted average — security carries the most weight since a failure
  // there (e.g. no encryption at all) is usually the most consequential.
  const rawTrust = Math.round(
    securityReport.score * 0.5 + privacyReport.score * 0.3 + phishingSafetyForTrust * 0.2
  );

  // Critical-issue cap: some failures are severe enough on their own that
  // no amount of unrelated good news (e.g. a clean privacy score) should
  // be able to average them away into an overall "Safe" verdict. Each cap
  // is a ceiling, not a penalty — the lowest applicable ceiling wins.
  // Lookalike / cheap-TLD heuristics are NOT caps: they are weak signals.
  //
  // Batch 2: the crossOriginForm cap now only fires for the genuinely
  // suspicious "unrelated-https" destination category (flags.crossOriginForm
  // is only ever set true in that case — see scoring.js). Same-origin,
  // same-site/subdomain, and known-identity-provider destinations never
  // reach this cap at all, which is the fix for the old behavior of
  // applying this same severe cap to ordinary SSO / subdomain patterns.
  // The cap's value is unchanged (35) — only the condition that triggers
  // it has been narrowed.
  const criticalCaps = [];
  if (flags.httpsMissing) criticalCaps.push({ cap: 40, reason: "page is not using HTTPS at all" });
  if (flags.insecureLoginForm) criticalCaps.push({ cap: 20, reason: "a login form submits over plain HTTP" });
  if (flags.crossOriginForm) criticalCaps.push({ cap: 35, reason: "a password field on this page submits to an unrelated, unrecognized domain" });
  if (flags.sameSiteNoneInsecureCookies) criticalCaps.push({ cap: 50, reason: "cookies use an invalid SameSite=None-without-Secure configuration" });

  let trustScore = rawTrust;
  let capReason = null;
  if (criticalCaps.length > 0) {
    const worst = criticalCaps.reduce((a, b) => (a.cap < b.cap ? a : b));
    if (worst.cap < trustScore) {
      trustScore = worst.cap;
      capReason = worst.reason;
    }
  }

  const dashboard = {
    securityScore: securityReport.score,
    privacyScore: privacyReport.score,
    phishingRiskScore,
    trustScore,
    ...riskColor(trustScore),
  };

  const summary = generateSafetySummary({ securityReport, privacyReport, trackers, dashboard, capReason });

  // Smart Warnings: only things at "orange" or "red" should ever interrupt
  // the user with a persistent, must-dismiss banner. "green"/"yellow" only
  // get a brief, auto-dismissing, non-blocking confirmation. This is a
  // deliberate design choice — alert fatigue from warning on every minor
  // issue is what makes real users tune out security warnings entirely.
  const criticalIssue = dashboard.color === "orange" || dashboard.color === "red";

  return {
    dashboard,
    securityReport,
    privacyReport,
    trackers,
    cookieBreakdown,
    fingerprintTechniques,
    // Batch 3: the same tiered evidence classification used to compute
    // the Privacy-score penalty above, exposed directly so popup.js can
    // display the SAME conclusion instead of recomputing its own
    // (previously inconsistent) risk thresholds from the raw array.
    fingerprintReport: privacyReport.fingerprintReport,
    permissionEvents,
    summary,
    criticalIssue,
    capReason,
    findings: securityReport.findings || [],
    headerReport: securityReport.headerReport,
    mixedContent: securityReport.mixedContent,
    clickjacking: securityReport.headerReport?.clickjacking || null,
    explanation: `${summary.headline} ${summary.advice}`,
  };
}
