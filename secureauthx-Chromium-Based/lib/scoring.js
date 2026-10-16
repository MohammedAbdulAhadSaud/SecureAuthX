/**
 * SecureAuthX — scoring.js
 *
 * A DELIBERATELY SCOPED-DOWN version of "Module 6: Website Security Score".
 * Full phishing-ML / domain-reputation / tracker-fingerprinting detection
 * is out of scope for this build (see README "Future Scope") — those
 * need training data or third-party threat-intel feeds a solo project
 * can't credibly ship. What we CAN check reliably, locally, and honestly:
 *
 *  - Is the page HTTPS? Is there mixed content (an HTTPS page loading
 *    HTTP sub-resources)?
 *  - Does the login form submit to HTTPS (not HTTP, and not a different
 *    origin than the page itself — a classic red flag)?
 *  - Is the hostname a raw IP address, or IDN/punycode-encoded — both
 *    are strong, well-established phishing signals for a page asking
 *    for credentials.
 *  - Is the hostname on a TLD that's disproportionately abused for
 *    throwaway phishing domains (heuristic weight only, not a ban list).
 *  - Are cookies set with the Secure flag?
 *  - Are there a large number of distinct third-party script hosts?
 *  - Homograph/typosquat + edit-distance + phonetic (Soundex) check
 *    against a list of commonly spoofed brand names (heuristic only —
 *    NOT a full reputation system, and never claims certainty).
 */

const COMMONLY_SPOOFED_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
  "linkedin", "dropbox", "coinbase", "binance", "adobe", "outlook",
  "twitter", "ebay", "docusign", "americanexpress", "usps", "fedex",
  "steam", "spotify", "whatsapp",
  // Deliberately NOT included: "irs" — as a bare 3-letter substring it
  // collides with ordinary English words/domains ("first", "thirst",
  // "firstbank.com", "firstdata.com"), which would false-positive
  // constantly. Short, common-substring brand tokens are excluded on
  // this basis rather than guessing at word-boundary heuristics.
];

// The brand's own legitimate domain(s) — a hostname that's an exact match
// or subdomain of one of these is NOT flagged, however the brand name
// appears. Anything else that mentions the brand name IS flagged, whether
// verbatim ("facebook-login.xyz") or via homoglyph substitution
// ("faceb00k.com") — see looksLikeTyposquat below.
const BRAND_REAL_DOMAINS = {
  paypal: ["paypal.com"],
  google: ["google.com", "googleusercontent.com", "gstatic.com", "goo.gl"],
  microsoft: ["microsoft.com", "live.com", "office.com", "msn.com", "microsoftonline.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.ca", "a2z.com"],
  facebook: ["facebook.com", "fb.com"],
  instagram: ["instagram.com"],
  netflix: ["netflix.com"],
  bankofamerica: ["bankofamerica.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  linkedin: ["linkedin.com", "licdn.com"],
  dropbox: ["dropbox.com", "dropboxusercontent.com"],
  coinbase: ["coinbase.com"],
  binance: ["binance.com", "binance.us"],
  adobe: ["adobe.com"],
  outlook: ["outlook.com", "live.com", "office.com", "microsoftonline.com"],
  twitter: ["twitter.com", "x.com", "t.co"],
  ebay: ["ebay.com"],
  docusign: ["docusign.com", "docusign.net"],
  americanexpress: ["americanexpress.com", "aexp.com"],
  usps: ["usps.com"],
  fedex: ["fedex.com"],
  steam: ["steampowered.com", "steamcommunity.com"],
  spotify: ["spotify.com"],
  whatsapp: ["whatsapp.com"],
};

// crude homoglyph normalization for the heuristic check
const HOMOGLYPH_MAP = { "0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "!": "i" };
function normalizeHomoglyphs(str) {
  return str
    .toLowerCase()
    .split("")
    .map((c) => HOMOGLYPH_MAP[c] ?? c)
    .join("");
}

// Strip punctuation commonly inserted to dodge naive substring matching
// (e.g. "pay-pal-secure.com", "face_book.net") while keeping this purely
// a detection-side normalization — never used for the "is it the real
// domain" check, which always uses the untouched hostname.
function stripSeparators(str) {
  return str.replace(/[-_.]/g, "");
}

function isSubdomainOf(hostname, domain) {
  return hostname === domain || hostname.endsWith("." + domain);
}

/** Iterative Levenshtein edit distance — small strings only, used for typosquat detection. */
function editDistance(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const curr = [i];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    prev = curr;
  }
  return prev[n];
}

// Digraphs that are visually near-indistinguishable from a single letter
// in most UI fonts — the classic typosquat trick ("arnazon" for "amazon",
// "rnicrosoft" for "microsoft"). Applied as a targeted substring rewrite
// rather than loosening edit-distance tolerance, which would otherwise
// false-positive on unrelated words (e.g. "amazing.com" is edit-distance
// 2 from "amazon" but shares no visual-substitution trick with it).
const VISUAL_SUBSTITUTIONS = [
  [/rn/g, "m"],
  [/vv/g, "w"],
  [/cl/g, "d"],
  [/ii/g, "u"],
];
function applyVisualSubstitutions(str) {
  return VISUAL_SUBSTITUTIONS.reduce((s, [pattern, replacement]) => s.replace(pattern, replacement), str);
}

// Common, clearly-non-impersonating suffixes for "about a brand" sites —
// comparison/review/status sites routinely contain the brand name
// verbatim without pretending to BE that brand. Only exempts the exact
// "brand+suffix" first-label shape, so "paypal-secure-login.xyz" and
// "paypal-alternative.com" are still told apart correctly.
const BENIGN_BRAND_SUFFIXES = [
  "alternative", "alternatives", "review", "reviews", "vs", "comparison",
  "comparisons", "tutorial", "tutorials", "guide", "guides", "down",
  "status", "outage", "wiki", "blog", "news", "forum", "forums",
];
function isBenignBrandMention(firstLabel, brand) {
  if (!firstLabel.startsWith(brand)) return false;
  const rest = firstLabel.slice(brand.length).replace(/^[-_]/, "");
  return BENIGN_BRAND_SUFFIXES.includes(rest);
}

// Phonetic matching — catches misspellings that SOUND like the brand but
// aren't visually similar and aren't a small edit distance away, e.g.
// "gugle" for "google" (2 character changes, but identical when spoken)
// or "faisbook" for "facebook". This is a Soundex-style key (first letter
// kept, remaining consonants grouped into digits by sound, vowels reset
// adjacency, h/w are transparent) — but deliberately does NOT truncate to
// the classic 4-character Soundex length. Truncation is what causes
// Soundex's well-known over-collision problem for this use case: under
// standard truncated Soundex, "amazing"/"amazon", "linked"/"linkedin",
// "dropship"/"dropbox", and "netflow"/"netflix" all collide to the same
// code (verified while building this) purely because they share their
// first 3 consonant sounds — even though they're unrelated words. Keeping
// the full, untruncated code still matches genuine phonetic near-misses
// (verified: "gugle"/"google", "faisbook"/"facebook", "amazawn"/"amazon",
// "droppbaks"/"dropbox", "wotsapp"/"whatsapp" all still match) while
// telling apart words with a different total number of consonant sounds.
const SOUNDEX_CODES = {
  b: "1", f: "1", p: "1", v: "1",
  c: "2", g: "2", j: "2", k: "2", q: "2", s: "2", x: "2", z: "2",
  d: "3", t: "3",
  l: "4",
  m: "5", n: "5",
  r: "6",
};
function soundex(word) {
  const letters = (word || "").toLowerCase().replace(/[^a-z]/g, "");
  if (!letters) return "";
  const first = letters[0].toUpperCase();
  let code = "";
  let lastDigit = SOUNDEX_CODES[letters[0]] || "";
  for (let i = 1; i < letters.length; i++) {
    const ch = letters[i];
    const digit = SOUNDEX_CODES[ch];
    if (digit) {
      if (digit !== lastDigit) code += digit;
      lastDigit = digit;
    } else if (ch !== "h" && ch !== "w") {
      // A true vowel (not h/w) resets adjacency — a repeated consonant
      // sound separated by a vowel counts as two occurrences, matching
      // standard Soundex behavior. Deliberately NOT truncated — see note
      // above on why truncation causes false positives here.
      lastDigit = "";
    }
  }
  return first + code;
}

// Known coincidental collisions: real English words or real, unrelated
// domains that happen to contain a brand token as a substring, or land
// within edit-distance/phonetic range of one. Found by testing, not
// guessed — each entry below was confirmed to false-positive before this
// list existed. This is a maintained exception list, not a dictionary or
// a claim of completeness — same heuristic-not-verified framing as the
// rest of this file.
const BRAND_FALSE_POSITIVE_WORDS = {
  apple: ["grapple", "grapples", "grappled", "grappling", "appleton", "appletonwi", "doppler"],
  chase: ["purchase", "purchases", "purchased", "purchasing", "repurchase", "chasm", "chaser", "chasers", "chasing"],
  steam: ["steamship", "steamboat", "steampunk", "steamroller", "steamrolled", "steamer", "steamers", "steamy"],
  outlook: ["outlookindia"],
};
function isKnownFalsePositiveWord(firstLabel, brand) {
  return (BRAND_FALSE_POSITIVE_WORDS[brand] || []).includes(firstLabel);
}

/**
 * Batch 2: per-label (domain-boundary-aware) matching.
 *
 * Previously, Cases 1-4 below ran against the ENTIRE hostname with dots
 * stripped out (e.g. "shop.netflixfanclub.example.info" became
 * "shopnetflixfanclubexampleinfo"). That meant a brand name could be
 * "formed" purely by two unrelated labels sitting next to each other once
 * their separating dot was removed — a false-positive class an attacker
 * doesn't even need to engineer on purpose. Checking each DNS label
 * independently fixes that, while still catching the same
 * brand-in-a-single-label impersonation patterns this heuristic exists
 * for (including brand-as-a-subdomain attacks like
 * "paypal.attacker-domain.com", since "paypal" is still its own label).
 *
 * This also fixes a related latent gap: the exception lists
 * (BENIGN_BRAND_SUFFIXES / BRAND_FALSE_POSITIVE_WORDS) were previously
 * only checked against the FIRST label, so "purchase.com" was correctly
 * excluded for "chase" but "www.purchase.com" or "shop.purchase.com" was
 * not — checking exceptions per-label closes that gap too.
 *
 * Fuzzy checks (edit-distance / Soundex) deliberately stay scoped to the
 * first label only, unchanged from before — they're noisier than exact/
 * near-exact substring-style checks, and widening them to every label
 * risks new false positives on arbitrary subdomains without a documented
 * need for it.
 */
function labelMatchesBrand(label, brand) {
  if (!label) return null;
  if (isBenignBrandMention(label, brand)) return null; // e.g. "dropboxalternative", "paypal-reviews"
  if (isKnownFalsePositiveWord(label, brand)) return null; // e.g. "grapple", "purchase", "outlookindia"

  const normalizedLabel = normalizeHomoglyphs(label);
  const separatorStrippedLabel = stripSeparators(label);
  const normalizedSeparatorStrippedLabel = normalizeHomoglyphs(separatorStrippedLabel);
  const visualSubstitutedLabel = applyVisualSubstitutions(separatorStrippedLabel);

  // Case 1: brand name appears verbatim within a single label — e.g. the
  // label "facebook-login" in "facebook-login.xyz".
  if (label.includes(brand)) return { kind: "substring" };

  // Case 2: brand name appears only after de-homoglyphing — e.g. the
  // label is "faceb00k" but normalizes to "facebook".
  if (normalizedLabel.includes(brand)) return { kind: "homoglyph" };

  // Case 3: brand name appears once separators (dashes/underscores) are
  // stripped from the label, with or without homoglyph substitution —
  // e.g. "pay-pal-secure" or "g00gle-mail".
  if (separatorStrippedLabel.includes(brand) || normalizedSeparatorStrippedLabel.includes(brand)) {
    return { kind: "obfuscated" };
  }

  // Case 4: brand name appears after undoing common visually-similar
  // digraph substitutions — e.g. "arnazon" -> "amazon" via rn->m.
  if (visualSubstitutedLabel.includes(brand)) {
    return { kind: "visual-substitution" };
  }

  return null;
}

export function looksLikeTyposquat(hostname) {
  const lowerHost = (hostname || "").toLowerCase();
  const labels = lowerHost.split(".").filter(Boolean);

  // The registrable label we compare for near-miss edit distance —
  // roughly "the part before the first dot", which is where brand
  // impersonation almost always lives (e.g. "arnazon" in "arnazon.com").
  const firstLabel = labels[0] || "";

  for (const brand of COMMONLY_SPOOFED_BRANDS) {
    // Defensive floor: a brand token under 4 characters is too likely to
    // collide with ordinary English substrings (see the "irs"/"first"
    // case above) for plain substring matching to be safe.
    if (brand.length < 4) continue;

    const realDomains = BRAND_REAL_DOMAINS[brand] || [];
    const isActuallyTheBrand = realDomains.some((d) => isSubdomainOf(lowerHost, d));
    if (isActuallyTheBrand) continue; // it really is the brand's own domain — never flag

    // Cases 1-4: exact/near-exact matching, checked per label.
    for (const label of labels) {
      const hit = labelMatchesBrand(label, brand);
      if (hit) return { brand, kind: hit.kind };
    }

    // Case 5: the first label is a SINGLE character away from the brand
    // name (one insert/delete/substitute) — catches simple typos like
    // "gogle" or "paypaI" that don't match any of the above. Kept at
    // distance 1 deliberately: a looser threshold starts matching
    // unrelated real words (e.g. "amazing" is distance-2 from "amazon").
    if (isBenignBrandMention(firstLabel, brand) || isKnownFalsePositiveWord(firstLabel, brand)) continue;

    if (firstLabel.length >= 4 && firstLabel !== brand && editDistance(firstLabel, brand) <= 1) {
      return { brand, kind: "edit-distance" };
    }

    // Case 6: the first label SOUNDS like the brand name (same Soundex
    // code) even though it's spelled too differently for the edit-distance
    // check above — e.g. "gugle" or "faisbook". Soundex alone is coarse
    // enough to false-positive on unrelated words, so this is guarded by
    // a length-difference cap: only fires when the label is within 2
    // characters of the brand's length, which keeps it from matching
    // longer, unrelated words that happen to land on the same 4-digit code.
    if (
      firstLabel.length >= 4 &&
      firstLabel !== brand &&
      Math.abs(firstLabel.length - brand.length) <= 2 &&
      soundex(firstLabel) === soundex(brand)
    ) {
      return { brand, kind: "phonetic" };
    }
  }
  return null;
}

// Free/low-friction-registration TLDs disproportionately used for
// throwaway phishing infrastructure. This is a mild heuristic weight,
// not an accusation — plenty of legitimate sites use these too, so it
// contributes a small amount to phishing risk rather than a large one.
const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "work",
  "support", "zip", "mov", "quest", "gd", "buzz", "rest", "loan", "men",
]);

function getTld(hostname) {
  const parts = (hostname || "").toLowerCase().split(".");
  return parts.length > 1 ? parts[parts.length - 1] : "";
}

function isIpAddressHostname(hostname) {
  const h = (hostname || "").trim();
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h)) {
    return h.split(".").every((octet) => Number(octet) <= 255);
  }
  // IPv6 (bracketed or bare)
  const bare = h.replace(/^\[|\]$/g, "");
  if (/^[0-9a-f:]+$/i.test(bare) && bare.includes(":")) return true;
  return false;
}

function isPunycodeHostname(hostname) {
  return /(^|\.)xn--/i.test(hostname || "");
}

/**
 * Batch 2 — registrable-domain helper (deliberately NOT a Public Suffix
 * List implementation).
 *
 * This exists solely to tell "different subdomain of the same site"
 * (login.example.com vs. www.example.com) apart from "different site
 * entirely" (login.example.com vs. example.net) for password-form
 * destination analysis. A full PSL has ~10,000 entries and changes over
 * time; shipping a naive "last two labels" rule for everything would be
 * WRONG for any real multi-label public suffix (e.g. it would treat
 * "example.co.uk" and "attacker.co.uk" as "the same site", which is
 * false — co.uk is a public registry suffix, not anyone's registrable
 * domain). So instead: last-two-labels is the default, with a short,
 * explicit, conservative list of known multi-label suffixes bumping the
 * comparison to the last three labels. This is intentionally narrow — it
 * covers the common cases named in the Batch 2 spec and nothing more.
 * A pattern that isn't recognized here simply falls back to "unrelated"
 * treatment, which is the safe direction to err in.
 */
const MULTI_LABEL_PUBLIC_SUFFIXES = new Set(["co.uk", "com.au", "co.jp", "co.in"]);

export function getRegistrableDomain(hostname) {
  const h = (hostname || "").toLowerCase().replace(/\.$/, "");
  if (!h || isIpAddressHostname(h)) return h; // no registrable-domain concept for raw IPs
  const labels = h.split(".").filter(Boolean);
  if (labels.length < 2) return h;

  const lastTwo = labels.slice(-2).join(".");
  if (labels.length >= 3 && MULTI_LABEL_PUBLIC_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

export function isSameRegistrableDomain(hostnameA, hostnameB) {
  if (!hostnameA || !hostnameB) return false;
  return getRegistrableDomain(hostnameA) === getRegistrableDomain(hostnameB);
}

/**
 * Batch 2 — small, explicit, conservative allowlist of well-known
 * third-party identity providers. A cross-origin password form that
 * submits to one of these is expected, everyday SSO behavior, not a
 * phishing signal.
 *
 * Domain-boundary-aware: matching reuses `isSubdomainOf`, which requires
 * an exact match or a match on a "." label boundary — so "foo.okta.com"
 * matches the "okta.com" entry, but "evilokta.com" does NOT (it doesn't
 * equal "okta.com" and doesn't end in ".okta.com"). This is deliberately
 * NOT a substring check, to avoid the same false-positive class Batch 2
 * is fixing elsewhere in this file.
 *
 * Wildcard-style entries ("okta.com", "auth0.com") are listed at the
 * apex because those providers host customer-specific tenants on
 * subdomains by design (e.g. "acme.okta.com"). Single-purpose login
 * hosts are listed at their specific hostname instead, to stay
 * conservative rather than trusting an entire apex domain unnecessarily.
 */
const KNOWN_IDENTITY_PROVIDERS = [
  "accounts.google.com",
  "appleid.apple.com",
  "login.microsoftonline.com",
  "login.live.com",
  "login.windows.net",
  "okta.com",
  "auth0.com",
  "onelogin.com",
  "pingidentity.com",
  "pingone.com",
];

export function isKnownIdentityProvider(hostname) {
  const h = (hostname || "").toLowerCase();
  if (!h) return false;
  return KNOWN_IDENTITY_PROVIDERS.some((provider) => isSubdomainOf(h, provider));
}

/**
 * Batch 2 — classify where an HTTPS password form submits to, for
 * identity/phishing purposes only (never used to affect the Security
 * score — see the "Security vs Identity separation" note where this is
 * called from computeSiteScore).
 *
 * Only called for forms already confirmed to submit over HTTPS — HTTP
 * destinations are handled entirely separately, as a transport-security
 * Security-score issue (see insecureLoginForm below).
 */
export function classifyHttpsFormDestination(form, pageHostname) {
  if (form.actionSameOrigin) return "same-origin";
  const actionHostname = (form.actionHostname || "").toLowerCase();
  if (isKnownIdentityProvider(actionHostname)) return "known-identity-provider";
  if (isSameRegistrableDomain(actionHostname, pageHostname)) return "same-site";
  return "unrelated-https";
}

/**
 * signals expected shape (gathered by content script + background):
 * {
 *   isHttps: bool,
 *   hostname: string,
 *   forms: [{ actionIsHttps: bool, actionSameOrigin: bool, actionHostname: string }],  // password-bearing forms only
 *   thirdPartyScriptHosts: string[],
 *   mixedContentCount: number,          // legacy; prefer mixedContent
 *   mixedContent: { activeCount, passiveCount, activeEvidence, passiveEvidence },
 *   cookies: [{ secure: bool, httpOnly: bool, sameSite: string }],
 *   headers: { captured: bool, present: {[name]: string} } | undefined,
 * }
 *
 * KNOWN LIMITATION (documented honestly, not silently missed): the
 * typosquat/homograph checks below match brand names against the literal
 * hostname string. For an IDN homograph attack, `hostname` arrives already
 * punycode-encoded (e.g. "xn--pple-43d.com" for a Cyrillic look-alike of
 * "apple.com") — the substring/homoglyph matching can't "see" the brand
 * name inside that encoded form without a punycode decoder, which this
 * build doesn't include. isPunycodeHostname() below is the mitigation:
 * browsers themselves only render a hostname as punycode (rather than the
 * actual Unicode) when their own anti-spoofing logic already considers the
 * script mix suspicious — so flagging punycode presence at all is a
 * reasonable proxy signal, just not a brand-specific one.
 */

// Not all recommended headers matter equally for an active security
// posture — CSP and HSTS materially reduce real attack classes (XSS,
// protocol downgrade), so they're weighted heavier than the others.
const HEADER_WEIGHTS = {
  "content-security-policy": 7,
  "strict-transport-security": 6,
  "x-frame-options": 3,
  "x-content-type-options": 2,
  "referrer-policy": 2,
  "permissions-policy": 2,
};

export const SECURITY_HEADER_NAMES = Object.keys(HEADER_WEIGHTS);

const HEADER_LABELS = {
  "content-security-policy": "Content-Security-Policy",
  "strict-transport-security": "Strict-Transport-Security",
  "x-frame-options": "X-Frame-Options",
  "x-content-type-options": "X-Content-Type-Options",
  "referrer-policy": "Referrer-Policy",
  "permissions-policy": "Permissions-Policy",
};

/** Strip query/hash so evidence cannot retain tokens or session ids. */
export function evidenceUrlFromAbsolute(absoluteUrl) {
  try {
    const u = new URL(absoluteUrl);
    return `${u.origin}${u.pathname}`;
  } catch {
    return null;
  }
}

function parseCspDirectives(cspValue) {
  const map = new Map();
  if (!cspValue) return map;
  // Multiple CSP headers are combined with "; " in capture; treat as one policy list.
  for (const part of String(cspValue).split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = tokens[0].toLowerCase();
    const values = tokens.slice(1);
    const existing = map.get(name) || [];
    map.set(name, existing.concat(values));
  }
  return map;
}

function evaluateHsts(value) {
  if (!value || !String(value).trim()) return { status: "missing", detail: "Header not set." };
  const match = /max-age\s*=\s*(\d+)/i.exec(value);
  if (!match) return { status: "invalid", detail: "Present but missing max-age." };
  const maxAge = Number(match[1]);
  if (!(maxAge > 0)) return { status: "invalid", detail: "Present but max-age is 0." };
  return { status: "ok", detail: `max-age=${maxAge}` };
}

function evaluateXContentTypeOptions(value) {
  if (!value || !String(value).trim()) return { status: "missing", detail: "Header not set." };
  if (String(value).trim().toLowerCase() === "nosniff") {
    return { status: "ok", detail: "nosniff" };
  }
  return { status: "invalid", detail: `Unexpected value (want nosniff).` };
}

function evaluateXFrameOptions(value) {
  if (!value || !String(value).trim()) return { status: "missing", detail: "Header not set." };
  const v = String(value).trim().toUpperCase();
  if (v === "DENY" || v === "SAMEORIGIN") return { status: "ok", detail: v, normalized: v };
  if (v.startsWith("ALLOW-FROM")) return { status: "ok", detail: "ALLOW-FROM", normalized: "ALLOW-FROM", partial: true };
  return { status: "invalid", detail: "Unrecognized value (want DENY or SAMEORIGIN).", normalized: null };
}

function evaluatePresentNonEmpty(value, missingDetail) {
  if (!value || !String(value).trim()) return { status: "missing", detail: missingDetail };
  return { status: "ok", detail: "Present." };
}

function classifyFrameAncestors(sources) {
  if (sources == null) return { kind: "absent" }; // no CSP
  if (!Array.isArray(sources) || sources.length === 0) return { kind: "unconstrained" };
  const normalized = sources.map((s) => String(s).toLowerCase());
  if (normalized.some((s) => s === "*")) return { kind: "wildcard" };
  const onlyNone = normalized.every((s) => s === "'none'");
  const onlySelfOrNone = normalized.every((s) => s === "'self'" || s === "'none'");
  if (onlyNone || onlySelfOrNone) return { kind: "restrictive", sources: normalized };
  return { kind: "allowlist", sources: normalized };
}

/**
 * Clickjacking verdict from X-Frame-Options + CSP frame-ancestors.
 * The stricter of the two mechanisms wins (browsers enforce both).
 */
export function assessClickjacking({ captured, xfo, frameAncestors }) {
  if (!captured) {
    return {
      verdict: "unable-to-determine",
      label: "Unable to determine",
      reason: "Response headers were not captured for this page, so framing protection cannot be checked.",
      skipXfoPenalty: true,
    };
  }

  const xfoProtects = xfo?.status === "ok" && (xfo.normalized === "DENY" || xfo.normalized === "SAMEORIGIN");
  const xfoPartial = xfo?.status === "ok" && xfo.normalized === "ALLOW-FROM";
  const fa = frameAncestors || { kind: "absent" };
  const cspProtects = fa.kind === "restrictive";
  const cspPartial = fa.kind === "allowlist";

  if (xfoProtects || cspProtects) {
    const via = [];
    if (cspProtects) via.push("CSP frame-ancestors");
    if (xfoProtects) via.push(`X-Frame-Options ${xfo.normalized}`);
    return {
      verdict: "protected",
      label: "Protected",
      reason: `Framing is restricted (${via.join(" and ")}).`,
      skipXfoPenalty: cspProtects && !(xfoProtects || xfoPartial),
    };
  }

  if (xfoPartial || cspPartial) {
    return {
      verdict: "partially-protected",
      label: "Partially protected",
      reason: cspPartial
        ? `CSP frame-ancestors allows specific origins (${(fa.sources || []).join(" ")}).`
        : "X-Frame-Options ALLOW-FROM permits framing by a named origin.",
      skipXfoPenalty: cspPartial && xfo?.status === "missing",
    };
  }

  return {
    verdict: "potentially-frameable",
    label: "Potentially frameable",
    reason: "No valid X-Frame-Options DENY/SAMEORIGIN and no restricting CSP frame-ancestors.",
    skipXfoPenalty: false,
  };
}

/**
 * Evaluate only the six recommended security headers.
 * Unrelated HTTP headers are ignored. Missing capture is not treated as "all missing".
 */
export function evaluateSecurityHeaders(headers) {
  const captured = !!(headers && headers.captured === true);
  const present = (headers && headers.present) || {};
  const items = [];

  const cspRaw = present["content-security-policy"];
  const cspDirectives = captured ? parseCspDirectives(cspRaw) : new Map();
  const hasCsp = captured && !!(cspRaw && String(cspRaw).trim());
  const faSources = hasCsp ? (cspDirectives.has("frame-ancestors") ? cspDirectives.get("frame-ancestors") : []) : null;
  const frameAncestors = captured ? classifyFrameAncestors(hasCsp ? faSources : null) : { kind: "absent" };

  const evaluators = {
    "content-security-policy": () => {
      if (!captured) return { status: "unknown", detail: "Unable to determine." };
      if (!hasCsp) return { status: "missing", detail: "Header not set." };
      const faNote = frameAncestors.kind === "restrictive"
        ? "frame-ancestors is restrictive."
        : frameAncestors.kind === "allowlist"
          ? "frame-ancestors allowlists specific origins."
          : frameAncestors.kind === "wildcard"
            ? "frame-ancestors is * (does not restrict framing)."
            : "Present (no frame-ancestors directive).";
      return { status: "ok", detail: faNote };
    },
    "strict-transport-security": () => (captured ? evaluateHsts(present["strict-transport-security"]) : { status: "unknown", detail: "Unable to determine." }),
    "x-frame-options": () => (captured ? evaluateXFrameOptions(present["x-frame-options"]) : { status: "unknown", detail: "Unable to determine." }),
    "x-content-type-options": () => (captured ? evaluateXContentTypeOptions(present["x-content-type-options"]) : { status: "unknown", detail: "Unable to determine." }),
    "referrer-policy": () => (captured ? evaluatePresentNonEmpty(present["referrer-policy"], "Header not set.") : { status: "unknown", detail: "Unable to determine." }),
    "permissions-policy": () => (captured ? evaluatePresentNonEmpty(present["permissions-policy"], "Header not set.") : { status: "unknown", detail: "Unable to determine." }),
  };

  for (const name of SECURITY_HEADER_NAMES) {
    const result = evaluators[name]();
    items.push({
      name,
      label: HEADER_LABELS[name],
      status: result.status,
      detail: result.detail,
      normalized: result.normalized,
      partial: result.partial,
    });
  }

  const xfoItem = items.find((i) => i.name === "x-frame-options");
  const clickjacking = assessClickjacking({
    captured,
    xfo: xfoItem,
    frameAncestors,
  });

  return { captured, items, clickjacking, frameAncestors };
}

export function normalizeMixedContent(signals) {
  const mc = signals && signals.mixedContent;
  if (mc && typeof mc === "object") {
    return {
      activeCount: Number(mc.activeCount) || 0,
      passiveCount: Number(mc.passiveCount) || 0,
      activeEvidence: Array.isArray(mc.activeEvidence) ? mc.activeEvidence.slice(0, 8) : [],
      passiveEvidence: Array.isArray(mc.passiveEvidence) ? mc.passiveEvidence.slice(0, 8) : [],
    };
  }
  // Legacy: mixedContentCount was scripts/iframes/stylesheets only (active).
  const n = Number(signals && signals.mixedContentCount) || 0;
  return { activeCount: n, passiveCount: 0, activeEvidence: [], passiveEvidence: [] };
}

function pushFinding(findings, entry) {
  findings.push({
    id: entry.id,
    category: entry.category,
    severity: entry.severity,
    penalty: entry.penalty,
    what: entry.what,
    why: entry.why,
    evidence: entry.evidence,
    confidence: entry.confidence || "high",
  });
}

export function computeSiteScore(signals) {
  let score = 100;
  const reasons = [];
  const findings = [];
  const flags = {
    httpsMissing: false,
    mixedContent: false,
    mixedContentActive: false,
    mixedContentPassive: false,
    insecureLoginForm: false,
    crossOriginForm: false, // Batch 2: true only for a genuinely unrelated-HTTPS destination
    formDestinationCategory: "none", // 'none' | 'http' | 'same-origin' | 'same-site' | 'known-identity-provider' | 'unrelated-https'
    formDestinationCounts: { http: 0, sameOrigin: 0, sameSite: 0, identityProvider: 0, unrelatedHttps: 0 },
    insecureCookies: false,
    nonHttpOnlyCookies: false,
    sameSiteNoneInsecureCookies: false,
    highThirdPartyScriptCount: false,
    spoofDomain: false,
    spoofDetail: null,
    ipHostname: false,
    punycodeHostname: false,
    suspiciousTld: false,
    missingHeaderCount: 0,
    missingHeaderNames: [],
    headersCaptured: false,
    clickjackingVerdict: "unable-to-determine",
  };

  if (!signals.isHttps) {
    score -= 40;
    flags.httpsMissing = true;
    reasons.push({ severity: "high", text: "Page is not served over HTTPS." });
    pushFinding(findings, {
      id: "https-missing",
      category: "security",
      severity: "high",
      penalty: 40,
      what: "Page is not served over HTTPS.",
      why: "Anything sent on this page (including passwords) can be read or changed on the network.",
      evidence: "document protocol is http:",
      confidence: "high",
    });
  } else {
    const mixed = normalizeMixedContent(signals);
    flags.mixedContentActive = mixed.activeCount > 0;
    flags.mixedContentPassive = mixed.passiveCount > 0;
    flags.mixedContent = flags.mixedContentActive; // legacy flag: active only

    if (mixed.activeCount > 0) {
      const penalty = Math.min(20, 12 + mixed.activeCount * 2);
      score -= penalty;
      reasons.push({
        severity: "medium",
        text: `${mixed.activeCount} active mixed-content resource(s) (script, iframe, or stylesheet) loaded over HTTP on this HTTPS page.`,
      });
      pushFinding(findings, {
        id: "mixed-content-active",
        category: "security",
        severity: "medium",
        penalty,
        what: "Active mixed content (script, iframe, or stylesheet over HTTP).",
        why: "An attacker on the network can replace those resources and run code or change the page.",
        evidence: mixed.activeEvidence.join(", ") || `${mixed.activeCount} active HTTP subresource(s)`,
        confidence: "high",
      });
    }
    if (mixed.passiveCount > 0) {
      const penalty = Math.min(6, mixed.passiveCount * 2);
      score -= penalty;
      reasons.push({
        severity: "low",
        text: `${mixed.passiveCount} passive mixed-content resource(s) (image, audio, or video) loaded over HTTP.`,
      });
      pushFinding(findings, {
        id: "mixed-content-passive",
        category: "security",
        severity: "low",
        penalty,
        what: "Passive mixed content (image/audio/video over HTTP).",
        why: "Those files can be swapped or watched on the path, but they do not execute as page script. This is not treated as phishing.",
        evidence: mixed.passiveEvidence.join(", ") || `${mixed.passiveCount} passive HTTP subresource(s)`,
        confidence: "high",
      });
    }
  }

  // -----------------------------------------------------------------------
  // Password-form destination analysis (Batch 2).
  //
  // HTTP-vs-HTTPS is a transport-security question and stays in the
  // Security score, exactly as before. Where an HTTPS form submits TO
  // (same page, related subdomain, known identity provider, or somewhere
  // unrelated) is an identity/phishing question — Batch 1 already kept
  // hostname-lookalike signals out of Security for this reason ("Trust
  // must not average the same issue twice"); Batch 2 extends that same
  // separation to form-destination signals. So: no Security-score penalty
  // is applied for any HTTPS destination category here. analysis.js folds
  // the genuinely-suspicious case (unrelated-https) into Phishing Risk
  // instead. The structured category/counts are still recorded on `flags`
  // so the finding stays visible as evidence either way.
  // -----------------------------------------------------------------------
  const insecureForms = (signals.forms || []).filter((f) => !f.actionIsHttps);
  flags.formDestinationCounts.http = insecureForms.length;
  if (insecureForms.length > 0) {
    score -= 30;
    flags.insecureLoginForm = true;
    reasons.push({ severity: "high", text: `${insecureForms.length} login form(s) submit over plain HTTP.` });
    pushFinding(findings, {
      id: "insecure-login-form",
      category: "security",
      severity: "high",
      penalty: 30,
      what: "A password form submits over plain HTTP.",
      why: "Credentials can be intercepted or modified in transit. This is a transport-security issue, tracked separately from where an HTTPS form submits to.",
      evidence: `${insecureForms.length} password-bearing form(s) with a non-HTTPS action`,
      confidence: "high",
    });
  }

  const httpsForms = (signals.forms || []).filter((f) => f.actionIsHttps);
  const categoryRank = { "same-site": 0, "known-identity-provider": 0, "unrelated-https": 1 };
  let worstHttpsCategory = null; // among same-site / known-identity-provider / unrelated-https

  for (const f of httpsForms) {
    const category = classifyHttpsFormDestination(f, signals.hostname || "");
    if (category === "same-origin") {
      flags.formDestinationCounts.sameOrigin++;
      continue;
    }
    if (category === "same-site") flags.formDestinationCounts.sameSite++;
    else if (category === "known-identity-provider") flags.formDestinationCounts.identityProvider++;
    else flags.formDestinationCounts.unrelatedHttps++;

    if (worstHttpsCategory === null || categoryRank[category] > categoryRank[worstHttpsCategory]) {
      worstHttpsCategory = category;
    }
  }

  flags.formDestinationCategory =
    worstHttpsCategory || (flags.formDestinationCounts.sameOrigin > 0 ? "same-origin" : (insecureForms.length > 0 ? "http" : "none"));

  if (worstHttpsCategory === "unrelated-https") {
    // The only form-destination category treated as suspicious. Kept OUT
    // of the Security score (see comment above) — this only informs
    // findings/reasons here; analysis.js is what turns it into Phishing
    // Risk and a Trust cap.
    flags.crossOriginForm = true;
    reasons.push({
      severity: "medium",
      text: `${flags.formDestinationCounts.unrelatedHttps} form(s) submit credentials to an unrelated external domain.`,
    });
    pushFinding(findings, {
      id: "unrelated-credential-destination",
      category: "identity",
      severity: "medium",
      penalty: 0,
      what: "A password form submits to a domain unrelated to the page and not a recognized identity provider.",
      why: "That can be legitimate (a lesser-known SSO/auth provider) or it can send credentials to a third party. Kept out of the Security score; factored into Phishing Risk instead.",
      evidence: `${flags.formDestinationCounts.unrelatedHttps} password-bearing form(s) with a cross-registrable-domain HTTPS action`,
      confidence: "medium",
    });
  } else if (worstHttpsCategory === "same-site") {
    reasons.push({
      severity: "low",
      text: `${flags.formDestinationCounts.sameSite} form(s) submit to a related subdomain of this site — not treated as suspicious.`,
    });
  } else if (worstHttpsCategory === "known-identity-provider") {
    reasons.push({
      severity: "low",
      text: `${flags.formDestinationCounts.identityProvider} form(s) submit to a recognized identity provider (SSO) — not treated as suspicious.`,
    });
  }

  const cookies = signals.cookies || [];

  const sameSiteNoneInsecure = cookies.filter((c) => (c.sameSite || "").toLowerCase() === "no_restriction" && !c.secure);
  if (sameSiteNoneInsecure.length > 0) {
    const penalty = Math.min(15, sameSiteNoneInsecure.length * 5);
    score -= penalty;
    flags.sameSiteNoneInsecureCookies = true;
    reasons.push({ severity: "high", text: `${sameSiteNoneInsecure.length} cookie(s) set SameSite=None without Secure — an invalid, high-risk combination.` });
    pushFinding(findings, {
      id: "samesite-none-insecure",
      category: "security",
      severity: "high",
      penalty,
      what: "Cookie(s) use SameSite=None without the Secure flag.",
      why: "That combination is invalid and is meant for cross-site cookies on HTTPS only.",
      evidence: `${sameSiteNoneInsecure.length} cookie(s) (flags only; names/values not used in scoring)`,
      confidence: "high",
    });
  }

  // Do not also penalize those same cookies under the generic "missing Secure" rule.
  const insecureCookies = cookies.filter((c) => !c.secure && (c.sameSite || "").toLowerCase() !== "no_restriction");
  if (insecureCookies.length > 0) {
    const penalty = Math.min(20, insecureCookies.length * 3);
    score -= penalty;
    flags.insecureCookies = true;
    reasons.push({ severity: insecureCookies.length >= 5 ? "medium" : "low", text: `${insecureCookies.length} cookie(s) missing the Secure flag.` });
    pushFinding(findings, {
      id: "cookies-not-secure",
      category: "security",
      severity: insecureCookies.length >= 5 ? "medium" : "low",
      penalty,
      what: "Cookie(s) missing the Secure flag.",
      why: "Without Secure, the browser may send the cookie on unencrypted HTTP requests.",
      evidence: `${insecureCookies.length} first-party cookie(s) with secure=false`,
      confidence: "high",
    });
  }

  const nonHttpOnlyCookies = cookies.filter((c) => !c.httpOnly);
  if (nonHttpOnlyCookies.length > 0) {
    const penalty = Math.min(15, nonHttpOnlyCookies.length * 2);
    score -= penalty;
    flags.nonHttpOnlyCookies = true;
    reasons.push({ severity: nonHttpOnlyCookies.length >= 5 ? "medium" : "low", text: `${nonHttpOnlyCookies.length} cookie(s) missing the HttpOnly flag (readable by page JavaScript).` });
    pushFinding(findings, {
      id: "cookies-not-httponly",
      category: "security",
      severity: nonHttpOnlyCookies.length >= 5 ? "medium" : "low",
      penalty,
      what: "Cookie(s) missing the HttpOnly flag.",
      why: "Page JavaScript (including injected script) can read those cookies.",
      evidence: `${nonHttpOnlyCookies.length} first-party cookie(s) with httpOnly=false`,
      confidence: "high",
    });
  }

  const thirdPartyCount = (signals.thirdPartyScriptHosts || []).length;
  if (thirdPartyCount > 5) {
    const penalty = Math.min(15, (thirdPartyCount - 5) * 1.5);
    score -= penalty;
    flags.highThirdPartyScriptCount = true;
    reasons.push({ severity: thirdPartyCount > 15 ? "medium" : "low", text: `Unusually high number of third-party script sources (${thirdPartyCount}).` });
    pushFinding(findings, {
      id: "third-party-scripts",
      category: "security",
      severity: thirdPartyCount > 15 ? "medium" : "low",
      penalty,
      what: `Many distinct third-party script hosts (${thirdPartyCount}).`,
      why: "This is a volume signal, not proof that those hosts are trackers or malware.",
      evidence: `${thirdPartyCount} unique hostnames on script src`,
      confidence: "low",
    });
  }

  const hostname = signals.hostname || "";

  // Identity / lookalike flags feed Phishing Risk. They are not subtracted
  // from Security so Trust does not count the same hostname issue twice.
  if (isIpAddressHostname(hostname)) {
    flags.ipHostname = true;
    reasons.push({ severity: "high", text: "Site is identified by a raw IP address rather than a domain name — unusual and risky for a login page." });
  }

  if (isPunycodeHostname(hostname)) {
    flags.punycodeHostname = true;
    reasons.push({ severity: "medium", text: "Hostname uses punycode (internationalized domain) encoding — can be used to visually mimic other domains." });
  }

  const tld = getTld(hostname);
  if (SUSPICIOUS_TLDS.has(tld)) {
    flags.suspiciousTld = true;
    reasons.push({ severity: "low", text: `Domain uses a ".${tld}" TLD that's disproportionately used for low-cost/throwaway sites — not proof of anything on its own.` });
  }

  const spoofHit = looksLikeTyposquat(hostname);
  if (spoofHit) {
    flags.spoofDomain = true;
    flags.spoofDetail = spoofHit;
    reasons.push({
      severity: "high",
      text: `Hostname resembles "${spoofHit.brand}" (${
        spoofHit.kind === "edit-distance" ? "near-identical spelling"
        : spoofHit.kind === "phonetic" ? "sounds the same when spoken aloud"
        : "lookalike characters"
      }) — possible typosquat. This is a heuristic, not a verified detection.`,
    });
  }

  const headerReport = evaluateSecurityHeaders(signals.headers);
  flags.headersCaptured = headerReport.captured;
  flags.clickjackingVerdict = headerReport.clickjacking.verdict;

  if (!headerReport.captured) {
    reasons.push({ severity: "low", text: "Security headers could not be determined (response headers were not captured)." });
    pushFinding(findings, {
      id: "headers-unknown",
      category: "security",
      severity: "low",
      penalty: 0,
      what: "Security headers: unable to determine.",
      why: "Without the document's response headers, missing CSP/HSTS/framing headers cannot be assumed.",
      evidence: "No main-frame header capture for this tab",
      confidence: "low",
    });
  } else {
    const skipXfo = headerReport.clickjacking.skipXfoPenalty;
    const penalized = headerReport.items.filter((item) => {
      if (item.status === "ok" || item.status === "unknown") return false;
      if (item.name === "x-frame-options" && skipXfo) return false;
      return true;
    });
    flags.missingHeaderCount = penalized.length;
    flags.missingHeaderNames = penalized.map((i) => i.name);

    if (penalized.length > 0) {
      const penalty = Math.min(20, penalized.reduce((sum, h) => sum + (HEADER_WEIGHTS[h.name] ?? 2), 0));
      score -= penalty;
      reasons.push({
        severity: penalized.some((h) => h.name === "content-security-policy" || h.name === "strict-transport-security") ? "medium" : "low",
        text: `${penalized.length} recommended security header(s) missing or invalid: ${penalized.map((h) => h.name).join(", ")}.`,
      });
      pushFinding(findings, {
        id: "security-headers",
        category: "security",
        severity: penalized.some((h) => h.name === "content-security-policy" || h.name === "strict-transport-security") ? "medium" : "low",
        penalty,
        what: "Recommended security headers missing or invalid.",
        why: "These headers reduce XSS, clickjacking, MIME sniffing, and HTTPS downgrade risk. Only the six checked headers are counted.",
        evidence: penalized.map((h) => `${h.name}: ${h.status} (${h.detail})`).join("; "),
        confidence: "high",
      });
    }

    const cj = headerReport.clickjacking;
    if (cj.verdict === "potentially-frameable") {
      const xfoAlreadyPenalized = penalized.some((h) => h.name === "x-frame-options");
      const cjPenalty = xfoAlreadyPenalized ? 0 : 3;
      score -= cjPenalty;
      reasons.push({ severity: "medium", text: `Clickjacking: ${cj.label}. ${cj.reason}` });
      pushFinding(findings, {
        id: "clickjacking",
        category: "security",
        severity: "medium",
        penalty: cjPenalty,
        what: "Page appears potentially frameable.",
        why: "Another site may embed this page in an iframe and trick users into clicking hidden controls.",
        evidence: cj.reason,
        confidence: "medium",
      });
    } else if (cj.verdict === "partially-protected") {
      reasons.push({ severity: "low", text: `Clickjacking: ${cj.label}. ${cj.reason}` });
      pushFinding(findings, {
        id: "clickjacking",
        category: "security",
        severity: "low",
        penalty: 0,
        what: "Clickjacking protection is only partial.",
        why: "Some third-party origins may still embed this page.",
        evidence: cj.reason,
        confidence: "medium",
      });
    } else if (cj.verdict === "protected") {
      pushFinding(findings, {
        id: "clickjacking",
        category: "security",
        severity: "low",
        penalty: 0,
        what: "Clickjacking protections are in place.",
        why: "X-Frame-Options and/or CSP frame-ancestors restrict embedding.",
        evidence: cj.reason,
        confidence: "high",
      });
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  let riskLevel = "Low";
  if (score < 40) riskLevel = "High";
  else if (score < 70) riskLevel = "Medium";

  return { score, riskLevel, reasons, flags, findings, headerReport, mixedContent: normalizeMixedContent(signals) };
}
