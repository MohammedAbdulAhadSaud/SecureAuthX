# SecureAuthX

A cross-browser (Chrome / Firefox / Edge / Brave / Opera) extension that:

- **Derives** a unique, high-entropy password per site from one master password (never stored, never transmitted)
- **Detects password reuse** locally, using comparison hashes only
- **Analyzes password strength** offline (entropy, common-password check, pattern detection)
- **Scores the current page's basic security posture** (HTTPS, form targets, cookie flags, a lookalike-hostname heuristic)

This build is a **deliberately scoped-down subset** of a larger original spec. See [Scope Decisions](#scope-decisions) for what was cut and why — that reasoning is part of the project's engineering story, not an afterthought.

---

## Why this exists (short version)

Password reuse + weak passwords + server-side breaches are one of the most common real-world attack chains (credential stuffing). SecureAuthX doesn't invent new cryptography to solve this — it applies **standard, well-understood primitives** (PBKDF2 via the browser's native Web Crypto API) in a careful way:

- The derived password's resistance to cracking comes from its **entropy** (long, random-looking, from a strong master password) — not from any custom hashing trick.
- Binding derivation to `window.location.hostname` (a browser-verified value, not user-typed text) gives phishing resistance: a lookalike domain produces a completely different derived password.

### v2 design change: domain-only derivation (no username, no rotation counter)

Per project spec, derivation is: **Master Password + Website Domain + Scrambled(user-typed password)** — nothing else. This was a deliberate spec decision, made with the trade-offs below understood and accepted:

- **No per-account separation.** Two accounts on the same domain (e.g. a personal and a work account on the same site) will get the *identical* derived password. If that's a problem for a given site, the workaround is typing a different "password to derive from" input per account — it's part of the derivation key material, so a different scramble input produces a different result even on the same domain.
- **No revocation without a full reset.** There's no counter to bump if a site is breached — the only way to change one site's derived password is to change the master password, which changes *every* site's derived password at once (see "Master Password" below).

### On the "deterministic scrambling" step

Before derivation, the user-typed password is deterministically rearranged (a Fisher–Yates shuffle seeded by its own length/uppercase/lowercase/digit/symbol counts — same input always scrambles the same way, no randomness). **This is included because the spec requires it, and it is documented honestly in code comments (`lib/crypto.js`) and here: it does not add cryptographic strength.** It's a public, deterministic transformation — PBKDF2 already achieves far stronger mixing via the avalanche effect, so scrambling before PBKDF2 is redundant from a security-analysis standpoint. Its actual security still rests entirely on PBKDF2 + master password strength. If asked in a defense, this is the honest answer — do not claim otherwise.

### Master password: one-time setup, no rotation

On first launch, the user sets a master password. **The extension never stores it, in any form** — not even encrypted. What it stores instead is a one-way PBKDF2 "verifier" (same pattern real password managers use for an unlock check): enough to confirm a *re-entered* master password is correct (catches typos before silently generating a wrong password), but not enough to reconstruct the master password itself. There is intentionally no in-app option to change or rotate it, per spec. The only reset path is wiping all local data and re-onboarding from scratch — which invalidates every previously-derived password's ability to be regenerated identically (since the new master password produces different outputs).

---

## Safe Browsing Assistant, Smart Warnings, and Visit Reputation

Beyond raw scores, SecureAuthX now translates results into plain language and surfaces them proactively:

- **Safe Browsing Assistant** — the Dashboard's "Explanation" section was replaced with a structured, plain-language summary: an emoji + headline ("This website may not be safe."), a bulleted list of specific checks (✓/⚠), and one line of concrete advice. Same underlying rule-based data as before (see honesty note below), just presented the way an ordinary user actually reads it.
- **Before-Login / Payment-Page Warning** — focusing a password field or a detected payment field (credit card number, CVV, expiry, etc.) triggers an inline banner with the same summary, labeled "Login Page" or "Payment Page."
- **Smart Warnings** — only "High Risk"/"Critical" results show a persistent, must-dismiss banner. Everything else shows a brief, auto-dismissing confirmation. This is deliberate: interrupting for every minor issue (a few trackers, one missing header) is what makes real users tune out security warnings entirely — so only genuinely serious findings (no HTTPS at all, an insecure login form, a lookalike domain) interrupt.
- **Proactive fake-login alert** — if the automatic per-page-load scan finds a critical issue, the banner appears immediately and unprompted, without waiting for the user to click into anything.
- **Visit reputation (local only)** — SecureAuthX now remembers how many times *this browser* has visited a domain and whether any past visit ever flagged a critical issue, shown as "You've visited this domain N times, no issues detected" or "First time here — be a little more cautious." This is purely local history, not an external reputation score, and is never sent anywhere.

### Two real bugs found and fixed while building this

1. **Trust score could be misleadingly "Safe" despite a fundamental failure.** `http://http.badssl.com/` (plain HTTP, by design — it's a deliberately-insecure test site) was scoring **Trust 80/Safe** before this fix. The cause: Trust was a straight average of Security/Privacy/Phishing, so a bad Security score (40, correctly reflecting "not HTTPS") got diluted by unrelated Privacy/Phishing scores that were fine (there were no trackers or forms to flag). **Fix:** `analysis.js` now applies a critical-issue *cap* — if the page isn't HTTPS at all, isn't using a secure login form, or looks like a lookalike domain, Trust is capped at 40/20/30 respectively regardless of how good the unrelated scores are. The same page now correctly scores **Trust 40/High Risk**. A single serious failure can no longer be averaged away by unrelated good news.
2. **The phishing-risk number itself had a related bug**: it was computed by regex-matching the *already-generated sentences* from the security report (e.g. checking if reason text matched `/plain HTTP/i`), and the actual HTTPS-missing sentence didn't match that pattern — so a plain-HTTP page scored a false 100/100 on phishing risk. **Fix:** `scoring.js` now returns structured boolean `flags` (`httpsMissing`, `insecureLoginForm`, `spoofDomain`, etc.) alongside its human-readable reasons, and `analysis.js` computes phishing risk directly from those flags — never by re-parsing generated text.
3. **Fake-login detection had a gap matching its own advertised example.** The typosquat heuristic explicitly *excluded* cases where a brand name appeared verbatim in the hostname (it was only built to catch homoglyph substitution like `faceb00k.com`), so `facebook-login.xyz` — the exact kind of fake-login example this feature is supposed to catch — wasn't flagged. **Fix:** added a small real-domain allowlist per brand (`BRAND_REAL_DOMAINS` in `scoring.js`); a hostname is now flagged if it mentions a brand name (verbatim or via homoglyph) and ISN'T that brand's actual domain or a subdomain of it. Verified against 8 cases including legitimate subdomains (`www.facebook.com`, `m.facebook.com`) to confirm no false positives on real brand domains.

Payment-page protection and standalone fake-login/before-login alerts share the same underlying banner and summary infrastructure described above — see `content.js`'s `renderSafetyBanner` and `isPaymentField`.

## Multi-Master-Profile System & Session Unlocking

Instead of a single master password, SecureAuthX supports multiple independent **Master Profiles** (e.g. "Personal", "Work", "University"), each with its own master password, its own PBKDF2 verifier, and its own independent unlock session. **The password derivation algorithm itself is completely unchanged** — profiles only change *which* master password feeds into the same `deriveSitePassword(masterPassword, domain, rawPassword)` function.

- **Never stored:** any profile's plaintext master password. Only `{ saltHex, verifierHex }` per profile, same one-way verifier pattern as before.
- **Session unlock:** checking "Unlock for this browser session" caches the plaintext master password **only in memory, inside the background service worker** — never in `browser.storage`. It's cleared on Lock Session, after 30 minutes of inactivity (reset on each use), or when the browser/service worker restarts.
- **Independent sessions:** unlocking "Personal" has no effect on "Work" or any other profile's lock state — verified in testing (see below).
- **Backward compatible:** an existing single-profile installation is automatically migrated into a profile named "Personal" on first run after update — no need to re-create the master password, and every previously-derived password for that profile still regenerates identically.

### Honest limitation: MV3 service worker lifetime

Chrome (and other Chromium-based browsers) can terminate an MV3 background service worker during idle periods, which would wipe the in-memory session Map **before** the 30-minute inactivity window elapses. This is a platform constraint, not a bug: it means a session might lock itself somewhat earlier than 30 minutes in practice, especially on Chrome. It degrades **safely** — the profile just shows "locked" sooner, never a security leak — but it's worth knowing before demoing a long-idle scenario. A `chrome.alarms`-based keep-alive (`background.js`) reduces how often this happens by periodically waking the service worker, but cannot fully eliminate it, since alarms can trigger code but can't preserve JS variable state across an actual service-worker restart. If asked in a defense, this is the honest, accurate answer.

## Threat Model

| Threat | Mitigated? | How |
|---|---|---|
| Password reuse across sites | ✅ Yes, at the domain level | Derivation is bound to `hostname`, so different domains get different outputs. Same-domain multi-account reuse is NOT separated (see "domain-only derivation" above) |
| Weak / dictionary-guessable passwords | ✅ Yes | Derived output is high-entropy by construction |
| DB leak → offline cracking | ✅ Yes, for derived passwords | No dictionary of "things humans typed" contains a random 20-char derived string |
| Phishing (lookalike domain) | ✅ Partially | Derivation binds to real hostname; a heuristic hostname check also flags common lookalikes |
| Network interception (MITM) | ❌ Out of scope | This is TLS's job. If TLS is broken, nothing at the application layer saves you — see note below |
| One master password compromised | ⚠️ Cascades, and cannot be rotated | If an attacker recovers your master password, **every site's derived password can be regenerated**, and there is no in-app rotation — the only recovery is a full reset (see above). This is a stricter trade-off than the earlier per-site-counter design, made deliberately per spec. **Use a genuinely strong, unique master password — write it down and store it somewhere safe, since there is no recovery.** |
| Master password typo silently producing a wrong password | ✅ Yes | A local, non-recoverable PBKDF2 verifier checks re-entered master passwords before deriving, and warns on mismatch |
| Same-domain multi-account collision | ❌ Not mitigated (by spec) | Documented trade-off of domain-only derivation |
| OS-level compromise, malware, keyloggers | ❌ Out of scope | No browser extension can fix a compromised OS |
| Full phishing / ML-based threat detection | ❌ Out of scope (this build) | See Scope Decisions |

**On interception specifically:** an earlier design idea explored sending a client-side hash of the password instead of the plaintext, on the theory that "no dictionary can crack a hash." This was rejected during design: a captured hash is just as replayable as a captured plaintext password ("pass-the-hash"), so it doesn't address interception at all, and it doesn't stop dictionary attacks either since an attacker can hash their own guesses the same way. That's why this build leans entirely on TLS for transport security and focuses its own value on entropy + origin-binding instead.

---

## Scope Decisions

The original spec (7 modules + AI assistant + full dashboard + 5-browser test matrix) is closer to 3–4 separate major projects. Building all of it shallowly would be worse for a demo/defense than building a core well. What's implemented vs. deferred:

**Implemented (working code in this repo):**
- Module 1 — Site-specific password derivation (domain + master password + deterministic scrambling)
- Module 2 — Reuse detection (local comparison hashes only)
- Module 3 — Password strength analyzer
- Module 6 — Full website security/privacy Dashboard: security score, privacy score, phishing risk, overall trust score, security headers report, cookie inspector, tracker detection (static local signature list), permission/privacy-access monitoring (geolocation/camera/microphone/notifications/clipboard/fullscreen), browser fingerprinting indicators (canvas/WebGL/audio/timezone/locale/font enumeration), network activity summary, and a rule-based (non-LLM) explanation — see honesty note below
- Automatic, no-interaction analysis on every page load, with a colored trust-score badge on the extension icon
- Master password onboarding (one-time, no in-app rotation) with typo-detecting verifier
- In-page icon on password fields for one-click inline derivation

**Deferred — documented as Future Scope, not implemented:**
- Module 4 — Full phishing detection beyond the heuristic typosquat/lookalike + form-target checks already included (a real system needs a domain-reputation feed or trained model)
- Module 5 — Deep tracker/fingerprinting research (current tracker list is a maintained static signature set, not a live feed; fingerprinting detection covers the common techniques — canvas, WebGL, audio, timezone, locale, font enumeration — but isn't exhaustive)
- Module 7 — Safe Inspection Mode (depends on Modules 4+5 being more complete first)
- A live LLM-backed "AI Assistant" (current "Explanation" text is rule-based templating, clearly labeled as such in the UI — see below)
- Full separate Dashboard tab/page with history charts and report export
- Cloud sync, passkey support, mobile companion, enterprise dashboard

If asked in a defense why these are excluded: each requires either external threat-intel data, a trained model, or an external API key to be *honest* about its accuracy or to function at all — shipping a fake or trivial version would be worse than clearly scoping them as future work.

### On the "AI Assistant" / explanation text

The spec calls for an "AI Security Assistant." What's implemented is a **rule-based, fully local, deterministic template generator** (`lib/analysis.js` → `generateExplanation()`) that turns the top-severity findings into a plain-language sentence. It is explicitly labeled "Explanation (rule-based, local — not a live AI call)" in the popup UI, rather than being presented as AI-generated, because it isn't. Wiring this to a real LLM call (e.g. sending the same JSON report to the Anthropic API and asking for a summary) is a small, well-scoped future step — the report object already has the exact shape an LLM prompt would need — but doing so requires the user to supply an API key, which isn't appropriate to bake into a demo build by default.

---

## Architecture

```
secureauthx/
├── manifest.json          # MV3 manifest
├── lib/
│   ├── crypto.js          # PBKDF2 derivation + scrambling + site-safe formatting + reuse hash + master verifier
│   ├── strength.js        # Offline password strength heuristics
│   ├── scoring.js         # Security score (HTTPS, forms, cookies, headers, typosquat heuristic)
│   ├── trackers.js        # Static tracker signature database + matcher
│   ├── analysis.js        # Aggregates everything into the Dashboard's 4 headline scores + explanation
│   ├── storage.js         # Whitelist wrapper around browser.storage.local
│   └── vendor/
│       └── browser-polyfill.js   # Mozilla's webextension-polyfill for Chrome/Firefox parity
├── background/
│   └── background.js      # Service worker: message routing, webRequest header/traffic capture, cookie inspection, badge coloring, auto-analysis on page load
├── content/
│   ├── page-hook.js        # MAIN-world script: detects fingerprinting + sensitive-permission API calls
│   └── content.js          # ISOLATED-world script: login form detection, signal gathering, password autofill, in-page derive icon
└── popup/
    ├── popup.html
    ├── popup.css
    └── popup.js
```

### Why a separate MAIN-world script (`page-hook.js`)?

Content scripts run in an "isolated world" — they share the page's DOM but not its JavaScript objects. Wrapping `window.AudioContext` from the normal content script would only affect the content script's own view of that object, not the page's, so it would never actually observe the page using it. `page-hook.js` is declared with `"world": "MAIN"` in `manifest.json`, which runs it in the page's own JS realm so the wrapping is real. It communicates findings (never data — just "canvas fingerprinting technique used", not what was drawn) to `content.js` via a DOM `CustomEvent`, which is a standard, safe pattern for MAIN↔ISOLATED world communication.

### New permissions and why

- **`webRequest`** — needed to read response headers (security headers report) and observe sub-resource request counts/domains (network activity summary). This is read-only observation; nothing is blocked or modified.
- **`tabs`** — needed for `tabs.onUpdated` (to trigger automatic analysis on page load) and to read tab URLs for domain-based logic.
- **`alarms`** — used only for the session keep-alive alarm described above; not used for scheduling anything user-facing.

### Data flow — password generation

```
User types master password (in-memory only, in popup.js)
        │
        ▼
crypto.js: PBKDF2(master, salt = origin+username+counter, 250k iterations)
        │
        ▼
formatAsPassword(): shape raw bytes into a valid site password
        │
        ├──► displayed in popup, optionally copied
        ├──► sent to content.js to fill the focused password field
        └──► reuseComparisonHash() computed and checked against storage.js
                (only the hash is stored — never the derived password,
                 never the master password)
```

### What's stored in `browser.storage.local` (see storage.js for the enforced whitelist)

- Site metadata: `{ origin, username, counter, algoVersion, savedAt }`
- Reuse-detection hashes: `SHA-256("secureauthx:reuse:v1:" + derivedPassword)` mapped to a list of origins
- Settings (theme, derived length, risk threshold)
- Cached site-score reports

**Never stored:** master password, derived passwords, plaintext of anything typed into a password field.

---

## Installation (development / unpacked)

### Firefox
1. Go to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `manifest.json` from this folder

### Chrome / Edge / Brave
1. Go to `chrome://extensions` (or `edge://extensions`, `brave://extensions`)
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select this folder

### Opera
1. Go to `opera://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select this folder

---

## Known cross-browser caveat

Firefox's support for `"background": { "service_worker": ..., "type": "module" }` (MV3) landed later than Chrome's and behaves slightly differently across Firefox versions. If you hit background-script issues specifically in Firefox, the fallback is `"background": { "scripts": ["lib/vendor/browser-polyfill.js", "background/background.js"] }` (non-module, classic script) — this is a one-line manifest change and is a good thing to mention in a defense as a real cross-browser engineering trade-off you navigated.

---

## Security Notes for Presentation / Defense

- **Why PBKDF2 and not Argon2id for derivation?** PBKDF2 is natively available via `SubtleCrypto` in every target browser with no WASM dependency, which matters a lot for a "just works, no build pipeline" extension. Argon2id is more resistant to GPU/ASIC attacks and would be a reasonable upgrade path (documented as future work) using a WASM library, at the cost of a larger bundle and a build step.
- **Why SHA-256 (fast hash) for reuse detection instead of PBKDF2/Argon2id?** Slow KDFs defend against *offline* attacks on a *stored, leaked* secret. Reuse detection is a same-device, real-time comparison — there's no offline-attacker scenario to defend against here, so using a slow hash would only cost latency for no security benefit. Worth stating explicitly if asked, since it's a common point of confusion.
- **Why is the derived password formatted with a guaranteed-character-class step instead of just base64-encoding the raw bytes?** Because real sites require specific character classes (uppercase, digit, symbol) and this maximizes compatibility while staying fully deterministic from the same key material.
