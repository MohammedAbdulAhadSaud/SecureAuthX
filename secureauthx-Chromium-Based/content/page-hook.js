/**
 * SecureAuthX — page-hook.js  (runs in the PAGE's own JS realm — "MAIN" world)
 *
 * This script never reads or touches password fields, form data, or any
 * user-typed content. Its only job is to detect WHEN a page calls certain
 * browser APIs known to be used for fingerprinting or that require a
 * sensitive permission, and report that fact (not any data) to the
 * isolated content script via a DOM CustomEvent.
 *
 * Why a MAIN-world script is needed at all: the isolated content-script
 * world (content.js) shares the DOM but NOT the page's JS objects — so
 * wrapping `window.AudioContext` from content.js would only affect
 * content.js's own view of that object, not the page's. To actually
 * observe the page calling these APIs, the wrapping has to happen in the
 * page's own realm, which is what `"world": "MAIN"` in manifest.json does.
 *
 * Each signal type is only reported ONCE per page load (deduped) — this
 * is a presence/absence detector, not a full call logger.
 */

(function () {
  const seen = new Set();

  // Batch 3 fix (corrected): page-hook.js (MAIN world, document_start) can
  // dispatch a signal before content.js (isolated world, document_idle)
  // has attached its "sax:signal" listener -- a CustomEvent dispatched
  // with no listener attached is simply lost, not queued for later.
  //
  // An earlier version of this fix tried to bridge that gap with a
  // `window.__saxSignalBuffer` property. That does not work: MAIN and
  // isolated worlds share the DOM but have SEPARATE JavaScript global
  // objects, so a property written on one world's `window` is invisible
  // to the other world's `window` -- it is not a shared channel at all.
  //
  // The DOM itself, by contrast, genuinely is shared between the two
  // worlds (this is what makes the live CustomEvent dispatch below work
  // in the first place). So the catch-up mechanism here is a DOM
  // attribute on `document.documentElement` (present from document_start
  // onward, unlike `document.body`) rather than a JS global: every time a
  // NEW signal is recorded, the existing "category:technique" identifiers
  // already tracked in `seen` are serialized into that attribute. This
  // stores nothing beyond what the live event already carries -- no
  // arguments, values, or page content, ever.
  const SIGNAL_ATTR = "data-sax-signals";

  function report(category, technique) {
    const key = `${category}:${technique}`;
    if (seen.has(key)) return;
    seen.add(key);
    const detail = { category, technique };
    window.dispatchEvent(new CustomEvent("sax:signal", { detail }));
    try {
      document.documentElement.setAttribute(SIGNAL_ATTR, JSON.stringify(Array.from(seen)));
    } catch { /* never let instrumentation break the page */ }
  }

  function safeWrap(obj, prop, onCall) {
    if (!obj || !(prop in obj)) return;
    const original = obj[prop];
    if (typeof original !== "function") return;
    try {
      obj[prop] = function (...args) {
        // Batch 3: onCall also receives `this` (the calling object/element)
        // so call sites can inspect context (e.g. "is this canvas actually
        // attached to the visible page?") instead of only the arguments.
        // Existing callers that only take `args` are unaffected — the
        // extra parameter is simply ignored by them.
        try { onCall(args, this); } catch { /* never let instrumentation break the page */ }
        return original.apply(this, args);
      };
    } catch { /* some properties are non-configurable; skip silently */ }
  }

  function safeWrapGetter(proto, prop, onGet) {
    const desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.get) return;
    try {
      Object.defineProperty(proto, prop, {
        ...desc,
        get() {
          try { onGet(); } catch { /* ignore */ }
          return desc.get.call(this);
        },
      });
    } catch { /* ignore non-configurable */ }
  }

  // ---------------- Fingerprinting: Canvas (Batch 3: context-aware) ----------------
  //
  // Calling toDataURL()/getImageData() at all is completely ordinary —
  // chart libraries, image editors, screenshot tools, and QR-code
  // generators all do this on a normal, visible canvas the user can see.
  // That's not evidence of fingerprinting. The actual canvas-fingerprint
  // technique specifically renders to a canvas that is NEVER shown to the
  // user — detached from the document, hidden via CSS, or sized down to a
  // few pixels — purely so its pixel data can be read back and hashed.
  // Only that "hidden/offscreen canvas" pattern is reported now.
  //
  // Known limitation (documented, not fixed here): a legitimate app that
  // deliberately renders to an off-screen/tiny canvas for its own internal
  // processing (e.g. a thumbnail generator) before ever showing anything
  // would also match this heuristic. There is no way to distinguish that
  // from a real fingerprint canvas using only DOM attachment/size — this
  // is a heuristic proxy, not proof, same as the rest of this file.
  function looksLikeHiddenFingerprintCanvas(canvas) {
    if (!canvas || typeof canvas !== "object") return false;
    try {
      if (!document.contains(canvas)) return true; // never shown to the user at all
      const style = window.getComputedStyle ? window.getComputedStyle(canvas) : null;
      const hiddenByStyle =
        !!style && (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0);
      const tiny = (canvas.width || 0) <= 16 && (canvas.height || 0) <= 16;
      return hiddenByStyle || tiny;
    } catch {
      return false; // if we can't tell, don't guess — avoid a false positive
    }
  }

  if (window.HTMLCanvasElement) {
    safeWrap(HTMLCanvasElement.prototype, "toDataURL", (args, canvas) => {
      if (looksLikeHiddenFingerprintCanvas(canvas)) report("fingerprint", "canvasFingerprint");
    });
  }
  if (window.CanvasRenderingContext2D) {
    safeWrap(CanvasRenderingContext2D.prototype, "getImageData", (args, ctx) => {
      if (looksLikeHiddenFingerprintCanvas(ctx && ctx.canvas)) report("fingerprint", "canvasFingerprint");
    });
    // Font enumeration (Batch 4 Phase 2A: distinct-font-aware).
    //
    // Previously a coarse "more than 15 measureText() calls total" proxy
    // -- counted ANY canvas text measurement regardless of which font or
    // string was involved, so ordinary heavy canvas text use (paragraph/
    // word-wrap layout, chart labeling, rich-text editors) with many
    // calls in ONE font could false-positive identically to real font
    // probing. Real font enumeration specifically tries MANY DISTINCT
    // fonts while measuring the SAME (or a small handful of) test
    // string, comparing widths to detect which fonts are actually
    // installed. Only that shape is reported now.
    //
    // Data minimization: font names and measured strings are NEVER
    // stored as literal strings, not even internally -- only their hash
    // outputs (plain numbers, for distinctness bucketing only) ever
    // populate the sets below, and neither the hashes nor the originals
    // ever leave this closure. Only the fixed string "fontEnumeration"
    // (unchanged from before) ever reaches report().
    //
    // Known limitation (documented, not fixed here): a page using many
    // distinct fonts AND deliberately varying the measured string on
    // every call would evade the "<=3 distinct strings" condition below.
    // This is an honest, acknowledged gap in this heuristic, not a claim
    // that it's unbeatable -- consistent with every other heuristic in
    // this file.
    function cheapHash(str) {
      let h = 0;
      for (let i = 0; i < str.length; i++) {
        h = (h * 31 + str.charCodeAt(i)) | 0;
      }
      return h;
    }

    const FONT_ENUM_MAX_TRACKED_ENTRIES = 200; // bounds worst-case memory regardless of call volume
    const FONT_ENUM_DISTINCT_FONT_THRESHOLD = 15; // same numeric threshold as before, now applied to distinct fonts
    const FONT_ENUM_MAX_DISTINCT_STRINGS = 3;

    const distinctFontHashes = new Set();
    const distinctStringHashes = new Set();
    let fontEnumerationReported = false;

    safeWrap(CanvasRenderingContext2D.prototype, "measureText", (args, ctx) => {
      if (fontEnumerationReported) return; // already reported -- stop doing any further tracking work

      const text = typeof args[0] === "string" ? args[0] : "";
      const font = ctx && typeof ctx.font === "string" ? ctx.font : "";

      if (distinctFontHashes.size < FONT_ENUM_MAX_TRACKED_ENTRIES) distinctFontHashes.add(cheapHash(font));
      if (distinctStringHashes.size < FONT_ENUM_MAX_TRACKED_ENTRIES) distinctStringHashes.add(cheapHash(text));

      if (
        distinctFontHashes.size > FONT_ENUM_DISTINCT_FONT_THRESHOLD &&
        distinctStringHashes.size <= FONT_ENUM_MAX_DISTINCT_STRINGS
      ) {
        fontEnumerationReported = true;
        report("fingerprint", "fontEnumeration");
      }
    });
  }

  // ---------------- Fingerprinting: WebGL (Batch 3: argument-aware) ----------------
  //
  // getParameter()/getExtension() are called by literally every WebGL
  // application (any 3D scene, map, or game) on its very first frame, for
  // completely ordinary rendering setup and feature detection — calling
  // them at all proves nothing. The specific, well-documented
  // fingerprinting technique is requesting the WEBGL_debug_renderer_info
  // extension and then reading the UNMASKED_VENDOR_WEBGL /
  // UNMASKED_RENDERER_WEBGL parameters it exposes, which reveal the real
  // GPU vendor/model string the browser otherwise deliberately hides for
  // privacy. Only that specific pattern is reported now; ordinary
  // getParameter/getExtension calls for anything else are ignored.
  const UNMASKED_VENDOR_WEBGL = 0x9245;
  const UNMASKED_RENDERER_WEBGL = 0x9246;

  [window.WebGLRenderingContext, window.WebGL2RenderingContext].forEach((ctx) => {
    if (!ctx) return;
    safeWrap(ctx.prototype, "getParameter", (args) => {
      const pname = args[0];
      if (pname === UNMASKED_VENDOR_WEBGL || pname === UNMASKED_RENDERER_WEBGL) {
        report("fingerprint", "webglDebugInfo");
      }
    });
    safeWrap(ctx.prototype, "getExtension", (args) => {
      const name = String(args[0] || "").toLowerCase();
      if (name === "webgl_debug_renderer_info") {
        report("fingerprint", "webglDebugInfo");
      }
    });
    // Batch 4 Phase 2A: getSupportedExtensions() takes no arguments, so
    // unlike getParameter/getExtension above there is nothing to inspect
    // in the call itself — the call existing at all is the signal. This
    // method is rarer in ordinary feature-detection than checking one or
    // two named extensions (the getExtension case already handled
    // above), so it is tracked as its own, separate technique rather than
    // folded into webglDebugInfo. Only the fixed technique-name string
    // ever leaves this hook — the returned extension list itself is never
    // read, stored, or inspected here.
    safeWrap(ctx.prototype, "getSupportedExtensions", () => {
      report("fingerprint", "webglExtensionEnumeration");
    });
  });

  // ---------------- Fingerprinting: Audio (Batch 3: pattern-aware) ----------------
  //
  // Merely constructing an AudioContext/OfflineAudioContext is completely
  // ordinary — games, video calls, music players, and synth demos all do
  // this — so construction alone is no longer reported (this also removes
  // the previous global-constructor override, which was itself a page-
  // breakage risk: replacing window.AudioContext entirely could break
  // `instanceof AudioContext` checks against an already-cached reference).
  //
  // The actual audio-fingerprinting technique specifically renders a
  // signal through an OfflineAudioContext and reads back the resulting
  // buffer's samples to hash them. Only that render-then-read pattern is
  // reported now: we track buffers produced by OfflineAudioContext's
  // startRendering(), and report only when one of those specific buffers
  // is later read via getChannelData().
  //
  // Known limitation (documented, not fixed here): a legitimate audio-
  // processing app that renders offline and then genuinely inspects the
  // samples (e.g. a loudness/waveform analysis tool) would also match
  // this pattern — there is no way to prove *intent* from the API calls
  // alone. This is narrower and far less prone to false positives than
  // the previous "any AudioContext" check, but it is still a heuristic.
  const offlineRenderedBuffers = new WeakSet();

  if (window.OfflineAudioContext) {
    const proto = OfflineAudioContext.prototype;
    const originalStartRendering = proto.startRendering;
    if (typeof originalStartRendering === "function") {
      try {
        proto.startRendering = function (...args) {
          const resultPromise = originalStartRendering.apply(this, args);
          if (resultPromise && typeof resultPromise.then === "function") {
            resultPromise.then(
              (buffer) => {
                try { if (buffer) offlineRenderedBuffers.add(buffer); } catch { /* ignore */ }
              },
              () => { /* rendering failed/aborted — nothing to track */ }
            );
          }
          return resultPromise;
        };
      } catch { /* non-configurable in some engines; skip silently */ }
    }
  }

  if (window.AudioBuffer) {
    safeWrap(AudioBuffer.prototype, "getChannelData", (args, buffer) => {
      if (offlineRenderedBuffers.has(buffer)) {
        report("fingerprint", "audioFingerprint");
      }
    });
  }

  // ---------------- Fingerprinting: Client Hints (Batch 4 Phase 2A) ----------------
  //
  // navigator.userAgentData exposes low-entropy fields (brands, mobile,
  // platform) synchronously and always -- reading those is extremely
  // common (feature-gating, analytics) and is NOT hooked here at all.
  // getHighEntropyValues() is the explicit, opt-in async call that can
  // reveal higher-entropy fields (device model, OS version, CPU
  // architecture/bitness, full version list). Only requesting SEVERAL of
  // those specific high-entropy fields together is reported -- a single
  // common field alone (e.g. just "platformVersion", used by ordinary
  // OS-targeted download pages) is left alone, since that's a genuinely
  // common, legitimate pattern on its own.
  //
  // Data minimization: only the requested FIELD NAMES (a fixed, small set
  // of enum-like strings such as "model"/"architecture") are ever
  // inspected here, and only to count how many recognized high-entropy
  // names were requested. The method's RETURN VALUE -- the actual
  // resolved device/OS values -- is never read, stored, or forwarded by
  // this hook at all. Only the fixed technique-name string ever leaves.
  const HIGH_ENTROPY_HINT_NAMES = [
    "model", "platformVersion", "architecture", "bitness",
    "fullVersionList", "uaFullVersion", "wow64", "formFactor",
  ];
  const HIGH_ENTROPY_HINT_THRESHOLD = 2;

  if (window.navigator && navigator.userAgentData) {
    const uaDataProto = Object.getPrototypeOf(navigator.userAgentData);
    if (uaDataProto) {
      safeWrap(uaDataProto, "getHighEntropyValues", (args) => {
        const requested = Array.isArray(args[0]) ? args[0] : [];
        const highEntropyCount = requested.filter((h) => HIGH_ENTROPY_HINT_NAMES.includes(h)).length;
        if (highEntropyCount >= HIGH_ENTROPY_HINT_THRESHOLD) {
          report("fingerprint", "clientHintsHighEntropy");
        }
      });
    }
  }

  // ---------------- Fingerprinting: timezone / locale ----------------
  if (window.Intl && Intl.DateTimeFormat) {
    safeWrap(Intl.DateTimeFormat.prototype, "resolvedOptions", () => report("fingerprint", "timezone"));
  }
  if (window.Navigator) {
    // Batch 3: `navigator.languages` (plural — the full ordered preference
    // list) is added alongside the existing singular `navigator.language`
    // hook. Both are reported under the SAME "locale" technique name
    // rather than a new one, so this only widens what's observed without
    // adding any new scoring weight — locale-based signals stay
    // informational-tier either way (see lib/analysis.js).
    safeWrapGetter(Navigator.prototype, "language", () => report("fingerprint", "locale"));
    safeWrapGetter(Navigator.prototype, "languages", () => report("fingerprint", "locale"));
  }

  // ---------------- Permissions: Geolocation ----------------
  if (navigator.geolocation) {
    safeWrap(navigator.geolocation, "getCurrentPosition", () => report("permission", "geolocation"));
    safeWrap(navigator.geolocation, "watchPosition", () => report("permission", "geolocation"));
  }

  // ---------------- Permissions: Camera / Microphone ----------------
  if (navigator.mediaDevices) {
    safeWrap(navigator.mediaDevices, "getUserMedia", (args) => {
      const constraints = args[0] || {};
      if (constraints.video) report("permission", "camera");
      if (constraints.audio) report("permission", "microphone");
      if (!constraints.video && !constraints.audio) report("permission", "camera");
    });
  }

  // ---------------- Permissions: Notifications ----------------
  if (window.Notification) {
    const OriginalNotification = window.Notification;
    try {
      window.Notification = function (...args) {
        report("permission", "notifications");
        return new OriginalNotification(...args);
      };
      window.Notification.prototype = OriginalNotification.prototype;
      window.Notification.requestPermission = function (...args) {
        report("permission", "notifications");
        return OriginalNotification.requestPermission(...args);
      };
      // Batch 3 fix: `Notification.permission` on the real API is a LIVE
      // getter that reflects the current permission state and can change
      // over the page's lifetime (e.g. right after the user responds to
      // the browser's permission prompt). The previous code copied it
      // once as a static value at hook-install time, which froze it
      // forever — any page checking `Notification.permission` after a
      // user grants/denies permission would see a stale value for the
      // rest of the page's life. Defining it as a live getter here keeps
      // it accurate without changing what's reported.
      try {
        Object.defineProperty(window.Notification, "permission", {
          configurable: true,
          enumerable: true,
          get() { return OriginalNotification.permission; },
        });
      } catch {
        // Fallback for engines that won't allow redefining this property
        // on the replacement constructor — keep the old (imperfect)
        // snapshot behavior rather than letting the whole override throw.
        window.Notification.permission = OriginalNotification.permission;
      }
    } catch { /* ignore */ }
  }

  // ---------------- Permissions: Clipboard ----------------
  if (navigator.clipboard) {
    safeWrap(navigator.clipboard, "readText", () => report("permission", "clipboard"));
    safeWrap(navigator.clipboard, "writeText", () => report("permission", "clipboard"));
  }

  // ---------------- Permissions: Fullscreen ----------------
  if (window.Element) {
    safeWrap(Element.prototype, "requestFullscreen", () => report("permission", "fullscreen"));
  }
})();
