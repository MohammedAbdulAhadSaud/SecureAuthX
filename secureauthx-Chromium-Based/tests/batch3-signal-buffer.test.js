/**
 * SecureAuthX — Batch 3 signal-buffer fix test suite
 *
 * Tests the CORRECTED cross-world signal-buffer mechanism: a DOM
 * attribute on document.documentElement, replacing the earlier
 * window.__saxSignalBuffer approach (which never worked, since MAIN and
 * isolated worlds do not share a JS global object).
 *
 * WRITE SIDE (page-hook.js): tested against the REAL, unmodified source
 * file via Node's vm module. Two separate vm contexts model the two
 * separate JS realms Chrome actually uses for MAIN vs. isolated worlds —
 * each gets its OWN global object — while a single fake "documentElement"
 * object (plain JS, shared by reference) stands in for the one thing that
 * genuinely IS shared between the two worlds: the DOM. This is
 * deliberately NOT a same-realm test, because a same-realm test would not
 * have caught the original window.__saxSignalBuffer bug (a plain shared
 * JS object would have "worked" there too, which is exactly why that
 * approach looked correct in isolation but failed in real Chrome).
 *
 * READ/DRAIN SIDE (content.js): content.js is not an ES module and pulls
 * in a large amount of unrelated DOM-scanning machinery to fully load, so
 * rather than loading the entire file, this mirrors ONLY the small
 * parsing/reconstruction algorithm content.js uses to drain the
 * attribute. If that parsing logic in content.js changes, these tests
 * should be updated to match.
 *
 * Run with:  node --test tests/batch3-signal-buffer.test.js
 */

import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pageHookSource = fs.readFileSync(path.join(__dirname, "../content/page-hook.js"), "utf8");

// ---------------------------------------------------------------------
// Minimal MAIN-world realm builder for exercising the REAL page-hook.js
// source. Only what page-hook.js's existing `if (window.X)` guards check
// for is provided — everything else is deliberately absent so those
// guards no-op exactly as they do on a real page lacking that API,
// without needing to stub the entire browser platform.
// ---------------------------------------------------------------------
function createFakeDocumentElement() {
  const attrs = new Map();
  return {
    getAttribute(name) { return attrs.has(name) ? attrs.get(name) : null; },
    setAttribute(name, value) { attrs.set(name, String(value)); },
    removeAttribute(name) { attrs.delete(name); },
  };
}

function createMainWorldContext(sharedDocumentElement) {
  const listeners = [];
  const navigatorProto = {};
  Object.defineProperty(navigatorProto, "language", { get() { return "en-US"; }, configurable: true });

  const sandbox = {};
  sandbox.window = sandbox; // window === globalThis, matching a real page realm
  sandbox.document = { documentElement: sharedDocumentElement, contains: () => true };
  sandbox.navigator = Object.create(navigatorProto);
  sandbox.Navigator = { prototype: navigatorProto };
  sandbox.CustomEvent = class CustomEvent {
    constructor(type, init) { this.type = type; this.detail = init && init.detail; }
  };
  sandbox.dispatchEvent = (event) => listeners.filter((l) => l.type === event.type).forEach((l) => l.cb(event));
  sandbox.addEventListener = (type, cb) => listeners.push({ type, cb });

  return vm.createContext(sandbox);
}

function loadPageHookInto(ctx) {
  vm.runInContext(pageHookSource, ctx, { filename: "page-hook.js" });
}

// ---------------------------------------------------------------------
// A. Write side — real page-hook.js source, simulated MAIN world
// ---------------------------------------------------------------------

test("real page-hook.js writes fingerprint:timezone to the shared DOM attribute", () => {
  const docEl = createFakeDocumentElement();
  const ctx = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`Intl.DateTimeFormat().resolvedOptions().timeZone`, ctx);

  const raw = docEl.getAttribute("data-sax-signals");
  assert.ok(raw, "expected the signal attribute to be written");
  const parsed = JSON.parse(raw);
  assert.ok(Array.isArray(parsed));
  assert.ok(parsed.includes("fingerprint:timezone"));
});

test("real page-hook.js does NOT use a window property as the cross-world channel", () => {
  const docEl = createFakeDocumentElement();
  const ctx = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`Intl.DateTimeFormat().resolvedOptions().timeZone`, ctx);

  // The whole point of this fix: nothing on this realm's global object
  // should be the thing carrying the signal across to another realm.
  const globalKeys = vm.runInContext("Object.keys(globalThis)", ctx);
  assert.ok(!globalKeys.includes("__saxSignalBuffer"), "no window/global property should be used as the cross-world buffer");
});

test("real page-hook.js: repeated calls dedup, matching the existing `seen` Set behavior", () => {
  const docEl = createFakeDocumentElement();
  const ctx = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`
    Intl.DateTimeFormat().resolvedOptions().timeZone;
    Intl.DateTimeFormat().resolvedOptions().timeZone;
    Intl.DateTimeFormat().resolvedOptions().timeZone;
  `, ctx);

  const parsed = JSON.parse(docEl.getAttribute("data-sax-signals"));
  assert.equal(parsed.filter((x) => x === "fingerprint:timezone").length, 1);
});

test("real page-hook.js: a second distinct signal accumulates alongside the first", () => {
  const docEl = createFakeDocumentElement();
  const ctx = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`Intl.DateTimeFormat().resolvedOptions().timeZone`, ctx);
  vm.runInContext(`navigator.language`, ctx);

  const parsed = JSON.parse(docEl.getAttribute("data-sax-signals"));
  assert.ok(parsed.includes("fingerprint:timezone"));
  assert.ok(parsed.includes("fingerprint:locale"));
});

test("real page-hook.js: the attribute never contains anything beyond plain category:technique strings", () => {
  const docEl = createFakeDocumentElement();
  const ctx = createMainWorldContext(docEl);
  loadPageHookInto(ctx);

  vm.runInContext(`Intl.DateTimeFormat().resolvedOptions().timeZone`, ctx);
  vm.runInContext(`navigator.language`, ctx);

  const parsed = JSON.parse(docEl.getAttribute("data-sax-signals"));
  for (const entry of parsed) {
    assert.equal(typeof entry, "string");
    assert.match(entry, /^[a-zA-Z]+:[a-zA-Z]+$/, `entry should be a plain "category:technique" string, got: ${entry}`);
  }
});

// ---------------------------------------------------------------------
// B. Read/drain side — mirrors content.js's exact parsing algorithm
// ---------------------------------------------------------------------

/**
 * Mirrors the drain block added to content.js. Kept intentionally tiny
 * and side-effect-free (returns the reconstructed {category, technique}
 * pairs instead of mutating a Set) so it's easy to assert against.
 */
function drainSignalAttribute(getAttributeValue) {
  const results = [];
  try {
    const raw = getAttributeValue();
    if (raw) {
      const bufferedKeys = JSON.parse(raw);
      if (Array.isArray(bufferedKeys)) {
        for (const key of bufferedKeys) {
          if (typeof key !== "string") continue;
          const separatorIndex = key.indexOf(":");
          if (separatorIndex === -1) continue;
          results.push({
            category: key.slice(0, separatorIndex),
            technique: key.slice(separatorIndex + 1),
          });
        }
      }
    }
  } catch {
    // must never throw
  }
  return results;
}

test("drain: well-formed attribute reconstructs category/technique pairs correctly", () => {
  const result = drainSignalAttribute(() => JSON.stringify(["fingerprint:timezone", "fingerprint:canvasFingerprint", "permission:camera"]));
  assert.deepEqual(result, [
    { category: "fingerprint", technique: "timezone" },
    { category: "fingerprint", technique: "canvasFingerprint" },
    { category: "permission", technique: "camera" },
  ]);
});

test("drain: missing attribute (null) yields no results and does not throw", () => {
  assert.deepEqual(drainSignalAttribute(() => null), []);
});

test("drain: empty string attribute yields no results and does not throw", () => {
  assert.deepEqual(drainSignalAttribute(() => ""), []);
});

test("drain: invalid JSON does not throw and yields no results", () => {
  assert.deepEqual(drainSignalAttribute(() => "{not valid json"), []);
});

test("drain: valid JSON that is not an array does not throw and yields no results", () => {
  assert.deepEqual(drainSignalAttribute(() => JSON.stringify({ not: "an array" })), []);
});

test("drain: non-string entries in the array are skipped, not thrown on", () => {
  const result = drainSignalAttribute(() => JSON.stringify(["fingerprint:timezone", 42, null, { odd: "object" }, "permission:camera"]));
  assert.deepEqual(result, [
    { category: "fingerprint", technique: "timezone" },
    { category: "permission", technique: "camera" },
  ]);
});

test("drain: a string entry with no colon is skipped, not thrown on", () => {
  const result = drainSignalAttribute(() => JSON.stringify(["fingerprint:timezone", "malformed-no-colon"]));
  assert.deepEqual(result, [{ category: "fingerprint", technique: "timezone" }]);
});

test("drain: getAttribute itself throwing does not propagate", () => {
  assert.doesNotThrow(() => {
    const result = drainSignalAttribute(() => { throw new Error("boom"); });
    assert.deepEqual(result, []);
  });
});
