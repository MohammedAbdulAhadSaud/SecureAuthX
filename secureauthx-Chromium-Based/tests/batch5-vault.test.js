/** SecureAuthX — Phase 3B vault unit tests. Run with: node --test tests/batch5-vault.test.js */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deriveVaultKey, generateVaultSalt, encryptVaultPayload, decryptVaultPayload, computeMasterVerifier } from "../lib/crypto.js";
import { getVaultRecord, setVaultRecord, deleteVaultRecord } from "../lib/storage.js";
import {
  createEmptyVaultPayload, loadVault, saveVault, addItem, updateItem, deleteItem,
  findItemsForSite, searchItems, toListSummary, generateRandomPassword,
  buildExportPayload, validateImportPayload, MAX_ITEMS, VAULT_VERSION,
} from "../lib/vault.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => fs.readFileSync(path.join(__dirname, rel), "utf8");
const hexToBytes = (hex) => Uint8Array.from(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));

let fakeData;
test.beforeEach(() => {
  fakeData = {};
  globalThis.browser = { storage: { local: {
    get: (key) => Promise.resolve(key in fakeData ? { [key]: fakeData[key] } : {}),
    set: (obj) => { Object.assign(fakeData, obj); return Promise.resolve(); },
    remove: (key) => { delete fakeData[key]; return Promise.resolve(); },
  } } };
});

/* ======================= 3B-1: crypto ======================= */

test("different passwords -> different keys (cross-decrypt fails)", async () => {
  const salt = generateVaultSalt();
  const keyA = await deriveVaultKey("pw one", salt);
  const keyB = await deriveVaultKey("pw two", salt);
  const enc = await encryptVaultPayload(keyA, { v: 1 });
  await assert.rejects(() => decryptVaultPayload(keyB, enc.ivHex, enc.ciphertextHex));
});

test("different salts -> different keys for the same password", async () => {
  const saltA = generateVaultSalt(), saltB = generateVaultSalt();
  assert.notEqual(saltA, saltB);
  const keyA = await deriveVaultKey("same pw", saltA);
  const keyB = await deriveVaultKey("same pw", saltB);
  const enc = await encryptVaultPayload(keyA, { v: 1 });
  await assert.rejects(() => decryptVaultPayload(keyB, enc.ivHex, enc.ciphertextHex));
});

test("vault key is non-extractable", async () => {
  const key = await deriveVaultKey("pw", generateVaultSalt());
  assert.equal(key.extractable, false);
  await assert.rejects(() => crypto.subtle.exportKey("raw", key));
});

test("the stored master verifier cannot decrypt the vault (verifier != vault key)", async () => {
  const salt = generateVaultSalt();
  const vaultKey = await deriveVaultKey("shared pw", salt);
  const enc = await encryptVaultPayload(vaultKey, { items: [] });
  const { verifierHex } = await computeMasterVerifier("shared pw", salt);
  const verifierAsKey = await crypto.subtle.importKey("raw", hexToBytes(verifierHex), { name: "AES-GCM" }, false, ["decrypt"]);
  await assert.rejects(() => crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(enc.ivHex) }, verifierAsKey, hexToBytes(enc.ciphertextHex)));
});

test("encrypt/decrypt round trip preserves the payload exactly", async () => {
  const key = await deriveVaultKey("pw", generateVaultSalt());
  const payload = { version: 1, items: [{ id: "a", site: "example.com", secret: "hunter2" }] };
  const { ivHex, ciphertextHex } = await encryptVaultPayload(key, payload);
  assert.deepEqual(await decryptVaultPayload(key, ivHex, ciphertextHex), payload);
});

test("fresh 96-bit IV every encryption; same key + plaintext -> different ciphertext", async () => {
  const key = await deriveVaultKey("pw", generateVaultSalt());
  const a = await encryptVaultPayload(key, { v: 1 });
  const b = await encryptVaultPayload(key, { v: 1 });
  assert.equal(a.ivHex.length, 24);
  assert.notEqual(a.ivHex, b.ivHex);
  assert.notEqual(a.ciphertextHex, b.ciphertextHex);
});

test("tampered ciphertext is rejected (AES-GCM authentication)", async () => {
  const key = await deriveVaultKey("pw", generateVaultSalt());
  const { ivHex, ciphertextHex } = await encryptVaultPayload(key, { v: 1 });
  const tampered = ciphertextHex.slice(0, -2) + (ciphertextHex.slice(-2) === "00" ? "01" : "00");
  await assert.rejects(() => decryptVaultPayload(key, ivHex, tampered));
});

test("tampered IV is rejected", async () => {
  const key = await deriveVaultKey("pw", generateVaultSalt());
  const { ivHex, ciphertextHex } = await encryptVaultPayload(key, { v: 1 });
  const badIv = ivHex.slice(0, -2) + (ivHex.slice(-2) === "00" ? "01" : "00");
  await assert.rejects(() => decryptVaultPayload(key, badIv, ciphertextHex));
});

/* ======================= 3B-1: storage ======================= */

test("storage persists exactly the record it is given, and nothing else", async () => {
  const record = { version: 1, saltHex: "aa", ivHex: "bb", ciphertextHex: "cc" };
  await setVaultRecord("p1", record);
  assert.deepEqual(await getVaultRecord("p1"), record);
  assert.equal(await getVaultRecord("nope"), null);
  await deleteVaultRecord("p1");
  assert.equal(await getVaultRecord("p1"), null);
});

test("saveVault persists NO plaintext credential data, NO master password anywhere in storage", async () => {
  const masterPassword = "Very-Unique-Master-Password-ZZ9";
  const { payload, saltHex } = await loadVault("p2", masterPassword);
  addItem(payload, { site: "example.com", username: "alice@example.com", secret: "UniqueSecretValue-QQ7", accountLabel: "Work", notes: "UniqueNoteValue-KK3" });
  await saveVault("p2", masterPassword, saltHex, payload);

  const everything = JSON.stringify(fakeData);
  for (const forbidden of [masterPassword, "UniqueSecretValue-QQ7", "alice@example.com", "UniqueNoteValue-KK3", "Work"]) {
    assert.ok(!everything.includes(forbidden), `storage must not contain "${forbidden}"`);
  }
  const record = fakeData.sax_vault.p2;
  assert.deepEqual(Object.keys(record).sort(), ["ciphertextHex", "ivHex", "saltHex", "version"]);
});

test("full load/save round trip restores items", async () => {
  const { payload, saltHex } = await loadVault("p3", "master pw");
  addItem(payload, { site: "example.com", secret: "s3cret!" });
  await saveVault("p3", "master pw", saltHex, payload);
  const reloaded = await loadVault("p3", "master pw");
  assert.equal(reloaded.isNew, false);
  assert.equal(reloaded.payload.items[0].secret, "s3cret!");
});

test("every save uses a new IV and keeps the same salt", async () => {
  const { payload, saltHex } = await loadVault("p4", "pw");
  addItem(payload, { site: "a.com", secret: "x" });
  await saveVault("p4", "pw", saltHex, payload);
  const first = await getVaultRecord("p4");
  await saveVault("p4", "pw", saltHex, payload);
  const second = await getVaultRecord("p4");
  assert.notEqual(first.ivHex, second.ivHex);
  assert.equal(first.saltHex, second.saltHex);
});

test("a new vault gets a random salt (not static)", async () => {
  const a = await loadVault("pa", "pw");
  const b = await loadVault("pb", "pw");
  assert.notEqual(a.saltHex, b.saltHex);
  assert.equal(a.isNew, true);
});

test("wrong master password rejects loadVault and returns no contents", async () => {
  const { payload, saltHex } = await loadVault("p5", "right pw");
  addItem(payload, { site: "example.com", secret: "topsecret" });
  await saveVault("p5", "right pw", saltHex, payload);
  await assert.rejects(() => loadVault("p5", "wrong pw"));
});

test("version handling: unsupported-version or malformed decrypted payload is rejected", async () => {
  const salt = generateVaultSalt();
  const key = await deriveVaultKey("pw", salt);
  for (const [i, bad] of [{ version: 999, items: [] }, { version: 1 }, { version: 1, items: "x" }].entries()) {
    const { ivHex, ciphertextHex } = await encryptVaultPayload(key, bad);
    await setVaultRecord(`pv${i}`, { version: 1, saltHex: salt, ivHex, ciphertextHex });
    await assert.rejects(() => loadVault(`pv${i}`, "pw"));
  }
});

/* ======================= 3B-3: CRUD ======================= */

test("addItem validates input and normalizes site", () => {
  const payload = createEmptyVaultPayload();
  assert.equal(addItem(payload, { site: "", secret: "x" }).ok, false);
  assert.equal(addItem(payload, { site: "a.com", secret: "" }).ok, false);
  assert.equal(addItem(payload, { site: "a.com", secret: "x".repeat(513) }).ok, false);
  assert.equal(addItem(payload, { site: "a.com", secret: "x", notes: "n".repeat(2001) }).ok, false);
  assert.equal(addItem(payload, undefined).ok, false);
  const r = addItem(payload, { site: "  Example.COM  ", secret: "x" });
  assert.equal(r.ok, true);
  assert.equal(r.item.site, "example.com");
  assert.equal(payload.items.length, 1);
});

test("items get stable unique IDs, even for identical content (no duplicate IDs)", () => {
  const payload = createEmptyVaultPayload();
  const a = addItem(payload, { site: "a.com", username: "u", secret: "x" }).item;
  const b = addItem(payload, { site: "a.com", username: "u", secret: "x" }).item;
  assert.notEqual(a.id, b.id);
  assert.equal(new Set(payload.items.map((i) => i.id)).size, 2);
});

test("multiple accounts for the same site coexist", () => {
  const payload = createEmptyVaultPayload();
  addItem(payload, { site: "a.com", username: "alice", secret: "1", accountLabel: "Personal" });
  addItem(payload, { site: "a.com", username: "bob", secret: "2", accountLabel: "Work" });
  assert.equal(findItemsForSite(payload, "a.com").length, 2);
});

test("MAX_ITEMS is enforced", () => {
  const payload = createEmptyVaultPayload();
  for (let i = 0; i < MAX_ITEMS; i++) payload.items.push({ id: String(i), site: `s${i}.com`, secret: "x" });
  assert.equal(addItem(payload, { site: "over.com", secret: "x" }).ok, false);
});

test("updateItem updates fields + updatedAt, re-validates, and errors on unknown id", async () => {
  const payload = createEmptyVaultPayload();
  const { item } = addItem(payload, { site: "a.com", secret: "old" });
  const created = item.createdAt;
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(updateItem(payload, item.id, { secret: "new", notes: "n" }).ok, true);
  assert.equal(payload.items[0].secret, "new");
  assert.equal(payload.items[0].createdAt, created);
  assert.ok(payload.items[0].updatedAt > created);
  assert.equal(updateItem(payload, item.id, { secret: "" }).ok, false);
  assert.equal(payload.items[0].secret, "new");
  assert.equal(updateItem(payload, "nope", { secret: "x" }).ok, false);
});

test("deleteItem removes exactly the targeted item; unknown id errors", () => {
  const payload = createEmptyVaultPayload();
  const a = addItem(payload, { site: "a.com", secret: "x" }).item;
  addItem(payload, { site: "b.com", secret: "y" });
  assert.equal(deleteItem(payload, a.id).ok, true);
  assert.equal(payload.items.length, 1);
  assert.equal(payload.items[0].site, "b.com");
  assert.equal(deleteItem(payload, "nope").ok, false);
});

test("searchItems matches site/username/label case-insensitively", () => {
  const payload = createEmptyVaultPayload();
  addItem(payload, { site: "github.com", username: "octocat", accountLabel: "Work", secret: "x" });
  addItem(payload, { site: "example.com", username: "alice", accountLabel: "Personal", secret: "y" });
  assert.equal(searchItems(payload, "GITHUB").length, 1);
  assert.equal(searchItems(payload, "octocat").length, 1);
  assert.equal(searchItems(payload, "work").length, 1);
  assert.equal(searchItems(payload, "nomatch").length, 0);
  assert.equal(searchItems(payload, "").length, 2);
});

test("CRUD changes persist across save/load", async () => {
  const { payload, saltHex } = await loadVault("pc", "pw");
  const a = addItem(payload, { site: "a.com", secret: "1" }).item;
  addItem(payload, { site: "b.com", secret: "2" });
  updateItem(payload, a.id, { secret: "1-updated" });
  await saveVault("pc", "pw", saltHex, payload);
  const { payload: again } = await loadVault("pc", "pw");
  assert.equal(again.items.length, 2);
  assert.equal(again.items.find((i) => i.id === a.id).secret, "1-updated");
});

/* ======================= 3B-5: matching + summaries ======================= */

test("findItemsForSite: EXACT hostname match only (no subdomain/lookalike equivalence)", () => {
  const payload = createEmptyVaultPayload();
  addItem(payload, { site: "example.com", secret: "x" });
  assert.equal(findItemsForSite(payload, "example.com").length, 1);
  assert.equal(findItemsForSite(payload, "EXAMPLE.com").length, 1);
  for (const other of ["www.example.com", "example.com.evil.tld", "notexample.com", "example.co", "exampIe.com", ""]) {
    assert.equal(findItemsForSite(payload, other).length, 0, other);
  }
});

test("toListSummary strips secret and notes but keeps display metadata", () => {
  const payload = createEmptyVaultPayload();
  const { item } = addItem(payload, { site: "example.com", username: "u", secret: "topsecret", notes: "private", accountLabel: "L" });
  const s = toListSummary(item);
  assert.ok(!("secret" in s) && !("notes" in s));
  assert.equal(s.site, "example.com");
  assert.equal(s.username, "u");
  assert.ok(!JSON.stringify(s).includes("topsecret"));
});

/* ======================= 3B-6: export / import ======================= */

test("export payload is ciphertext-only (no plaintext secret) and has the documented shape", async () => {
  const { payload, saltHex } = await loadVault("pe", "pw");
  addItem(payload, { site: "a.com", username: "alice-user", secret: "verysecret-123" });
  await saveVault("pe", "pw", saltHex, payload);
  const exported = buildExportPayload(await getVaultRecord("pe"));
  assert.equal(exported.format, "secureauthx-vault-export");
  assert.deepEqual(Object.keys(exported).sort(), ["ciphertextHex", "format", "ivHex", "saltHex", "version"]);
  const text = JSON.stringify(exported);
  assert.ok(!text.includes("verysecret-123") && !text.includes("alice-user"));
});

test("import: valid export round-trips; wrong password and tampered data are rejected", async () => {
  const { payload, saltHex } = await loadVault("pi", "export pw");
  addItem(payload, { site: "a.com", secret: "s" });
  await saveVault("pi", "export pw", saltHex, payload);
  const exported = buildExportPayload(await getVaultRecord("pi"));
  assert.equal(validateImportPayload(exported).ok, true);

  const goodKey = await deriveVaultKey("export pw", exported.saltHex);
  const decrypted = await decryptVaultPayload(goodKey, exported.ivHex, exported.ciphertextHex);
  assert.equal(decrypted.items[0].site, "a.com");

  const badKey = await deriveVaultKey("not the pw", exported.saltHex);
  await assert.rejects(() => decryptVaultPayload(badKey, exported.ivHex, exported.ciphertextHex));

  const tampered = exported.ciphertextHex.slice(0, -2) + (exported.ciphertextHex.slice(-2) === "00" ? "01" : "00");
  await assert.rejects(() => decryptVaultPayload(goodKey, exported.ivHex, tampered));
});

test("validateImportPayload rejects malformed, wrong-format, wrong-version, and missing-field data", () => {
  assert.equal(validateImportPayload(null).ok, false);
  assert.equal(validateImportPayload("string").ok, false);
  assert.equal(validateImportPayload({}).ok, false);
  assert.equal(validateImportPayload({ format: "other" }).ok, false);
  assert.equal(validateImportPayload({ format: "secureauthx-vault-export", version: 999, saltHex: "a", ivHex: "b", ciphertextHex: "c" }).ok, false);
  assert.equal(validateImportPayload({ format: "secureauthx-vault-export", version: VAULT_VERSION, saltHex: "a" }).ok, false);
  assert.equal(validateImportPayload({ format: "secureauthx-vault-export", version: VAULT_VERSION, saltHex: 1, ivHex: "b", ciphertextHex: "c" }).ok, false);
  const good = { format: "secureauthx-vault-export", version: VAULT_VERSION, saltHex: "a".repeat(32), ivHex: "b".repeat(24), ciphertextHex: "c".repeat(64) };
  assert.equal(validateImportPayload(good).ok, true);
  assert.equal(validateImportPayload({ ...good, saltHex: "zz".repeat(16) }).ok, false);
  assert.equal(validateImportPayload({ ...good, saltHex: "a".repeat(30) }).ok, false);
  assert.equal(validateImportPayload({ ...good, ivHex: "b".repeat(22) }).ok, false);
  assert.equal(validateImportPayload({ ...good, ciphertextHex: "c".repeat(63) }).ok, false);
  assert.equal(validateImportPayload({ ...good, ciphertextHex: "xyz" }).ok, false);
});

/* ======================= 3B-4: random generator ======================= */

test("generateRandomPassword: requested length and all enabled classes present", () => {
  for (const len of [4, 12, 20, 64]) {
    const pw = generateRandomPassword(len);
    assert.equal(pw.length, len);
    assert.ok(/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw), pw);
  }
});

test("generateRandomPassword: honors character-class options", () => {
  assert.match(generateRandomPassword(30, { useUpper: false, useSymbols: false, useDigits: false }), /^[a-z]{30}$/);
  assert.match(generateRandomPassword(30, { useLower: false, useUpper: false, useSymbols: false }), /^[0-9]{30}$/);
  assert.ok(!/[^A-Za-z0-9]/.test(generateRandomPassword(40, { useSymbols: false })));
});

test("generateRandomPassword: minimum safe constraints are enforced", () => {
  assert.throws(() => generateRandomPassword(20, { useLower: false, useUpper: false, useDigits: false, useSymbols: false }));
  assert.throws(() => generateRandomPassword(3));
});

test("generateRandomPassword: non-deterministic (200 outputs all distinct)", () => {
  assert.equal(new Set(Array.from({ length: 200 }, () => generateRandomPassword(20))).size, 200);
});

test("generator source uses crypto.getRandomValues and never calls Math.random", () => {
  const code = read("../lib/vault.js").split("\n").filter((l) => !l.trim().startsWith("*") && !l.trim().startsWith("//") && !l.trim().startsWith("/*")).join("\n");
  assert.ok(code.includes("crypto.getRandomValues"));
  assert.ok(!code.includes("Math.random("));
});

/* ======================= security: no network, no leaks ======================= */

test("vault-related source files contain no network capability or secret logging", () => {
  for (const f of ["../lib/vault.js", "../lib/crypto.js", "../lib/storage.js"]) {
    const code = read(f);
    for (const banned of ["fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "navigator.sendBeacon", "console.log"]) {
      assert.ok(!code.includes(banned), `${f} must not contain ${banned}`);
    }
  }
});
