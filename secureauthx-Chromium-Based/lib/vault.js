/**
 * SecureAuthX — vault.js (Phase 3B)
 *
 * CRUD over the DECRYPTED in-memory vault payload, plus encrypt/decrypt
 * (lib/crypto.js) and persistence (lib/storage.js). Never sends anything
 * across a message boundary itself -- background.js owns that discipline.
 * No cloud, backend, account, sync, or network call exists here.
 */

import { deriveVaultKey, generateVaultSalt, encryptVaultPayload, decryptVaultPayload } from "./crypto.js";
import { getVaultRecord, setVaultRecord } from "./storage.js";

export const VAULT_VERSION = 1;
const MAX_SITE_LENGTH = 253;
const MAX_USERNAME_LENGTH = 254;
const MAX_SECRET_LENGTH = 512;
const MAX_NOTES_LENGTH = 2000;
const MAX_ACCOUNT_LABEL_LENGTH = 40;
export const MAX_ITEMS = 500;

function generateItemId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  return Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Lowercase+trim only. Matching is ALWAYS exact equality afterward. */
function normalizeSite(site) {
  return (site || "").trim().toLowerCase();
}

export function validateItemInput({ site, username, secret, accountLabel, notes }) {
  const trimmedSite = normalizeSite(site);
  if (!trimmedSite) return { ok: false, error: "Site is required." };
  if (trimmedSite.length > MAX_SITE_LENGTH) return { ok: false, error: "Site is too long." };
  if ((username || "").length > MAX_USERNAME_LENGTH) return { ok: false, error: "Username is too long." };
  if (!secret) return { ok: false, error: "Password/secret is required." };
  if (secret.length > MAX_SECRET_LENGTH) return { ok: false, error: "Password/secret is too long." };
  if ((accountLabel || "").length > MAX_ACCOUNT_LABEL_LENGTH) return { ok: false, error: "Account label is too long." };
  if ((notes || "").length > MAX_NOTES_LENGTH) return { ok: false, error: "Notes are too long." };
  return { ok: true };
}

export function createEmptyVaultPayload() {
  return { version: VAULT_VERSION, items: [] };
}

/**
 * Loads + decrypts a profile's vault (or returns a fresh empty one with a
 * new salt if none exists yet; nothing is persisted until saveVault()).
 * Throws on wrong master password OR tampered/malformed/wrong-version data.
 */
export async function loadVault(profileId, masterPassword) {
  const record = await getVaultRecord(profileId);
  if (!record) return { payload: createEmptyVaultPayload(), saltHex: generateVaultSalt(), isNew: true };
  const vaultKey = await deriveVaultKey(masterPassword, record.saltHex);
  const payload = await decryptVaultPayload(vaultKey, record.ivHex, record.ciphertextHex);
  if (!payload || payload.version !== VAULT_VERSION || !Array.isArray(payload.items)) {
    throw new Error("Vault record is malformed or from an unsupported version.");
  }
  return { payload, saltHex: record.saltHex, isNew: false };
}

export async function saveVault(profileId, masterPassword, saltHex, payload) {
  const vaultKey = await deriveVaultKey(masterPassword, saltHex);
  const { ivHex, ciphertextHex } = await encryptVaultPayload(vaultKey, payload);
  await setVaultRecord(profileId, { version: VAULT_VERSION, saltHex, ivHex, ciphertextHex });
  return { ivHex, ciphertextHex };
}

export function addItem(payload, { site, username, secret, accountLabel, notes } = {}) {
  if (payload.items.length >= MAX_ITEMS) return { ok: false, error: `Vault supports a maximum of ${MAX_ITEMS} items.` };
  const validation = validateItemInput({ site, username, secret, accountLabel, notes });
  if (!validation.ok) return validation;
  const now = Date.now();
  const item = {
    id: generateItemId(), site: normalizeSite(site), username: username || "", secret,
    accountLabel: accountLabel || "", notes: notes || "", createdAt: now, updatedAt: now,
  };
  payload.items.push(item);
  return { ok: true, item };
}

export function updateItem(payload, id, updates = {}) {
  const item = payload.items.find((i) => i.id === id);
  if (!item) return { ok: false, error: "Credential not found." };
  const merged = {
    site: updates.site !== undefined ? updates.site : item.site,
    username: updates.username !== undefined ? updates.username : item.username,
    secret: updates.secret !== undefined ? updates.secret : item.secret,
    accountLabel: updates.accountLabel !== undefined ? updates.accountLabel : item.accountLabel,
    notes: updates.notes !== undefined ? updates.notes : item.notes,
  };
  const validation = validateItemInput(merged);
  if (!validation.ok) return validation;
  item.site = normalizeSite(merged.site);
  item.username = merged.username || "";
  item.secret = merged.secret;
  item.accountLabel = merged.accountLabel || "";
  item.notes = merged.notes || "";
  item.updatedAt = Date.now();
  return { ok: true, item };
}

export function deleteItem(payload, id) {
  const index = payload.items.findIndex((i) => i.id === id);
  if (index === -1) return { ok: false, error: "Credential not found." };
  payload.items.splice(index, 1);
  return { ok: true };
}

/** EXACT hostname match only -- no fuzzy or subdomain equivalence. */
export function findItemsForSite(payload, site) {
  const normalized = normalizeSite(site);
  return payload.items.filter((i) => i.site === normalized);
}

export function searchItems(payload, query) {
  const q = (query || "").trim().toLowerCase();
  if (!q) return payload.items;
  return payload.items.filter(
    (i) => i.site.includes(q) || (i.username || "").toLowerCase().includes(q) || (i.accountLabel || "").toLowerCase().includes(q)
  );
}

/** Strips secret AND notes -- the only shape any list/search/match result may carry across a boundary. */
export function toListSummary(item) {
  const { secret, notes, ...rest } = item;
  return rest;
}

const EXPORT_FORMAT = "secureauthx-vault-export";

/** The export IS the stored ciphertext record -- nothing is decrypted to make it. */
export function buildExportPayload(vaultRecord) {
  return {
    format: EXPORT_FORMAT, version: vaultRecord.version,
    saltHex: vaultRecord.saltHex, ivHex: vaultRecord.ivHex, ciphertextHex: vaultRecord.ciphertextHex,
  };
}

export function validateImportPayload(data) {
  if (!data || typeof data !== "object") return { ok: false, error: "Not a valid export file." };
  if (data.format !== EXPORT_FORMAT) return { ok: false, error: "Not a SecureAuthX vault export file." };
  if (data.version !== VAULT_VERSION) return { ok: false, error: "Unsupported vault export version." };
  if (typeof data.saltHex !== "string" || typeof data.ivHex !== "string" || typeof data.ciphertextHex !== "string") {
    return { ok: false, error: "Export file is missing required fields." };
  }
  // Strict shape checks so malformed/hostile files are rejected before any crypto runs.
  const HEX = /^[0-9a-f]+$/i;
  if (!HEX.test(data.saltHex) || data.saltHex.length !== 32) return { ok: false, error: "Export file has an invalid salt." };
  if (!HEX.test(data.ivHex) || data.ivHex.length !== 24) return { ok: false, error: "Export file has an invalid IV." };
  if (!HEX.test(data.ciphertextHex) || data.ciphertextHex.length % 2 !== 0 || data.ciphertextHex.length < 32 || data.ciphertextHex.length > 4000000) {
    return { ok: false, error: "Export file has invalid ciphertext." };
  }
  return { ok: true };
}

/**
 * Truly-random generator for vault credentials -- deliberately separate
 * from crypto.js's DETERMINISTIC deriveSitePassword(). Uses
 * crypto.getRandomValues() only, never Math.random().
 */
const RANDOM_PASSWORD_CHARSETS = {
  lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789", symbols: "!@#$%^&*()-_=+[]{}",
};

export function generateRandomPassword(length = 20, options = {}) {
  const { useUpper = true, useLower = true, useDigits = true, useSymbols = true } = options;
  const sets = [];
  if (useLower) sets.push(RANDOM_PASSWORD_CHARSETS.lower);
  if (useUpper) sets.push(RANDOM_PASSWORD_CHARSETS.upper);
  if (useDigits) sets.push(RANDOM_PASSWORD_CHARSETS.digits);
  if (useSymbols) sets.push(RANDOM_PASSWORD_CHARSETS.symbols);
  if (sets.length === 0) throw new Error("At least one character set must be enabled");
  if (length < sets.length) throw new Error("length must be at least the number of enabled character sets");

  const fullSet = sets.join("");
  const chars = [];
  const guarantee = crypto.getRandomValues(new Uint8Array(sets.length));
  sets.forEach((set, i) => chars.push(set[guarantee[i] % set.length]));
  const fill = crypto.getRandomValues(new Uint8Array(Math.max(0, length - chars.length)));
  for (let i = 0; i < fill.length; i++) chars.push(fullSet[fill[i] % fullSet.length]);
  const shuffle = crypto.getRandomValues(new Uint8Array(chars.length));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = shuffle[i] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.slice(0, length).join("");
}
