/**
 * SecureAuthX — crypto.js
 *
 * All derivation happens locally, in memory, using the browser's native
 * Web Crypto API (SubtleCrypto). The master password is NEVER stored,
 * NEVER transmitted, and NEVER logged. It exists only for the duration
 * of a derivation call.
 *
 * DERIVATION INPUTS (v3, per project spec):
 *   Master Password + Website Domain + Account Identity
 *
 * This replaces the v2 design (Master Password + Domain +
 * Scrambled(user-typed password)). The "password to derive from" /
 * scramble concept is removed entirely — there is no longer a
 * user-typed password involved in derivation at all. Instead, the
 * Account Identity (a label like "Default", "Alice", "Work") takes
 * over the role of distinguishing multiple credentials on the same
 * domain: different account identities on the same domain now always
 * produce completely different derived passwords, which the old
 * domain-only salt could not do.
 *
 * Domain is the phishing-binding context (must come from a verified
 * browser value, e.g. location.hostname, never user-typed text).
 * Account Identity is just a label the user chose for this profile —
 * it is NOT a password itself and is stored as plain metadata.
 */

const PBKDF2_ITERATIONS = 250000; // OWASP-recommended floor for PBKDF2-SHA256 as of 2024/2025
const DERIVED_KEY_BITLEN = 256;

/** Encode a string as a Uint8Array (UTF-8). */
function toBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/**
 * Derive a raw high-entropy key from (masterPassword, domain, accountIdentity).
 * The master password is the key material; domain + account identity
 * together form the salt/context, so different accounts on the same
 * domain always produce completely different key material.
 */
async function deriveRawKey(masterPassword, domain, accountIdentity) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    toBytes(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const salt = toBytes(`secureauthx:v3:${domain}:${accountIdentity}`);

  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    DERIVED_KEY_BITLEN
  );

  return new Uint8Array(derivedBits);
}

/**
 * Convert raw key bytes into a password string that satisfies typical
 * site rules: guaranteed at least one lowercase, one uppercase, one
 * digit, one symbol, then filled out from a full character set,
 * deterministically shuffled from the same key material.
 */
function formatAsPassword(rawBytes, length = 20, options = {}) {
  const { useUpper = true, useLower = true, useDigits = true, useSymbols = true } = options;

  const sets = [];
  if (useLower) sets.push("abcdefghijklmnopqrstuvwxyz");
  if (useUpper) sets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (useDigits) sets.push("0123456789");
  if (useSymbols) sets.push("!@#$%^&*()-_=+[]{}");
  if (sets.length === 0) throw new Error("At least one character set must be enabled");

  const fullSet = sets.join("");
  const chars = [];

  sets.forEach((set, i) => {
    const idx = rawBytes[i % rawBytes.length] % set.length;
    chars.push(set[idx]);
  });

  let byteIdx = sets.length;
  while (chars.length < length) {
    const b = rawBytes[byteIdx % rawBytes.length];
    chars.push(fullSet[b % fullSet.length]);
    byteIdx++;
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const b = rawBytes[(byteIdx + i) % rawBytes.length];
    const j = b % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
    byteIdx++;
  }

  return chars.slice(0, length).join("");
}

/**
 * Public entry point: derive the actual site password to fill into a form.
 * `domain` should come from a verified browser value (location.hostname),
 * never from user-typed text, or phishing binding is defeated.
 *
 * `accountIdentity` is the selected account label (e.g. "Default",
 * "Alice", "Work") — a plain, non-secret identifier, never a password.
 * Combined with the master password and domain, it deterministically
 * produces a completely different password per account on the same site.
 */
export async function deriveSitePassword(masterPassword, domain, accountIdentity, options = {}) {
  const raw = await deriveRawKey(masterPassword, domain, accountIdentity);
  return formatAsPassword(raw, options.length ?? 20, options);
}

/**
 * Reuse-detection comparison value. Intentionally a FAST hash (SHA-256),
 * not PBKDF2 — see README for why a slow KDF is the wrong tool here.
 */
export async function reuseComparisonHash(password) {
  const digest = await crypto.subtle.digest("SHA-256", toBytes("secureauthx:reuse:v1:" + password));
  return bytesToHex(new Uint8Array(digest));
}

/* -------------------------------------------------------------------- *
 * Master password verifier
 *
 * The master password is set ONCE on first launch and is never stored.
 * To let the extension warn on typos on later use (without ever storing
 * the master password itself), we store a PBKDF2 verifier: a one-way
 * derived value computed from the master password + a random local salt.
 * This is the same pattern password managers use for their own "unlock"
 * check — it lets us confirm a re-entered master password is *correct*
 * without ever persisting anything that could reconstruct it.
 * -------------------------------------------------------------------- */

export async function computeMasterVerifier(masterPassword, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", toBytes(masterPassword), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { saltHex: bytesToHex(salt), verifierHex: bytesToHex(new Uint8Array(bits)) };
}

export async function verifyAgainstVerifier(masterPassword, saltHex, expectedVerifierHex) {
  const { verifierHex } = await computeMasterVerifier(masterPassword, saltHex);
  return verifierHex === expectedVerifierHex;
}

/* -------------------------------------------------------------------- *
 * Vault key derivation + encryption (Phase 3B)
 *
 * Separate from computeMasterVerifier() above in two ways: its own
 * independently-generated random salt, AND a different fixed context
 * string baked into the PBKDF2 input. The verifier is a one-way check
 * value safe to persist; this produces the actual AES-GCM key and must
 * NEVER be persisted -- only held in memory while a session is unlocked.
 * -------------------------------------------------------------------- */

const VAULT_KEY_PBKDF2_ITERATIONS = 250000;

export function generateVaultSalt() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

/** Returns a NON-EXTRACTABLE AES-256-GCM CryptoKey. */
export async function deriveVaultKey(masterPassword, saltHex) {
  const salt = hexToBytes(saltHex);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", toBytes(`secureauthx:vault-key:v1:${masterPassword}`), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: VAULT_KEY_PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

/** Fresh random 96-bit IV on EVERY call (AES-GCM requires IV uniqueness per key). */
export async function encryptVaultPayload(vaultKey, plaintextObject) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vaultKey, toBytes(JSON.stringify(plaintextObject)));
  return { ivHex: bytesToHex(iv), ciphertextHex: bytesToHex(new Uint8Array(ct)) };
}

/** Rejects on wrong key OR tampered ciphertext (GCM auth tag) -- callers must not distinguish the two. */
export async function decryptVaultPayload(vaultKey, ivHex, ciphertextHex) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(ivHex) }, vaultKey, hexToBytes(ciphertextHex));
  return JSON.parse(new TextDecoder().decode(pt));
}
