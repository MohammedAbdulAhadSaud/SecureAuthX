/**
 * SecureAuthX — storage.js
 *
 * The ONLY things ever written to browser.storage.local:
 *  - profiles state: { profiles: [{id, name, saltHex, verifierHex}], defaultProfileId }
 *    — one-way PBKDF2 verifiers per profile, NEVER the master password itself.
 *  - account identities per profile+site (labels only, e.g. "Default",
 *    "Alice" — NOT passwords): { [profileId]: { sites: { [domain]: {
 *    accounts: [...], lastSelected } } } }
 *  - site metadata: { domain, lastUsed }
 *  - reuse-detection comparison hashes (SHA-256 of derived password)
 *  - user settings (theme, thresholds)
 *  - lightweight security-score cache per origin
 *
 *  - vault records (Phase 3B): AES-256-GCM ciphertext + salt + IV + version ONLY.
 *
 * NEVER written here: decrypted vault contents, the vault encryption key, any master password (plaintext or otherwise),
 * derived site passwords, plaintext of anything typed into a password field.
 * Session-unlocked master passwords live ONLY in background.js's in-memory
 * `sessions` Map — never in browser.storage.
 */

const KEYS = {
  PROFILES_STATE: "sax_profiles_state",       // { profiles: [...], defaultProfileId }
  LEGACY_MASTER_VERIFIER: "sax_master_verifier", // old single-profile key, read once for migration
  ACCOUNTS: "sax_accounts",                    // { [profileId]: { sites: { [domain]: { accounts: [...], lastSelected } } } }
  SITES: "sax_sites",
  REUSE_HASHES: "sax_reuse",
  SETTINGS: "sax_settings",
  SCORE_CACHE: "sax_score_cache",
  VAULT: "sax_vault", // { [profileId]: { version, saltHex, ivHex, ciphertextHex } } -- AES-GCM ciphertext ONLY
  VISITS: "sax_visits", // { [domain]: { visitCount, lastVisited, everFlagged } } — local-only visit reputation
};

async function getAll(key, fallback) {
  const result = await browser.storage.local.get(key);
  return result[key] ?? fallback;
}

async function setAll(key, value) {
  await browser.storage.local.set({ [key]: value });
}

const MAX_PROFILE_NAME_LENGTH = 40;

export function validateProfileName(name) {
  const trimmed = (name || "").trim();
  if (!trimmed) return { ok: false, error: "Profile name can't be empty." };
  if (trimmed.length > MAX_PROFILE_NAME_LENGTH) {
    return { ok: false, error: `Profile name must be ${MAX_PROFILE_NAME_LENGTH} characters or fewer.` };
  }
  return { ok: true, name: trimmed };
}

function generateId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  // Fallback for environments without crypto.randomUUID
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ==================================================================== *
 * Master Profiles
 * ==================================================================== */

async function rawProfilesState() {
  return getAll(KEYS.PROFILES_STATE, { profiles: [], defaultProfileId: null });
}

/**
 * One-time, idempotent migration: if an old single-profile installation
 * (pre-multi-profile) has a legacy verifier and no profiles yet, wrap it
 * into a profile named "Personal" and make it the default. This preserves
 * the user's existing master password — they never need to re-create it,
 * since the verifier (and therefore their existing derived passwords)
 * carries over unchanged.
 */
export async function migrateLegacyProfileIfNeeded() {
  const state = await rawProfilesState();
  if (state.profiles.length > 0) return state;

  const legacy = await getAll(KEYS.LEGACY_MASTER_VERIFIER, null);
  if (!legacy) return state;

  const profile = { id: generateId(), name: "Personal", saltHex: legacy.saltHex, verifierHex: legacy.verifierHex };
  const migrated = { profiles: [profile], defaultProfileId: profile.id };
  await setAll(KEYS.PROFILES_STATE, migrated);
  await browser.storage.local.remove(KEYS.LEGACY_MASTER_VERIFIER);
  return migrated;
}

export async function getProfilesState() {
  return migrateLegacyProfileIfNeeded();
}

export async function hasAnyProfile() {
  const state = await migrateLegacyProfileIfNeeded();
  return state.profiles.length > 0;
}

export async function listProfiles() {
  const state = await migrateLegacyProfileIfNeeded();
  return state.profiles;
}

export async function getProfileById(id) {
  const state = await migrateLegacyProfileIfNeeded();
  return state.profiles.find((p) => p.id === id) ?? null;
}

export async function getDefaultProfileId() {
  const state = await migrateLegacyProfileIfNeeded();
  return state.defaultProfileId;
}

export async function addProfile(name, saltHex, verifierHex) {
  const state = await migrateLegacyProfileIfNeeded();
  const profile = { id: generateId(), name, saltHex, verifierHex };
  state.profiles.push(profile);
  if (!state.defaultProfileId) state.defaultProfileId = profile.id;
  await setAll(KEYS.PROFILES_STATE, state);
  return profile;
}

export async function renameProfile(id, newName) {
  const state = await migrateLegacyProfileIfNeeded();
  const profile = state.profiles.find((p) => p.id === id);
  if (!profile) throw new Error("Profile not found");
  profile.name = newName;
  await setAll(KEYS.PROFILES_STATE, state);
  return profile;
}

export async function deleteProfile(id) {
  const state = await migrateLegacyProfileIfNeeded();
  state.profiles = state.profiles.filter((p) => p.id !== id);
  if (state.defaultProfileId === id) {
    state.defaultProfileId = state.profiles[0]?.id ?? null;
  }
  await setAll(KEYS.PROFILES_STATE, state);

  // Account identities are owned by the profile — purge them too.
  const accountsState = await getAll(KEYS.ACCOUNTS, {});
  if (accountsState[id]) {
    delete accountsState[id];
    await setAll(KEYS.ACCOUNTS, accountsState);
  }

  // Phase 3B: the vault record is owned by the profile too -- purge it.
  const vaultState = await getAll(KEYS.VAULT, {});
  if (vaultState[id]) {
    delete vaultState[id];
    await setAll(KEYS.VAULT, vaultState);
  }

  return state;
}

export async function setDefaultProfile(id) {
  const state = await migrateLegacyProfileIfNeeded();
  if (!state.profiles.some((p) => p.id === id)) throw new Error("Profile not found");
  state.defaultProfileId = id;
  await setAll(KEYS.PROFILES_STATE, state);
  return state;
}

/* ==================================================================== *
 * Account identities — owned by (Master Profile, website), NOT global.
 * These are labels only ("Default", "Alice", "Work") — never passwords.
 * Max 5 accounts per site, matching the project spec.
 * ==================================================================== */

export const MAX_ACCOUNTS_PER_SITE = 5;
const MAX_ACCOUNT_NAME_LENGTH = 40;
const DEFAULT_ACCOUNT_NAME = "Default";

export function validateAccountName(name) {
  const trimmed = (name || "").trim();
  if (!trimmed) return { ok: false, error: "Account name can't be empty." };
  if (trimmed.length > MAX_ACCOUNT_NAME_LENGTH) {
    return { ok: false, error: `Account name must be ${MAX_ACCOUNT_NAME_LENGTH} characters or fewer.` };
  }
  return { ok: true, name: trimmed };
}

async function rawAccountsState() {
  return getAll(KEYS.ACCOUNTS, {});
}

function siteEntryFor(state, profileId, domain) {
  const profile = state[profileId] ?? { sites: {} };
  const site = profile.sites[domain] ?? { accounts: [DEFAULT_ACCOUNT_NAME], lastSelected: DEFAULT_ACCOUNT_NAME };
  return { profile, site };
}

/** List the accounts for a (profile, domain) pair, seeding a "Default" account if none exist yet. */
export async function listAccounts(profileId, domain) {
  const state = await rawAccountsState();
  const { site } = siteEntryFor(state, profileId, domain);
  return { accounts: site.accounts, lastSelected: site.lastSelected };
}

/** Add a new account identity for (profile, domain). Enforces uniqueness (case-insensitive) and the 5-account cap. */
export async function addAccount(profileId, domain, name) {
  const validated = validateAccountName(name);
  if (!validated.ok) return validated;

  const state = await rawAccountsState();
  const { profile, site } = siteEntryFor(state, profileId, domain);

  if (site.accounts.some((a) => a.toLowerCase() === validated.name.toLowerCase())) {
    return { ok: false, error: `An account named "${validated.name}" already exists for this site.` };
  }
  if (site.accounts.length >= MAX_ACCOUNTS_PER_SITE) {
    return { ok: false, error: `Each website supports a maximum of ${MAX_ACCOUNTS_PER_SITE} account identities.` };
  }

  site.accounts = [...site.accounts, validated.name];
  site.lastSelected = validated.name;
  profile.sites[domain] = site;
  state[profileId] = profile;
  await setAll(KEYS.ACCOUNTS, state);

  return { ok: true, accounts: site.accounts, lastSelected: site.lastSelected };
}

/** Remember which account was last selected for (profile, domain), so revisiting restores it. */
export async function setLastSelectedAccount(profileId, domain, name) {
  const state = await rawAccountsState();
  const { profile, site } = siteEntryFor(state, profileId, domain);
  if (!site.accounts.includes(name)) return { ok: false, error: "Account not found for this site." };
  site.lastSelected = name;
  profile.sites[domain] = site;
  state[profileId] = profile;
  await setAll(KEYS.ACCOUNTS, state);
  return { ok: true };
}


/** Delete an account identity for (profile, domain). At least one account must always remain for a site. */
export async function deleteAccount(profileId, domain, name) {
  const state = await rawAccountsState();
  const { profile, site } = siteEntryFor(state, profileId, domain);

  if (!site.accounts.includes(name)) {
    return { ok: false, error: "Account not found for this site." };
  }
  if (site.accounts.length <= 1) {
    return { ok: false, error: "At least one account must remain for a site." };
  }

  site.accounts = site.accounts.filter((a) => a !== name);
  if (site.lastSelected === name) {
    site.lastSelected = site.accounts[0];
  }
  profile.sites[domain] = site;
  state[profileId] = profile;
  await setAll(KEYS.ACCOUNTS, state);

  return { ok: true, accounts: site.accounts, lastSelected: site.lastSelected };
}

/* ==================================================================== *
 * Site metadata (domain-only)
 * ==================================================================== */

export async function saveSiteMeta(domain) {
  const sites = await getAll(KEYS.SITES, {});
  sites[domain] = { domain, lastUsed: Date.now() };
  await setAll(KEYS.SITES, sites);
  return sites[domain];
}

export async function listSites() {
  const sites = await getAll(KEYS.SITES, {});
  return Object.values(sites).sort((a, b) => b.lastUsed - a.lastUsed);
}

/* ==================================================================== *
 * Reuse detection
 * ==================================================================== */

export async function recordAndCheckReuse(domain, reuseHash) {
  const map = await getAll(KEYS.REUSE_HASHES, {});
  const existing = map[reuseHash] ?? [];
  const reusedElsewhere = existing.filter((d) => d !== domain);
  if (!existing.includes(domain)) {
    map[reuseHash] = [...existing, domain];
    await setAll(KEYS.REUSE_HASHES, map);
  }
  return reusedElsewhere;
}

/* ==================================================================== *
 * Settings
 * ==================================================================== */

export async function getSettings() {
  return getAll(KEYS.SETTINGS, { theme: "dark", riskThreshold: 60, derivedLength: 20 });
}

export async function saveSettings(partial) {
  const current = await getSettings();
  const next = { ...current, ...partial };
  await setAll(KEYS.SETTINGS, next);
  return next;
}

/* ==================================================================== *
 * Score cache (Dashboard — unchanged by this feature)
 * ==================================================================== */

export async function cacheScore(origin, scoreReport) {
  const cache = await getAll(KEYS.SCORE_CACHE, {});
  cache[origin] = { ...scoreReport, checkedAt: Date.now() };
  await setAll(KEYS.SCORE_CACHE, cache);
}

export async function getCachedScore(origin) {
  const cache = await getAll(KEYS.SCORE_CACHE, {});
  return cache[origin] ?? null;
}

/* ==================================================================== *
 * Visit reputation — LOCAL ONLY, never sent anywhere. Tracks how many
 * times this browser has seen a domain and whether any past scan on it
 * ever flagged a serious issue. This is "have I been here before and was
 * it ever a problem", not any kind of external reputation score.
 * ==================================================================== */

export async function recordVisit(domain, hadCriticalIssue) {
  const visits = await getAll(KEYS.VISITS, {});
  const existing = visits[domain] || { visitCount: 0, lastVisited: null, everFlagged: false };
  existing.visitCount += 1;
  existing.lastVisited = Date.now();
  if (hadCriticalIssue) existing.everFlagged = true;
  visits[domain] = existing;
  await setAll(KEYS.VISITS, visits);
  return existing;
}

export async function getVisitInfo(domain) {
  const visits = await getAll(KEYS.VISITS, {});
  return visits[domain] ?? null;
}



/* ==================================================================== *
 * Vault records (Phase 3B) -- CIPHERTEXT ONLY. This module never sees the
 * decrypted vault or the master password; it only stores/retrieves what
 * lib/vault.js already encrypted.
 * ==================================================================== */

export async function getVaultRecord(profileId) {
  const all = await getAll(KEYS.VAULT, {});
  return all[profileId] ?? null;
}

export async function setVaultRecord(profileId, record) {
  const all = await getAll(KEYS.VAULT, {});
  all[profileId] = record;
  await setAll(KEYS.VAULT, all);
  return record;
}

export async function deleteVaultRecord(profileId) {
  const all = await getAll(KEYS.VAULT, {});
  if (all[profileId]) {
    delete all[profileId];
    await setAll(KEYS.VAULT, all);
  }
}
