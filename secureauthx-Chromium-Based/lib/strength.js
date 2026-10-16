/**
 * SecureAuthX — strength.js
 * Local, offline password strength estimation. No network calls.
 * This is a heuristic estimator for user feedback, not a formal
 * cryptographic guarantee.
 */

const COMMON_PASSWORDS = new Set([
  "password", "123456", "123456789", "qwerty", "abc123", "password1",
  "111111", "12345678", "letmein", "welcome", "monkey", "iloveyou",
  "admin", "login", "starwars", "dragon", "football", "sunshine",
  "princess", "trustno1", "1234567", "000000", "passw0rd",
]);

function charsetSize(password) {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^a-zA-Z0-9]/.test(password)) size += 33;
  return size || 1;
}

function estimateEntropyBits(password) {
  const set = charsetSize(password);
  return Math.log2(set) * password.length;
}

function hasSequentialRun(password, len = 3) {
  const lower = password.toLowerCase();
  const seqs = "abcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i <= lower.length - len; i++) {
    const chunk = lower.slice(i, i + len);
    if (seqs.includes(chunk)) return true;
    if (seqs.split("").reverse().join("").includes(chunk)) return true;
  }
  return false;
}

function hasRepeatedChars(password, run = 3) {
  return new RegExp(`(.)\\1{${run - 1},}`).test(password);
}

/**
 * Returns a strength report:
 * { score: 0-100, label, entropyBits, issues: [], suggestions: [] }
 */
export function analyzeStrength(password) {
  if (!password) {
    return { score: 0, label: "Empty", entropyBits: 0, issues: ["No password entered"], suggestions: [] };
  }

  const issues = [];
  const suggestions = [];
  const lower = password.toLowerCase();

  if (COMMON_PASSWORDS.has(lower)) {
    issues.push("This is one of the most common leaked passwords in the world.");
  }
  if (password.length < 8) {
    issues.push("Too short (under 8 characters).");
    suggestions.push("Use at least 12–16 characters.");
  }
  if (!/[A-Z]/.test(password)) suggestions.push("Add an uppercase letter.");
  if (!/[a-z]/.test(password)) suggestions.push("Add a lowercase letter.");
  if (!/[0-9]/.test(password)) suggestions.push("Add a digit.");
  if (!/[^a-zA-Z0-9]/.test(password)) suggestions.push("Add a symbol.");
  if (hasSequentialRun(password)) {
    issues.push("Contains a sequential run (e.g. 'abc', '123').");
  }
  if (hasRepeatedChars(password)) {
    issues.push("Contains a repeated-character run (e.g. 'aaa').");
  }

  const entropyBits = estimateEntropyBits(password);

  // Rough, deliberately conservative scoring: entropy dominates, common
  // passwords / patterns cap the score regardless of raw entropy.
  let score = Math.min(100, Math.round((entropyBits / 100) * 100));
  if (COMMON_PASSWORDS.has(lower)) score = Math.min(score, 5);
  if (hasSequentialRun(password) || hasRepeatedChars(password)) score = Math.min(score, 40);
  if (password.length < 8) score = Math.min(score, 30);

  let label = "Very Weak";
  if (score >= 80) label = "Very Strong";
  else if (score >= 60) label = "Strong";
  else if (score >= 40) label = "Moderate";
  else if (score >= 20) label = "Weak";

  return {
    score,
    label,
    entropyBits: Math.round(entropyBits * 10) / 10,
    issues,
    suggestions,
  };
}
