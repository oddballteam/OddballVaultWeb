/**
 * Password/passphrase generation and strength scoring — the browser
 * equivalent of generator_service.py. Uses crypto.getRandomValues
 * exclusively (never Math.random) as the entropy source, matching the
 * original's exclusive use of Python's `secrets` module.
 */
import zxcvbn from "zxcvbn";

const AMBIGUOUS_CHARS = "0O1lI";
const SYMBOL_SET = "!@#$%^&*()-_=+[]{}|;:,.<>?";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";

export const GEN_MIN_LENGTH = 8;
export const GEN_MAX_LENGTH = 128;
export const GEN_DEFAULT_LENGTH = 20;

export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
  excludeChars: string;
}

export const defaultPasswordOptions: PasswordOptions = {
  length: GEN_DEFAULT_LENGTH,
  uppercase: true,
  lowercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
  excludeChars: "",
};

/** Rejection-sampled uniform random int in [0, max) — the secrets.randbelow equivalent. */
function secureRandomBelow(max: number): number {
  if (max <= 0) throw new RangeError("max must be positive");
  const bitsNeeded = Math.ceil(Math.log2(max));
  const bytesNeeded = Math.ceil(bitsNeeded / 8);
  const mask = (1 << bitsNeeded) - 1;
  let value: number;
  do {
    const bytes = crypto.getRandomValues(new Uint8Array(bytesNeeded));
    value = bytes.reduce((acc, b) => (acc << 8) | b, 0) & mask;
  } while (value >= max);
  return value;
}

function secureChoice<T>(pool: T[]): T {
  return pool[secureRandomBelow(pool.length)];
}

function filtered(chars: string, opts: PasswordOptions): string {
  let excluded = opts.excludeChars;
  if (opts.excludeAmbiguous) excluded += AMBIGUOUS_CHARS;
  return [...chars].filter((c) => !excluded.includes(c)).join("");
}

export function generatePassword(opts: PasswordOptions = defaultPasswordOptions): string {
  if (opts.length < GEN_MIN_LENGTH || opts.length > GEN_MAX_LENGTH) {
    throw new RangeError(`Length must be between ${GEN_MIN_LENGTH} and ${GEN_MAX_LENGTH}.`);
  }

  let charset = "";
  const required: string[] = [];
  if (opts.uppercase) {
    const pool = filtered(UPPER, opts);
    if (pool) { charset += pool; required.push(secureChoice([...pool])); }
  }
  if (opts.lowercase) {
    const pool = filtered(LOWER, opts);
    if (pool) { charset += pool; required.push(secureChoice([...pool])); }
  }
  if (opts.digits) {
    const pool = filtered(DIGITS, opts);
    if (pool) { charset += pool; required.push(secureChoice([...pool])); }
  }
  if (opts.symbols) {
    const pool = filtered(SYMBOL_SET, opts);
    if (pool) { charset += pool; required.push(secureChoice([...pool])); }
  }
  if (!charset) throw new Error("At least one character set must be selected.");

  const remaining = Math.max(0, opts.length - required.length);
  const body = Array.from({ length: remaining }, () => secureChoice([...charset]));
  const combined = [...required, ...body];

  // Fisher-Yates shuffle using the same secure source.
  for (let i = combined.length - 1; i > 0; i--) {
    const j = secureRandomBelow(i + 1);
    [combined[i], combined[j]] = [combined[j], combined[i]];
  }
  return combined.slice(0, opts.length).join("");
}

export interface PassphraseOptions {
  wordCount: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export const defaultPassphraseOptions: PassphraseOptions = {
  wordCount: 4,
  separator: "-",
  capitalize: true,
  includeNumber: false,
};

export const PASSPHRASE_MIN_WORDS = 3;
export const PASSPHRASE_MAX_WORDS = 10;

export function generatePassphrase(opts: PassphraseOptions = defaultPassphraseOptions): string {
  if (opts.wordCount < PASSPHRASE_MIN_WORDS || opts.wordCount > PASSPHRASE_MAX_WORDS) {
    throw new RangeError(`Word count must be between ${PASSPHRASE_MIN_WORDS} and ${PASSPHRASE_MAX_WORDS}.`);
  }
  let words = Array.from({ length: opts.wordCount }, () => secureChoice(WORD_LIST));
  if (opts.capitalize) words = words.map((w) => w[0].toUpperCase() + w.slice(1));
  if (opts.includeNumber) {
    const idx = secureRandomBelow(words.length);
    words[idx] = words[idx] + String(secureRandomBelow(10));
  }
  return words.join(opts.separator);
}

export interface StrengthResult {
  score: number;
  label: string;
  entropyBits: number;
  suggestions: string[];
  warning: string;
}

const STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"];

export function scorePassword(password: string): StrengthResult {
  if (!password) {
    return { score: 0, label: STRENGTH_LABELS[0], entropyBits: 0, suggestions: [], warning: "Password is empty." };
  }
  const result = zxcvbn(password);
  const guesses = Math.max(1, result.guesses ?? 1);
  return {
    score: result.score,
    label: STRENGTH_LABELS[result.score],
    entropyBits: Math.round(Math.log2(guesses) * 10) / 10,
    suggestions: result.feedback?.suggestions ?? [],
    warning: result.feedback?.warning ?? "",
  };
}

const WORD_LIST: string[] = [
  "abbey", "abbot", "abide", "abode", "about", "above", "abuse", "abyss", "acorn", "acute",
  "admit", "adobe", "adopt", "adore", "adorn", "adult", "agent", "agile", "aging", "agony",
  "agree", "ahead", "aided", "aisle", "alarm", "album", "alert", "algae", "alibi", "alien",
  "align", "alive", "allay", "alley", "allot", "allow", "alloy", "aloft", "alone", "along",
  "aloof", "aloud", "altar", "alter", "amaze", "amber", "amble", "amend", "ample", "angel",
  "anger", "angle", "angry", "anime", "ankle", "annex", "antic", "anvil", "apart", "apple",
  "apron", "aptly", "arbor", "ardor", "arena", "argon", "armor", "aroma", "arose", "array",
  "arson", "artsy", "ascot", "ashen", "askew", "atlas", "attic", "audio", "audit", "augur",
  "avail", "avian", "avoid", "award", "aware", "awful", "awoke", "axiom", "azure", "bacon",
  "badge", "bagel", "baggy", "balmy", "banal", "banjo", "barge", "baron", "basin", "batch",
  "baton", "bayou", "beach", "beady", "began", "being", "belch", "below", "bench", "berry",
  "birch", "birth", "bison", "blank", "blast", "blaze", "bleak", "blend", "blink", "block",
  "bloke", "blood", "bloom", "blown", "blunt", "blurb", "blurt", "bobby", "boggy", "bonus",
  "boost", "booth", "botch", "brash", "brave", "brawn", "braze", "bread", "break", "breed",
  "brisk", "broad", "broth", "brown", "brunt", "brute", "budge", "build", "bulge", "bunch",
];
