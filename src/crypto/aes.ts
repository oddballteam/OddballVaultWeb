/**
 * AES-256-GCM via the native Web Crypto SubtleCrypto API.
 *
 * Every encrypt call generates a fresh random 96-bit nonce — never reused,
 * never derived — matching the desktop app's aes.py invariant.
 */
import { fromBase64, toBase64 } from "./base64";

const NONCE_LENGTH_BYTES = 12;

export class DecryptionError extends Error {
  constructor() {
    super("Authentication tag verification failed.");
    this.name = "DecryptionError";
  }
}

/** Imports raw 32-byte key material as a non-extractable AES-GCM CryptoKey. */
export async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Generates fresh random 32-byte key material (an Item Key or Group KEK). */
export function generateAesKeyBytes(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export interface EncryptedPayload {
  nonce: string; // base64
  ciphertext: string; // base64
}

export async function encryptBytes(
  key: CryptoKey,
  plaintext: Uint8Array,
): Promise<EncryptedPayload> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH_BYTES));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext);
  return {
    nonce: toBase64(nonce),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
  };
}

export async function decryptBytes(
  key: CryptoKey,
  nonce: string,
  ciphertext: string,
): Promise<Uint8Array> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(nonce) },
      key,
      fromBase64(ciphertext),
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new DecryptionError();
  }
}

export async function encryptString(key: CryptoKey, plaintext: string): Promise<EncryptedPayload> {
  return encryptBytes(key, new TextEncoder().encode(plaintext));
}

export async function decryptString(
  key: CryptoKey,
  nonce: string,
  ciphertext: string,
): Promise<string> {
  const bytes = await decryptBytes(key, nonce, ciphertext);
  return new TextDecoder().decode(bytes);
}
