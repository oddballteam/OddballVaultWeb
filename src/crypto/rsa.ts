/**
 * RSA-OAEP-3072 keypairs, used to wrap the small (32-byte) AES keys that
 * distribute access to items and groups — never used to encrypt item
 * content directly.
 *
 * RSA-OAEP-3072/SHA-256 can only directly encrypt up to 318 bytes
 * (modulus/8 - 2*hashLen - 2). A 32-byte AES key fits comfortably; a PKCS8
 * private key (~1.6KB) does not — that's why group private keys are never
 * wrapped directly (see groupKeys.ts), only their 32-byte KEK is.
 */
import { fromBase64, toBase64 } from "./base64";

const RSA_OAEP_PARAMS = {
  name: "RSA-OAEP",
  modulusLength: 3072,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: "SHA-256",
} as const;

export const MAX_WRAPPABLE_BYTES = 318;

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(RSA_OAEP_PARAMS, true, ["encrypt", "decrypt"]) as Promise<CryptoKeyPair>;
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey("spki", key);
  return toBase64(new Uint8Array(spki));
}

export async function importPublicKey(base64Spki: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    fromBase64(base64Spki),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
}

export async function exportPrivateKeyPkcs8(key: CryptoKey): Promise<Uint8Array> {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
  return new Uint8Array(pkcs8);
}

/** Imports a decrypted private key for this session only — non-extractable. */
export async function importPrivateKeyPkcs8(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
}

/** Wraps a small AES key (Item Key or Group KEK) for one recipient. */
export async function wrapKey(rawKeyBytes: Uint8Array, recipientPublicKey: CryptoKey): Promise<string> {
  if (rawKeyBytes.length > MAX_WRAPPABLE_BYTES) {
    throw new Error(
      `Payload of ${rawKeyBytes.length} bytes exceeds RSA-OAEP-3072's direct capacity — ` +
        "wrap a symmetric key and encrypt the payload with that instead.",
    );
  }
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPublicKey, rawKeyBytes);
  return toBase64(new Uint8Array(wrapped));
}

export async function unwrapKey(wrappedBase64: string, privateKey: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, fromBase64(wrappedBase64));
  return new Uint8Array(raw);
}
