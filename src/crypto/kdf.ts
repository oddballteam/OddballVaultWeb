/**
 * Argon2id key derivation for the Master Key.
 *
 * Web Crypto has no native Argon2 (only PBKDF2), so this wraps hash-wasm's
 * WASM implementation — the browser equivalent of the desktop app's
 * argon2-cffi usage. Never roll your own primitive here.
 */
import { argon2id } from "hash-wasm";

export const KDF_DEFAULTS = {
  timeCost: 3,
  memoryCostKib: 65_536, // 64 MB
  parallelism: 2,
  hashLengthBytes: 32, // 256-bit output
  saltLengthBytes: 16,
} as const;

export function generateSalt(length: number = KDF_DEFAULTS.saltLengthBytes): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export interface KdfParams {
  timeCost: number;
  memoryCostKib: number;
  parallelism: number;
  hashLengthBytes: number;
}

export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: KdfParams = KDF_DEFAULTS,
): Promise<Uint8Array> {
  if (!password) throw new Error("Password must not be empty.");
  if (salt.length < 8) throw new Error("Salt must be at least 8 bytes.");

  const hash = await argon2id({
    password,
    salt,
    iterations: params.timeCost,
    memorySize: params.memoryCostKib,
    parallelism: params.parallelism,
    hashLength: params.hashLengthBytes,
    outputType: "binary",
  });
  return hash;
}
