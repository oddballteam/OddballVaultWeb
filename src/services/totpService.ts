/** RFC 6238 TOTP (RFC 4226 HOTP underneath) via native Web Crypto HMAC-SHA1. */

const STEP_SECONDS = 30;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export class TOTPError extends Error {}

export interface TOTPState {
  token: string;
  secondsRemaining: number;
  progress: number; // 0..1 fraction of the current window elapsed
}

function base32Decode(secret: string): Uint8Array {
  const cleaned = secret.trim().toUpperCase().replace(/=+$/, "");
  let bits = "";
  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new TOTPError("Invalid TOTP secret — must be Base32 encoded.");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

export function generateSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(20)); // 160-bit secret
  let output = "";
  for (const byte of bytes) output += BASE32_ALPHABET[byte % 32];
  return output;
}

async function hotp(keyBytes: Uint8Array, counter: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);

  const counterBuffer = new ArrayBuffer(8);
  new DataView(counterBuffer).setBigUint64(0, BigInt(counter), false);

  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBuffer));
  const offset = digest[19] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

export async function getCurrentState(secret: string): Promise<TOTPState> {
  if (!secret || !secret.trim()) throw new TOTPError("TOTP secret must not be empty.");
  const keyBytes = base32Decode(secret);
  const now = Date.now() / 1000;
  const counter = Math.floor(now / STEP_SECONDS);
  const elapsed = now % STEP_SECONDS;

  return {
    token: await hotp(keyBytes, counter),
    secondsRemaining: Math.floor(STEP_SECONDS - elapsed),
    progress: elapsed / STEP_SECONDS,
  };
}

export async function getToken(secret: string): Promise<string> {
  return (await getCurrentState(secret)).token;
}

export async function verifyToken(secret: string, token: string, validWindow = 1): Promise<boolean> {
  const keyBytes = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  for (let offset = -validWindow; offset <= validWindow; offset++) {
    if ((await hotp(keyBytes, counter + offset)) === token) return true;
  }
  return false;
}

export function getProvisioningUri(secret: string, accountName: string, issuer = "Oddball Vault"): string {
  const params = new URLSearchParams({ secret, issuer });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?${params.toString()}`;
}
