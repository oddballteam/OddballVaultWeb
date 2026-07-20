/**
 * Session-scoped holder for the unlocked vault: the RSA private key used to
 * unwrap Item Keys and Group KEKs. Mirrors the desktop app's VaultKey class —
 * same idle auto-lock behaviour, same "best-effort zeroing, not a hard
 * guarantee" caveat (JS has no ctypes.memset either; overwriting a
 * Uint8Array before dropping the reference narrows the exposure window but
 * can't force garbage collection).
 */
import { decryptBytes, encryptBytes, importAesKey } from "./aes";
import { deriveMasterKey, generateSalt, KDF_DEFAULTS, type KdfParams } from "./kdf";
import { exportPrivateKeyPkcs8, exportPublicKey, generateKeyPair, importPrivateKeyPkcs8 } from "./rsa";

export const AUTO_LOCK_DEFAULT_MINUTES = 5;
export const AUTO_LOCK_MIN_MINUTES = 1;
export const AUTO_LOCK_MAX_MINUTES = 10;
export const AUTO_LOCK_OPTIONS_MINUTES = [1, 2, 5, 10] as const;

const KEY_CHECK_PLAINTEXT = "KEY_CHECK_OK";

export class VaultKeyError extends Error {}

export interface StoredAccountCrypto {
  kdfSalt: Uint8Array;
  kdfParams: KdfParams;
  keyCheckNonce: string;
  keyCheckCiphertext: string;
  encryptedPrivateKeyNonce: string;
  encryptedPrivateKey: string;
  publicKeySpki: string;
}

/** Called once, at account setup, before anything is persisted to Supabase. */
export async function createAccountKeyMaterial(password: string): Promise<StoredAccountCrypto> {
  const kdfSalt = generateSalt();
  const masterKeyBytes = await deriveMasterKey(password, kdfSalt);
  const masterAesKey = await importAesKey(masterKeyBytes);

  const keyPair = await generateKeyPair();
  const publicKeySpki = await exportPublicKey(keyPair.publicKey);
  const privateKeyPkcs8 = await exportPrivateKeyPkcs8(keyPair.privateKey);

  const keyCheck = await encryptBytes(masterAesKey, new TextEncoder().encode(KEY_CHECK_PLAINTEXT));
  const wrappedPrivateKey = await encryptBytes(masterAesKey, privateKeyPkcs8);

  zeroBytes(masterKeyBytes);
  zeroBytes(privateKeyPkcs8);

  return {
    kdfSalt,
    kdfParams: KDF_DEFAULTS,
    keyCheckNonce: keyCheck.nonce,
    keyCheckCiphertext: keyCheck.ciphertext,
    encryptedPrivateKeyNonce: wrappedPrivateKey.nonce,
    encryptedPrivateKey: wrappedPrivateKey.ciphertext,
    publicKeySpki,
  };
}

export interface UnlockRecord {
  kdfSalt: Uint8Array;
  kdfParams: KdfParams;
  keyCheckNonce: string;
  keyCheckCiphertext: string;
  encryptedPrivateKeyNonce: string;
  encryptedPrivateKey: string;
}

type LockListener = () => void;

export class VaultSession {
  private rsaPrivateKey: CryptoKey | null = null;
  private idleTimeoutHandle: ReturnType<typeof setTimeout> | null = null;
  private idleMinutes: number = AUTO_LOCK_DEFAULT_MINUTES;
  private lockListeners: LockListener[] = [];
  private activityHandler = () => this.resetIdleTimer();

  isUnlocked(): boolean {
    return this.rsaPrivateKey !== null;
  }

  async unlock(password: string, record: UnlockRecord): Promise<void> {
    if (this.rsaPrivateKey !== null) {
      throw new VaultKeyError("Vault is already unlocked; call lock() first.");
    }

    const masterKeyBytes = await deriveMasterKey(password, record.kdfSalt, record.kdfParams);
    const masterAesKey = await importAesKey(masterKeyBytes);

    let checkPlaintext: string;
    try {
      const decrypted = await decryptBytes(masterAesKey, record.keyCheckNonce, record.keyCheckCiphertext);
      checkPlaintext = new TextDecoder().decode(decrypted);
    } catch {
      zeroBytes(masterKeyBytes);
      throw new VaultKeyError("Incorrect master password.");
    }
    if (checkPlaintext !== KEY_CHECK_PLAINTEXT) {
      zeroBytes(masterKeyBytes);
      throw new VaultKeyError("Incorrect master password.");
    }

    const privateKeyPkcs8 = await decryptBytes(
      masterAesKey,
      record.encryptedPrivateKeyNonce,
      record.encryptedPrivateKey,
    );
    this.rsaPrivateKey = await importPrivateKeyPkcs8(privateKeyPkcs8);

    zeroBytes(masterKeyBytes);
    zeroBytes(privateKeyPkcs8);
    this.startIdleTracking();
  }

  lock(): void {
    this.rsaPrivateKey = null;
    this.stopIdleTracking();
    for (const listener of this.lockListeners) listener();
  }

  getPrivateKey(): CryptoKey {
    if (!this.rsaPrivateKey) throw new VaultKeyError("Vault is locked.");
    return this.rsaPrivateKey;
  }

  onLock(listener: LockListener): () => void {
    this.lockListeners.push(listener);
    return () => {
      this.lockListeners = this.lockListeners.filter((l) => l !== listener);
    };
  }

  setAutoLockMinutes(minutes: number): void {
    if (minutes < AUTO_LOCK_MIN_MINUTES || minutes > AUTO_LOCK_MAX_MINUTES) {
      throw new RangeError(`Auto-lock must be between ${AUTO_LOCK_MIN_MINUTES} and ${AUTO_LOCK_MAX_MINUTES} minutes.`);
    }
    this.idleMinutes = minutes;
    if (this.isUnlocked()) this.resetIdleTimer();
  }

  private startIdleTracking(): void {
    window.addEventListener("mousemove", this.activityHandler);
    window.addEventListener("keydown", this.activityHandler);
    this.resetIdleTimer();
  }

  private stopIdleTracking(): void {
    window.removeEventListener("mousemove", this.activityHandler);
    window.removeEventListener("keydown", this.activityHandler);
    if (this.idleTimeoutHandle !== null) clearTimeout(this.idleTimeoutHandle);
    this.idleTimeoutHandle = null;
  }

  private resetIdleTimer(): void {
    if (this.idleTimeoutHandle !== null) clearTimeout(this.idleTimeoutHandle);
    this.idleTimeoutHandle = setTimeout(() => this.lock(), this.idleMinutes * 60_000);
  }
}

/** Best-effort zeroing — narrows the exposure window, not a hard guarantee (see module docstring). */
function zeroBytes(bytes: Uint8Array): void {
  crypto.getRandomValues(bytes);
  bytes.fill(0);
}
