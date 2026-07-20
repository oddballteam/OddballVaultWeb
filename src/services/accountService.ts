/** Account setup and unlock — the web equivalent of vault_service.py's vault-lifecycle methods. */
import { supabase } from "../api/supabase";
import { fromBase64, toBase64 } from "../crypto/base64";
import { createAccountKeyMaterial, VaultKeyError, type UnlockRecord } from "../crypto/vaultKey";
import { vaultSession } from "../crypto/session";
import type { AppUserRow } from "../types/db";
import { logEvent } from "./auditService";

export async function hasAccount(userId: string): Promise<boolean> {
  const { data, error } = await supabase.from("app_users").select("id").eq("id", userId).maybeSingle();
  if (error) throw error;
  return data !== null;
}

/** Runs once, the first time a given Okta identity signs in. */
export async function setupAccount(userId: string, email: string, masterPassword: string): Promise<void> {
  const material = await createAccountKeyMaterial(masterPassword);

  const { error: dirError } = await supabase
    .from("user_directory")
    .insert({ id: userId, email, public_key: material.publicKeySpki });
  if (dirError) throw dirError;

  const { error: userError } = await supabase.from("app_users").insert({
    id: userId,
    encrypted_private_key: material.encryptedPrivateKey,
    private_key_nonce: material.encryptedPrivateKeyNonce,
    kdf_salt: toBase64(material.kdfSalt),
    kdf_time_cost: material.kdfParams.timeCost,
    kdf_memory_cost: material.kdfParams.memoryCostKib,
    kdf_parallelism: material.kdfParams.parallelism,
    key_check_ciphertext: material.keyCheckCiphertext,
    key_check_nonce: material.keyCheckNonce,
  });
  if (userError) throw userError;
}

export async function unlock(userId: string, masterPassword: string): Promise<void> {
  const { data, error } = await supabase.from("app_users").select("*").eq("id", userId).single();
  if (error) throw error;
  const row = data as AppUserRow;

  const record: UnlockRecord = {
    kdfSalt: fromBase64(row.kdf_salt),
    kdfParams: {
      timeCost: row.kdf_time_cost,
      memoryCostKib: row.kdf_memory_cost,
      parallelism: row.kdf_parallelism,
      hashLengthBytes: 32,
    },
    keyCheckNonce: row.key_check_nonce,
    keyCheckCiphertext: row.key_check_ciphertext,
    encryptedPrivateKeyNonce: row.private_key_nonce,
    encryptedPrivateKey: row.encrypted_private_key,
  };

  try {
    await vaultSession.unlock(masterPassword, record);
  } catch (err) {
    if (err instanceof VaultKeyError) await logEvent(userId, "failed_unlock");
    throw err;
  }
  await logEvent(userId, "unlock");
}

export function lock(userId: string): void {
  vaultSession.lock();
  void logEvent(userId, "lock");
}
