/** Packs/unpacks an item's plaintext fields to and from its encrypted JSON envelope. */
import { decryptString, encryptString, type EncryptedPayload } from "./aes";
import type { ItemEnvelope } from "../types/vaultItem";

export async function encryptEnvelope(
  itemKey: CryptoKey,
  envelope: ItemEnvelope,
): Promise<EncryptedPayload> {
  return encryptString(itemKey, JSON.stringify(envelope));
}

export async function decryptEnvelope(
  itemKey: CryptoKey,
  nonce: string,
  ciphertext: string,
): Promise<ItemEnvelope> {
  const json = await decryptString(itemKey, nonce, ciphertext);
  return JSON.parse(json) as ItemEnvelope;
}
