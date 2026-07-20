/**
 * Group Folder key management — the two-layer scheme described in the
 * approved architecture: a group's RSA private key is too large to wrap
 * directly with RSA-OAEP for each member, so it's AES-GCM-encrypted once
 * under a random 32-byte Group KEK, and only that small KEK gets
 * RSA-OAEP-wrapped per member.
 */
import { decryptBytes, encryptBytes, generateAesKeyBytes, importAesKey } from "./aes";
import { exportPrivateKeyPkcs8, exportPublicKey, generateKeyPair, importPrivateKeyPkcs8, unwrapKey, wrapKey } from "./rsa";

export interface NewGroupKeyMaterial {
  publicKeySpki: string;
  encryptedPrivateKeyNonce: string;
  encryptedPrivateKey: string;
  /** Raw KEK bytes — caller must wrap this for the initial admin(s) via wrapKekForMember, then discard. */
  kek: Uint8Array;
}

/** Called once, when provisioning a new Group Folder. */
export async function createGroupKeyMaterial(): Promise<NewGroupKeyMaterial> {
  const keyPair = await generateKeyPair();
  const publicKeySpki = await exportPublicKey(keyPair.publicKey);
  const privateKeyPkcs8 = await exportPrivateKeyPkcs8(keyPair.privateKey);

  const kek = generateAesKeyBytes();
  const kekAesKey = await importAesKey(kek);
  const wrappedPrivateKey = await encryptBytes(kekAesKey, privateKeyPkcs8);

  return {
    publicKeySpki,
    encryptedPrivateKeyNonce: wrappedPrivateKey.nonce,
    encryptedPrivateKey: wrappedPrivateKey.ciphertext,
    kek,
  };
}

/** Wraps the group KEK for one member's public key — the only per-member cost of adding someone. */
export async function wrapKekForMember(kek: Uint8Array, memberPublicKey: CryptoKey): Promise<string> {
  return wrapKey(kek, memberPublicKey);
}

/** Unwraps a member's copy of the group KEK using their own RSA private key. */
export async function unwrapKekForMember(wrappedKek: string, memberPrivateKey: CryptoKey): Promise<Uint8Array> {
  return unwrapKey(wrappedKek, memberPrivateKey);
}

/** Recovers the group's RSA private key from its KEK — needed to unwrap group-targeted Item Keys. */
export async function unwrapGroupPrivateKey(
  encryptedPrivateKeyNonce: string,
  encryptedPrivateKey: string,
  kek: Uint8Array,
): Promise<CryptoKey> {
  const kekAesKey = await importAesKey(kek);
  const pkcs8 = await decryptBytes(kekAesKey, encryptedPrivateKeyNonce, encryptedPrivateKey);
  return importPrivateKeyPkcs8(pkcs8);
}
