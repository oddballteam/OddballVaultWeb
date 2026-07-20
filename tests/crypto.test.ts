import { describe, expect, it } from "vitest";
import { decryptBytes, encryptBytes, generateAesKeyBytes, importAesKey } from "../src/crypto/aes";
import { decryptEnvelope, encryptEnvelope } from "../src/crypto/envelope";
import { createGroupKeyMaterial, unwrapGroupPrivateKey, unwrapKekForMember, wrapKekForMember } from "../src/crypto/groupKeys";
import { deriveMasterKey, generateSalt } from "../src/crypto/kdf";
import { generateKeyPair, unwrapKey, wrapKey } from "../src/crypto/rsa";
import { emptyEnvelope } from "../src/types/vaultItem";

describe("AES-256-GCM", () => {
  it("round-trips plaintext and rejects a tampered ciphertext", async () => {
    const key = await importAesKey(generateAesKeyBytes());
    const plaintext = new TextEncoder().encode("correct horse battery staple");
    const { nonce, ciphertext } = await encryptBytes(key, plaintext);

    const decrypted = await decryptBytes(key, nonce, ciphertext);
    expect(new TextDecoder().decode(decrypted)).toBe("correct horse battery staple");

    const tampered = ciphertext.slice(0, -4) + "AAAA";
    await expect(decryptBytes(key, nonce, tampered)).rejects.toThrow();
  });
});

describe("Argon2id KDF", () => {
  it("is deterministic for the same password and salt", async () => {
    const salt = generateSalt();
    const a = await deriveMasterKey("hunter2-hunter2-hunter2", salt);
    const b = await deriveMasterKey("hunter2-hunter2-hunter2", salt);
    expect(Array.from(a)).toEqual(Array.from(b));
  });
});

describe("RSA-OAEP-3072 key wrapping", () => {
  it("wraps and unwraps a 32-byte Item Key", async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const itemKey = generateAesKeyBytes();

    const wrapped = await wrapKey(itemKey, publicKey);
    const unwrapped = await unwrapKey(wrapped, privateKey);
    expect(Array.from(unwrapped)).toEqual(Array.from(itemKey));
  });
});

describe("Group KEK two-layer wrap", () => {
  it("lets a member recover the group's private key via their own keypair", async () => {
    const member = await generateKeyPair();
    const group = await createGroupKeyMaterial();

    const wrappedForMember = await wrapKekForMember(group.kek, member.publicKey);
    const recoveredKek = await unwrapKekForMember(wrappedForMember, member.privateKey);
    expect(Array.from(recoveredKek)).toEqual(Array.from(group.kek));

    const groupPrivateKey = await unwrapGroupPrivateKey(
      group.encryptedPrivateKeyNonce,
      group.encryptedPrivateKey,
      recoveredKek,
    );
    expect(groupPrivateKey.type).toBe("private");
  });
});

describe("Item envelope", () => {
  it("round-trips the full plaintext JSON under an Item Key", async () => {
    const itemKey = await importAesKey(generateAesKeyBytes());
    const envelope = { ...emptyEnvelope("My Bank Login"), username: "alice", password: "s3cr3t" };

    const { nonce, ciphertext } = await encryptEnvelope(itemKey, envelope);
    const recovered = await decryptEnvelope(itemKey, nonce, ciphertext);
    expect(recovered).toEqual(envelope);
  });
});
