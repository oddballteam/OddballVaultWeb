import { VaultSession } from "./vaultKey";

/** App-wide singleton — the one place the unlocked RSA private key lives. */
export const vaultSession = new VaultSession();
