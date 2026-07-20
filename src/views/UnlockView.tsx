import { useState } from "react";
import { unlock } from "../services/accountService";

export function UnlockView({ userId, onUnlocked }: { userId: string; onUnlocked: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await unlock(userId, password);
      onUnlocked();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to unlock.");
    } finally {
      setBusy(false);
      setPassword("");
    }
  }

  return (
    <div className="centered-form">
      <h2>Unlock your vault</h2>
      <p className="muted">Enter your Master Password to decrypt your vault locally.</p>
      <form onSubmit={(e) => void handleSubmit(e)}>
        <div className="field-row">
          <label htmlFor="unlock-password">Master password</label>
          <input
            id="unlock-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
          />
        </div>
        {error && <p className="error-text">{error}</p>}
        <button type="submit" disabled={busy || !password}>{busy ? "Unlocking…" : "Unlock"}</button>
      </form>
    </div>
  );
}
