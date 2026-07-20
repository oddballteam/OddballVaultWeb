import { useState } from "react";
import { setupAccount } from "../services/accountService";
import { scorePassword } from "../services/generatorService";

const MASTER_PASSWORD_MIN_LEN = 12;
const STRENGTH_COLORS = ["#ef233c", "#f4a261", "#ffd166", "#06d6a0", "#4cc9f0"];

export function SetupAccountView({
  userId,
  email,
  onDone,
}: {
  userId: string;
  email: string;
  onDone: () => void;
}) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const strength = scorePassword(password);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < MASTER_PASSWORD_MIN_LEN) {
      setError(`Master password must be at least ${MASTER_PASSWORD_MIN_LEN} characters.`);
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await setupAccount(userId, email, password);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to set up account.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="centered-form">
      <h2>Create your master password</h2>
      <p className="muted">
        Your Okta login secures your account access. Now, create a Master Password to locally
        encrypt your vault. Because we are Zero-Knowledge, not even our servers can read this
        password — do not lose it, since your vault cannot be recovered without it.
      </p>
      <form onSubmit={(e) => void handleSubmit(e)}>
        <div className="field-row">
          <label htmlFor="password">Master password</label>
          <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          <div className="strength-bar">
            <div style={{ width: `${(strength.score + 1) * 20}%`, background: STRENGTH_COLORS[strength.score] }} />
          </div>
          <span className="muted">{strength.label}</span>
        </div>
        <div className="field-row">
          <label htmlFor="confirm">Confirm master password</label>
          <input id="confirm" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </div>
        {error && <p className="error-text">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? "Setting up…" : "Create vault"}</button>
      </form>
    </div>
  );
}
