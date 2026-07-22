import { useEffect, useState } from "react";
import { getCurrentState, type TOTPState } from "../services/totpService";

const CLIPBOARD_CLEAR_MS = 30_000;

export function TotpWidget({ secret }: { secret: string }) {
  const [state, setState] = useState<TOTPState | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const next = await getCurrentState(secret);
        if (!cancelled) setState(next);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Invalid TOTP secret.");
      }
    }
    void tick();
    const interval = setInterval(() => void tick(), 1000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [secret]);

  if (error) return <p className="error-text">{error}</p>;
  if (!state) return null;

  async function copy() {
    await navigator.clipboard.writeText(state!.token);
    setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => undefined);
    }, CLIPBOARD_CLEAR_MS);
  }

  return (
    <div className="field-row">
      <label>Authenticator code</label>
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
        <span style={{ fontFamily: "Consolas, monospace", fontSize: "1.4rem", letterSpacing: "0.15em" }}>
          {state.token}
        </span>
        <div className="strength-bar" style={{ flex: 1 }}>
          <div style={{ width: `${(1 - state.progress) * 100}%`, background: "var(--accent)" }} />
        </div>
        <span className="muted">{state.secondsRemaining}s</span>
      </div>
      <div className="field-actions">
        <button type="button" className="secondary" onClick={() => void copy()}>Copy</button>
      </div>
    </div>
  );
}
