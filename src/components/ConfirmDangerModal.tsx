import { AlertTriangle } from "lucide-react";
import { useState } from "react";

/**
 * Reusable "are you absolutely sure" gate for irreversible admin actions.
 * Requires typing the exact confirmation phrase before the destructive
 * button even becomes clickable — a single click on a red button is not
 * enough friction for something like wiping a user's entire vault.
 */
export function ConfirmDangerModal({
  title,
  message,
  confirmPhrase,
  confirmLabel,
  busy,
  onConfirm,
  onCancel,
}: {
  title: string;
  message: string;
  confirmPhrase: string;
  confirmLabel: string;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [typed, setTyped] = useState("");
  const matches = typed === confirmPhrase;

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="card compact-card modal-card danger-modal" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <AlertTriangle size={28} color="var(--danger)" />
          <h2 style={{ margin: 0, color: "var(--danger)" }}>{title}</h2>
        </div>
        <p style={{ marginTop: "0.75rem" }}>{message}</p>
        <div className="field-row">
          <label>
            Type <strong>{confirmPhrase}</strong> to confirm
          </label>
          <input value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus autoComplete="off" />
        </div>
        <div className="field-actions">
          <button className="secondary" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="danger" onClick={onConfirm} disabled={!matches || busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
