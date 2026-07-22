import { useState } from "react";
import { createExternalShare } from "../services/externalShareService";
import type { ItemEnvelope } from "../types/vaultItem";
import { Dropdown } from "./Dropdown";

const EXPIRY_OPTIONS = [
  { value: "1", label: "1 hour" },
  { value: "24", label: "24 hours (default)" },
  { value: "168", label: "7 days (max)" },
];

/** Rendered in place of ShareDialog's normal content when its globe toggle is active — no header/close of its own, ShareDialog owns the title. */
export function ExternalShareDialog({
  envelope,
  itemId,
  userId,
}: {
  envelope: ItemEnvelope;
  itemId: string;
  userId: string;
}) {
  const [expiryHours, setExpiryHours] = useState("24");
  const [url, setUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCreate() {
    setBusy(true);
    setError(null);
    try {
      const link = await createExternalShare(envelope, itemId, userId, Number(expiryHours));
      setUrl(link);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create share link.");
    } finally {
      setBusy(false);
    }
  }

  async function handleCopy() {
    if (!url) return;
    await navigator.clipboard.writeText(url);
    setCopied(true);
  }

  return (
    <div>
      <p className="muted">
        Creates a one-time link anyone can open without an account. It includes the whole record
        (all fields, notes, tags) and stops working after a single view or when it expires,
        whichever comes first.
      </p>

      {!url ? (
        <>
          <div className="field-row">
            <label>Expires in</label>
            <Dropdown<string>
              label={EXPIRY_OPTIONS.find((o) => o.value === expiryHours)?.label ?? "24 hours (default)"}
              options={EXPIRY_OPTIONS}
              onSelect={setExpiryHours}
            />
          </div>
          {error && <p className="error-text">{error}</p>}
          <button disabled={busy} onClick={() => void handleCreate()}>
            {busy ? "Creating…" : "Create Link"}
          </button>
        </>
      ) : (
        <>
          <p className="muted">
            Anyone with this link can view this record once. It can't be retrieved again once
            opened or after it expires.
          </p>
          <div className="field-row">
            <label>One-time link</label>
            <input value={url} readOnly onFocus={(e) => e.target.select()} />
          </div>
          <div className="field-actions">
            <button className="secondary" onClick={() => void handleCopy()}>{copied ? "Copied" : "Copy"}</button>
          </div>
        </>
      )}
    </div>
  );
}
