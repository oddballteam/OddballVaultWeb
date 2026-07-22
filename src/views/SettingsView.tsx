import { useEffect, useRef, useState } from "react";
import { Dropdown } from "../components/Dropdown";
import { InfoTooltip } from "../components/InfoTooltip";
import { vaultSession } from "../crypto/session";
import { AUTO_LOCK_DEFAULT_MINUTES, AUTO_LOCK_OPTIONS_MINUTES } from "../crypto/vaultKey";
import { getEvents } from "../services/auditService";
import { exportItems, importItems } from "../services/exportService";
import { listMyExternalShares, revokeExternalShare, type ExternalShareSummary } from "../services/externalShareService";
import { importCsv } from "../services/importService";
import { listItems } from "../services/vaultService";
import type { AuditLogRow } from "../types/db";

function shareStatus(share: ExternalShareSummary): "Used" | "Expired" | "Active" {
  if (share.burnedAt) return "Used";
  if (new Date(share.expiresAt) < new Date()) return "Expired";
  return "Active";
}

export function SettingsView({ userId }: { userId: string }) {
  const [events, setEvents] = useState<AuditLogRow[]>([]);
  const [autoLockMinutes, setAutoLockMinutes] = useState(AUTO_LOCK_DEFAULT_MINUTES);
  const [exportPassword, setExportPassword] = useState("");
  const [importPassword, setImportPassword] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [importBusy, setImportBusy] = useState(false);
  const [importFileName, setImportFileName] = useState<string | null>(null);
  const importFile = useRef<HTMLInputElement>(null);
  const [externalShares, setExternalShares] = useState<ExternalShareSummary[]>([]);
  const [shareError, setShareError] = useState<string | null>(null);

  useEffect(() => {
    void getEvents().then(setEvents);
    void refreshExternalShares();
  }, []);

  async function refreshExternalShares() {
    setExternalShares(await listMyExternalShares());
  }

  async function handleRevokeShare(id: string) {
    setShareError(null);
    try {
      await revokeExternalShare(id);
      await refreshExternalShares();
    } catch (err) {
      setShareError(err instanceof Error ? err.message : "Failed to revoke link.");
    }
  }

  function handleAutoLockChange(minutes: number) {
    setAutoLockMinutes(minutes);
    vaultSession.setAutoLockMinutes(minutes);
  }

  async function handleExportAll() {
    setStatus(null);
    try {
      const items = await listItems(userId);
      const blob = await exportItems(items.map((i) => i.id), exportPassword, userId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `oddball-vault-export-${Date.now()}.ovault`;
      a.click();
      URL.revokeObjectURL(url);
      setStatus(`Exported ${items.length} item(s).`);
    } catch (err) {
      setStatus(err instanceof Error ? `Export failed: ${err.message}` : "Export failed.");
    }
  }

  async function handleImport() {
    const file = importFile.current?.files?.[0];
    setImportError(null);
    setStatus(null);
    if (!file) {
      setImportError("Choose a file first.");
      return;
    }

    setImportBusy(true);
    try {
      if (file.name.toLowerCase().endsWith(".csv")) {
        const result = await importCsv(file, { type: "user", userId });
        setStatus(
          `Imported ${result.imported} item(s)` + (result.skipped ? `, skipped ${result.skipped}.` : "."),
        );
        if (result.errors.length > 0) setImportError(result.errors.join(" "));
      } else {
        if (!importPassword) {
          setImportError("Enter the export password for this .ovault file.");
          return;
        }
        const { imported } = await importItems(file, importPassword, { type: "user", userId }, userId);
        setStatus(`Imported ${imported} item(s).`);
      }
      if (importFile.current) importFile.current.value = "";
      setImportFileName(null);
    } catch (err) {
      setImportError(
        err instanceof Error
          ? err.message
          : "Import failed. Check that the file matches the expected format and try again.",
      );
    } finally {
      setImportBusy(false);
    }
  }

  return (
    <div className="detail-panel">
      <h2>Settings</h2>

      <div className="card">
        <h3>Auto-lock</h3>
        <div className="field-row">
          <label>Lock after this many minutes of inactivity (10 min hard cap)</label>
          <Dropdown<string>
            label={`${autoLockMinutes} min`}
            options={AUTO_LOCK_OPTIONS_MINUTES.map((m) => ({ value: String(m), label: `${m} min` }))}
            onSelect={(v) => handleAutoLockChange(Number(v))}
          />
        </div>
      </div>

      <div className="card">
        <h3>
          Export vault
          <InfoTooltip text="Decrypted, then re-encrypted under a separate export password. Never your master password." />
        </h3>
        <div className="field-row">
          <label>Export password</label>
          <input type="password" value={exportPassword} onChange={(e) => setExportPassword(e.target.value)} />
        </div>
        <button disabled={!exportPassword} onClick={() => void handleExportAll()}>Export all items</button>
      </div>

      <div className="card">
        <h3>
          Import vault
          <InfoTooltip
            text={
              <>
                Accepts either a <strong>.ovault</strong> file (this app's own encrypted export, needs the export
                password below) or a plain <strong>.csv</strong> export from another password manager. Expected CSV
                headers: <code>title</code> (or <code>name</code>), <code>username</code>, <code>password</code>,{" "}
                <code>url</code>, <code>notes</code>. Only the title column is required, the rest are optional.
              </>
            }
          />
        </h3>
        <div className="field-row">
          <label>File</label>
          <div className="file-picker-row">
            <label htmlFor="import-file" className="file-picker-button">Choose File</label>
            <input
              ref={importFile}
              id="import-file"
              type="file"
              accept=".ovault,.json,.csv"
              className="file-picker-input"
              onChange={(e) => setImportFileName(e.target.files?.[0]?.name ?? null)}
            />
            <span className="muted">{importFileName ?? "No file chosen"}</span>
          </div>
        </div>
        <div className="field-row">
          <label>Export password (only needed for .ovault files)</label>
          <input type="password" value={importPassword} onChange={(e) => setImportPassword(e.target.value)} />
        </div>
        {importError && <p className="error-text">{importError}</p>}
        <button disabled={importBusy} onClick={() => void handleImport()}>{importBusy ? "Importing…" : "Import"}</button>
      </div>

      {status && <p className="muted">{status}</p>}

      <div className="card">
        <h3>
          External share links
          <InfoTooltip text="One-time links created from a record's Share externally button. Each one stops working after a single view or its expiry, whichever comes first. Revoking one here disables it immediately, even if it was never opened." />
        </h3>
        {shareError && <p className="error-text">{shareError}</p>}
        {externalShares.length === 0 && <p className="muted">No share links yet.</p>}
        {externalShares.map((share) => {
          const status = shareStatus(share);
          return (
            <div className="grant-row" key={share.id}>
              <span>
                Created {new Date(share.createdAt).toLocaleString()}{" "}
                <span className="muted">({status}, expires {new Date(share.expiresAt).toLocaleString()})</span>
              </span>
              {status === "Active" && (
                <button className="danger" onClick={() => void handleRevokeShare(share.id)}>Revoke</button>
              )}
            </div>
          );
        })}
      </div>

      <div className="card">
        <h3>Audit log</h3>
        {events.map((event) => (
          <div className="audit-row" key={event.id}>
            <span>{event.event_type}</span>
            <span className="muted">{event.detail}</span>
            <span className="muted">{new Date(event.occurred_at).toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
