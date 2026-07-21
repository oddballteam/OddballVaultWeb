import { useEffect, useRef, useState } from "react";
import {
  deleteAttachment,
  downloadAttachment,
  listAttachments,
  uploadAttachment,
  type AttachmentSummary,
} from "../services/attachmentService";

export function AttachmentsPanel({ itemId, userId, canEdit }: { itemId: string; userId: string; canEdit: boolean }) {
  const [attachments, setAttachments] = useState<AttachmentSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  async function refresh() {
    setAttachments(await listAttachments(itemId, userId));
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [itemId]);

  async function handleUpload(file: File) {
    setBusy(true);
    try {
      await uploadAttachment(itemId, file, userId);
      await refresh();
    } finally {
      setBusy(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  async function handleDownload(attachmentId: string) {
    const { filename, bytes, mimeType } = await downloadAttachment(attachmentId, userId);
    const url = URL.createObjectURL(new Blob([bytes], { type: mimeType ?? "application/octet-stream" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleDelete(attachmentId: string) {
    setBusy(true);
    try {
      await deleteAttachment(attachmentId);
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h4>Attachments</h4>
      {attachments.map((att) => (
        <div className="grant-row" key={att.id}>
          <span>{att.filename} <span className="muted">({(att.sizeBytes / 1024).toFixed(1)} KB)</span></span>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button className="secondary" onClick={() => void handleDownload(att.id)}>Download</button>
            {canEdit && (
              <button className="danger" disabled={busy} onClick={() => void handleDelete(att.id)}>Delete</button>
            )}
          </div>
        </div>
      ))}
      {canEdit && (
        <div className="file-picker-row">
          <label htmlFor="attachment-file" className={`file-picker-button${busy ? " disabled" : ""}`}>
            Choose File
          </label>
          <input
            id="attachment-file"
            ref={fileInput}
            type="file"
            className="file-picker-input"
            disabled={busy}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleUpload(file);
            }}
          />
          <span className="muted">{busy ? "Uploading…" : "No file chosen"}</span>
        </div>
      )}
    </div>
  );
}
