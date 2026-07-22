import { Dices } from "lucide-react";
import { useState, type ReactNode } from "react";
import { PasswordGeneratorModal } from "./PasswordGeneratorModal";

const CLIPBOARD_CLEAR_MS = 30_000;

export function PasswordField({
  label,
  value,
  onChange,
  readOnly,
  allowGenerate = false,
  multiline = false,
}: {
  /** Usually a string, but can be an editable <input> (e.g. custom fields' user-named label) instead of static text. */
  label: ReactNode;
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  /** Only real login passwords get the generator — card numbers, CVVs, PINs, TOTP secrets, and private keys aren't passwords. */
  allowGenerate?: boolean;
  /** Secure-note-style content: multi-line, so it can't use <input type="password">'s native masking. */
  multiline?: boolean;
}) {
  const [visible, setVisible] = useState(false);
  const [generatorOpen, setGeneratorOpen] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => undefined);
    }, CLIPBOARD_CLEAR_MS);
  }

  return (
    <div className="field-row">
      <label>{label}</label>
      {multiline ? (
        readOnly ? (
          // ponytail: dot-replacement masking is only safe when truly read-only — typing into a
          // dot-replaced value would corrupt the real content, since a textarea has no native
          // mask like <input type="password"> does. Editable mode below is never masked instead.
          <textarea rows={4} value={visible ? value : "•".repeat(value.length)} readOnly />
        ) : (
          <textarea rows={4} value={value} onChange={(e) => onChange?.(e.target.value)} />
        )
      ) : (
        <input
          type={visible ? "text" : "password"}
          value={value}
          readOnly={readOnly}
          onChange={(e) => onChange?.(e.target.value)}
        />
      )}
      <div className="field-actions">
        {/* Multiline content is never masked while editable — the toggle would be a no-op then. */}
        {(!multiline || readOnly) && (
          <button type="button" className="secondary" onClick={() => setVisible((v) => !v)}>
            {visible ? "Hide" : "Reveal"}
          </button>
        )}
        <button type="button" className="secondary" onClick={() => void copy()}>
          Copy
        </button>
        {allowGenerate && onChange && !readOnly && (
          <button
            type="button"
            className="icon-button"
            title="Generate a password"
            aria-label="Generate a password"
            onClick={() => setGeneratorOpen(true)}
          >
            <Dices size={18} />
          </button>
        )}
      </div>
      {generatorOpen && (
        <PasswordGeneratorModal
          onUse={(generated) => {
            onChange?.(generated);
            setGeneratorOpen(false);
          }}
          onClose={() => setGeneratorOpen(false)}
        />
      )}
    </div>
  );
}
