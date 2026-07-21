import { Dices } from "lucide-react";
import { useState } from "react";
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
  label: string;
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
        // ponytail: masked by substituting dots rather than a native mask (textarea has none), so
        // editing while masked would edit the dots, not the real value — requires Reveal first.
        <textarea
          rows={4}
          value={visible ? value : "•".repeat(value.length)}
          readOnly={readOnly || !visible}
          onChange={(e) => onChange?.(e.target.value)}
        />
      ) : (
        <input
          type={visible ? "text" : "password"}
          value={value}
          readOnly={readOnly}
          onChange={(e) => onChange?.(e.target.value)}
        />
      )}
      <div className="field-actions">
        <button type="button" className="secondary" onClick={() => setVisible((v) => !v)}>
          {visible ? "Hide" : "Reveal"}
        </button>
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
