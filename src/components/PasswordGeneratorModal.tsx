import { X } from "lucide-react";
import { useState } from "react";
import {
  defaultPassphraseOptions,
  defaultPasswordOptions,
  generatePassphrase,
  generatePassword,
  scorePassword,
  type PassphraseOptions,
  type PasswordOptions,
} from "../services/generatorService";

const STRENGTH_COLORS = ["#ef233c", "#f4a261", "#ffd166", "#06d6a0", "#4cc9f0"];

export function PasswordGeneratorModal({
  onUse,
  onClose,
}: {
  onUse: (password: string) => void;
  onClose: () => void;
}) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [passwordOpts, setPasswordOpts] = useState<PasswordOptions>(defaultPasswordOptions);
  const [passphraseOpts, setPassphraseOpts] = useState<PassphraseOptions>(defaultPassphraseOptions);
  const [result, setResult] = useState(() => generatePassword(defaultPasswordOptions));

  function regenerate(opts = passwordOpts, phraseOpts = passphraseOpts, m = mode) {
    setResult(m === "password" ? generatePassword(opts) : generatePassphrase(phraseOpts));
  }

  const strength = scorePassword(result);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card compact-card modal-card" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h2 style={{ margin: 0 }}>Password Generator</h2>
          <button type="button" className="icon-button" aria-label="Close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="field-actions" style={{ justifyContent: "center", marginBottom: "1rem" }}>
          <button className={mode === "password" ? "" : "secondary"} onClick={() => { setMode("password"); regenerate(passwordOpts, passphraseOpts, "password"); }}>
            Password
          </button>
          <button className={mode === "passphrase" ? "" : "secondary"} onClick={() => { setMode("passphrase"); regenerate(passwordOpts, passphraseOpts, "passphrase"); }}>
            Passphrase
          </button>
        </div>

        <div className="field-row">
          <input readOnly value={result} style={{ fontFamily: "Consolas, monospace", textAlign: "center" }} />
        </div>
        <div className="strength-bar">
          <div style={{ width: `${(strength.score + 1) * 20}%`, background: STRENGTH_COLORS[strength.score] }} />
        </div>
        <p className="muted" style={{ textAlign: "center", marginTop: 0 }}>{strength.label} · {strength.entropyBits} bits entropy</p>

        <div className="field-actions" style={{ justifyContent: "center" }}>
          <button onClick={() => regenerate(passwordOpts, passphraseOpts, mode)}>Regenerate</button>
          <button className="secondary" onClick={() => void navigator.clipboard.writeText(result)}>Copy</button>
        </div>

        {mode === "password" ? (
          <>
            <div className="field-row">
              <label>Length: {passwordOpts.length}</label>
              <input
                type="range"
                min={8}
                max={128}
                value={passwordOpts.length}
                onChange={(e) => {
                  const next = { ...passwordOpts, length: Number(e.target.value) };
                  setPasswordOpts(next);
                  regenerate(next, passphraseOpts, "password");
                }}
              />
            </div>
            <div className="checkbox-grid">
              {(["uppercase", "lowercase", "digits", "symbols", "excludeAmbiguous"] as const).map((opt) => (
                <label key={opt} className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={passwordOpts[opt]}
                    onChange={(e) => {
                      const next = { ...passwordOpts, [opt]: e.target.checked };
                      setPasswordOpts(next);
                      regenerate(next, passphraseOpts, "password");
                    }}
                  />
                  {opt}
                </label>
              ))}
            </div>
          </>
        ) : (
          <div className="field-row">
            <label>Word count: {passphraseOpts.wordCount}</label>
            <input
              type="range"
              min={3}
              max={10}
              value={passphraseOpts.wordCount}
              onChange={(e) => {
                const next = { ...passphraseOpts, wordCount: Number(e.target.value) };
                setPassphraseOpts(next);
                regenerate(passwordOpts, next, "passphrase");
              }}
            />
          </div>
        )}

        <button style={{ width: "100%", marginTop: "0.5rem" }} onClick={() => onUse(result)}>
          Use Password
        </button>
      </div>
    </div>
  );
}
