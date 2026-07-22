import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { PasswordField } from "../components/PasswordField";
import { claimExternalShare, decryptClaimedShare } from "../services/externalShareService";
import type { ItemEnvelope } from "../types/vaultItem";

type FieldConfig = { key: keyof ItemEnvelope; label: string; sensitive?: boolean };

// No itemType is carried in the share (ItemEnvelope has no such field) — this
// is a flat superset covering every record type, filtered to whichever
// fields the shared record actually had a value for.
const ALL_FIELDS: FieldConfig[] = [
  { key: "username", label: "Username" },
  { key: "password", label: "Password", sensitive: true },
  { key: "url", label: "URL" },
  { key: "totpSecret", label: "TOTP secret", sensitive: true },
  { key: "cardholderName", label: "Cardholder name" },
  { key: "cardNumber", label: "Card number", sensitive: true },
  { key: "cardExpiry", label: "Expiry (MM/YY)" },
  { key: "cardCvv", label: "CVV", sensitive: true },
  { key: "cardPin", label: "PIN", sensitive: true },
  { key: "fullName", label: "Full name" },
  { key: "email", label: "Email" },
  { key: "phone", label: "Phone" },
  { key: "addressLine1", label: "Address line 1" },
  { key: "addressLine2", label: "Address line 2" },
  { key: "city", label: "City" },
  { key: "state", label: "State" },
  { key: "postalCode", label: "Postal code" },
  { key: "country", label: "Country" },
  { key: "sshHost", label: "Host" },
  { key: "sshPublicKey", label: "Public key" },
  { key: "sshPrivateKey", label: "Private key", sensitive: true },
  { key: "serviceName", label: "Service name" },
  { key: "keyName", label: "Key name" },
  { key: "keyValue", label: "Key value", sensitive: true },
  { key: "endpoint", label: "Endpoint" },
];

type LoadState = "loading" | "invalid" | { envelope: ItemEnvelope };

export function SharedLinkView() {
  const { id } = useParams<{ id: string }>();
  const [state, setState] = useState<LoadState>("loading");
  const claimedRef = useRef(false);

  useEffect(() => {
    // Claiming burns the link server-side — must fire at most once even
    // under StrictMode's deliberate double-invoke of effects in development.
    // (A `cancelled`-on-cleanup guard would drop the real result here: the
    // first invocation's cleanup fires before its in-flight claim resolves,
    // and the second invocation is a no-op because claimedRef is already set.)
    if (claimedRef.current) return;
    claimedRef.current = true;
    async function load() {
      const keyBase64 = window.location.hash.slice(1);
      if (!id || !keyBase64) {
        setState("invalid");
        return;
      }
      try {
        const claim = await claimExternalShare(id);
        if (!claim) {
          setState("invalid");
          return;
        }
        const envelope = await decryptClaimedShare(claim, keyBase64);
        setState({ envelope });
      } catch {
        setState("invalid");
      }
    }
    void load();
  }, [id]);

  return (
    <div style={{ maxWidth: "640px", margin: "2rem auto", padding: "0 1rem" }}>
      <div className="brand-lockup">
        <img src="/source_logo.png" alt="Oddball Vault" />
        <strong>Oddball Vault</strong>
      </div>

      {state === "loading" && <p className="muted centered-form">Loading…</p>}

      {state === "invalid" && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Link unavailable</h3>
          <p className="muted">
            This link is invalid, has expired, or has already been used. One-time links can only
            be opened once — ask whoever sent it to create a new one if you still need access.
          </p>
        </div>
      )}

      {typeof state === "object" && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>{state.envelope.title}</h3>
          <p className="muted">
            This one-time link has now been used and won't work again. Save anything you need from
            it now.
          </p>

          {ALL_FIELDS.filter((f) => Boolean(state.envelope[f.key])).map((field) =>
            field.sensitive ? (
              <PasswordField key={field.key} label={field.label} value={state.envelope[field.key] as string} readOnly />
            ) : (
              <div className="field-row" key={field.key}>
                <label>{field.label}</label>
                <input value={state.envelope[field.key] as string} readOnly />
              </div>
            ),
          )}

          {state.envelope.notes && (
            <PasswordField label="Notes" value={state.envelope.notes} readOnly multiline />
          )}

          {state.envelope.tags.length > 0 && (
            <div className="field-row">
              <label>Tags</label>
              <input value={state.envelope.tags.join(", ")} readOnly />
            </div>
          )}

          {state.envelope.customFields
            .filter((f) => f.value)
            .map((field, index) =>
              field.isSensitive ? (
                <PasswordField key={index} label={field.label} value={field.value} readOnly />
              ) : (
                <div className="field-row" key={index}>
                  <label>{field.label}</label>
                  <input value={field.value} readOnly />
                </div>
              ),
            )}
        </div>
      )}
    </div>
  );
}
