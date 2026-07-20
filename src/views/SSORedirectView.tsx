import { useEffect } from "react";
import { useAuth } from "../auth/AuthProvider";

/**
 * Target of the Okta tile's "Initiate Login URI" (IdP-initiated flow) —
 * landing here should immediately kick off the OAuth redirect, not wait
 * for a button click. Runs once on mount regardless of auth state, since
 * the whole point of being here is "start a fresh login."
 */
export function SSORedirectView() {
  const { login } = useAuth();

  useEffect(() => {
    void login();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="centered-form">
      <p className="muted">Redirecting to your organization's sign-in…</p>
    </div>
  );
}
