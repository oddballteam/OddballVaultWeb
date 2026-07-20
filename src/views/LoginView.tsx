import { useAuth } from "../auth/AuthProvider";

export function LoginView() {
  const { login } = useAuth();
  return (
    <div className="centered-form">
      <div className="brand-lockup">
        <img src="/source_logo.png" alt="Oddball Vault" />
        <h1>Oddball Vault</h1>
      </div>
      <p className="muted">Sign in with your organization's Okta account to continue.</p>
      <button onClick={() => void login()}>Sign in with Okta</button>
    </div>
  );
}
