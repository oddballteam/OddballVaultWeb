import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { AdminRoute, getUserGroups, hasAdminGroup } from "./auth/adminAccess";
import { useAuth } from "./auth/AuthProvider";
import { env } from "./config/env";
import { vaultSession } from "./crypto/session";
import { hasAccount } from "./services/accountService";
import { AdminDashboardView } from "./views/AdminDashboardView";
import { LoginView } from "./views/LoginView";
import { SetupAccountView } from "./views/SetupAccountView";
import { SSORedirectView } from "./views/SSORedirectView";
import { UnlockView } from "./views/UnlockView";
import { VaultShell } from "./views/VaultShell";

export default function App() {
  return (
    <Routes>
      {/* Target of Okta's IdP-initiated "Initiate Login URI" tile — must be
          reachable before the auth gate below, since landing here means
          "not authenticated yet, start a fresh login." */}
      <Route path="/sso" element={<SSORedirectView />} />
      <Route path="/*" element={<AuthenticatedApp />} />
    </Routes>
  );
}

function AuthenticatedApp() {
  const { user, session, isLoading, logout } = useAuth();
  const [accountChecked, setAccountChecked] = useState(false);
  const [accountExists, setAccountExists] = useState(false);
  const [unlocked, setUnlocked] = useState(false);

  const userId = user?.id ?? null;
  const email = user?.email ?? "";
  const userGroups = getUserGroups(session);
  const isAdmin = hasAdminGroup(session);

  useEffect(() => {
    if (!userId) return;
    if (env.mockAuthEnabled) {
      // Skip the Supabase-backed setup/unlock gate entirely — there's no
      // real backend behind the placeholder URL to check against.
      setAccountExists(true);
      setAccountChecked(true);
      setUnlocked(true);
      return;
    }
    void hasAccount(userId).then((exists) => {
      setAccountExists(exists);
      setAccountChecked(true);
    });
  }, [userId]);

  // Single source of truth for "fully signed out": the header lock icon and
  // the idle auto-lock timeout both ultimately call vaultSession.lock(),
  // which fires this listener — so both paths end up here, not two
  // separately-maintained sign-out code paths.
  useEffect(
    () =>
      vaultSession.onLock(() => {
        setUnlocked(false);
        void logout();
      }),
    [logout],
  );

  if (isLoading) return <p className="centered-form">Loading…</p>;
  if (!user || !userId) return <LoginView />;
  if (!accountChecked) return <p className="centered-form">Loading…</p>;

  if (!accountExists) {
    return <SetupAccountView userId={userId} email={email} onDone={() => { setAccountExists(true); }} />;
  }

  if (!unlocked && !env.mockAuthEnabled) {
    return <UnlockView userId={userId} onUnlocked={() => setUnlocked(true)} />;
  }

  return (
    <Routes>
      <Route
        path="/admin"
        element={
          <AdminRoute isAdmin={isAdmin}>
            <AdminDashboardView />
          </AdminRoute>
        }
      />
      <Route
        path="/*"
        element={<VaultShell userId={userId} userEmail={email} userGroups={userGroups} isAdmin={isAdmin} />}
      />
    </Routes>
  );
}
