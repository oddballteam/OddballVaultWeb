import { Lock, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { lock } from "../services/accountService";
import { GroupsView } from "./GroupsView";
import { SettingsView } from "./SettingsView";
import { VaultView } from "./VaultView";

type Nav = "vault" | "groups" | "settings";

export function VaultShell({
  userId,
  userEmail,
  // Not consumed here yet — accepted now so it's in place for the upcoming
  // RLS rewrite (see prop docblock below) without another prop-threading pass.
  userGroups: _userGroups,
  isAdmin,
}: {
  userId: string;
  userEmail: string;
  /**
   * Okta groups synced onto the session (auth.jwt() -> app_metadata ->
   * groups). Not yet consumed here — plumbed through in preparation for
   * the upcoming RLS rewrite that replaces the app-managed
   * group_memberships table with these directly.
   */
  userGroups: string[];
  isAdmin: boolean;
}) {
  const [nav, setNav] = useState<Nav>("vault");

  return (
    <div className="app-shell">
      <div className="topbar">
        <div className="topbar-brand">
          <img src="/source_logo.png" alt="Oddball Vault" />
          <strong>Oddball Vault</strong>
        </div>
        <div className="field-actions">
          {isAdmin && (
            <Link to="/admin" className="admin-link">
              <ShieldCheck size={16} />
              Admin
            </Link>
          )}
          <button
            className="icon-button"
            title="Lock vault and sign out"
            aria-label="Lock vault and sign out"
            onClick={() => lock(userId)}
          >
            <Lock size={20} />
          </button>
        </div>
      </div>
      <div className="vault-layout">
        <div className="sidebar">
          <button className={nav === "vault" ? "active" : ""} onClick={() => setNav("vault")}>Vault</button>
          <button className={nav === "groups" ? "active" : ""} onClick={() => setNav("groups")}>Groups</button>
          <button className={nav === "settings" ? "active" : ""} onClick={() => setNav("settings")}>Settings</button>
        </div>
        {nav === "vault" && <VaultView userId={userId} userEmail={userEmail} />}
        {nav === "groups" && <GroupsView userId={userId} userEmail={userEmail} />}
        {nav === "settings" && <SettingsView userId={userId} />}
      </div>
    </div>
  );
}
