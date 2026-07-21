import type { Session, User } from "@supabase/supabase-js";
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { supabase } from "../api/supabase";
import { env } from "../config/env";
import { getCurrentSession, login, logout } from "./supabaseAuth";

interface AuthContextValue {
  user: User | null;
  // Kept alongside `user` because Okta group membership (app_metadata.groups)
  // is injected into the JWT by the Custom Access Token Hook at mint time —
  // it never gets written back to the stored auth.users row, so session.user
  // (returned by GoTrue's own /user or sign-in response) never reflects it.
  // Reading groups requires decoding session.access_token directly; see
  // getUserGroups() in auth/adminAccess.tsx.
  session: Session | null;
  isLoading: boolean;
  login: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let active = true;

    void getCurrentSession().then((session) => {
      if (active) {
        setSession(session);
        setIsLoading(false);
      }
    });

    if (env.mockAuthEnabled) {
      return () => {
        active = false;
      };
    }

    // Implicit OAuth flow: supabase-js auto-detects the access token in the
    // URL fragment when the browser lands back here after Okta redirects
    // through Supabase, and fires this listener — no manual /callback route.
    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
    });

    return () => {
      active = false;
      listener.subscription.unsubscribe();
    };
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user: session?.user ?? null,
      session,
      isLoading,
      login: async () => {
        // Real Okta login navigates the whole page away, so there's normally
        // nothing to do after it resolves. Mock login doesn't navigate, so
        // pull the freshly "signed in" session into state here.
        await login();
        if (env.mockAuthEnabled) setSession(await getCurrentSession());
      },
      logout: async () => {
        await logout();
        setSession(null);
      },
    }),
    [session, isLoading],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider.");
  return ctx;
}
