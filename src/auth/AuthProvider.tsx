import type { User } from "@supabase/supabase-js";
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { supabase } from "../api/supabase";
import { env } from "../config/env";
import { getCurrentSession, login, logout } from "./supabaseAuth";

interface AuthContextValue {
  user: User | null;
  isLoading: boolean;
  login: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let active = true;

    void getCurrentSession().then((session) => {
      if (active) {
        setUser(session?.user ?? null);
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
      setUser(session?.user ?? null);
    });

    return () => {
      active = false;
      listener.subscription.unsubscribe();
    };
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isLoading,
      login: async () => {
        // Real Okta login navigates the whole page away, so there's normally
        // nothing to do after it resolves. Mock login doesn't navigate, so
        // pull the freshly "signed in" user into state here.
        await login();
        if (env.mockAuthEnabled) setUser((await getCurrentSession())?.user ?? null);
      },
      logout: async () => {
        await logout();
        setUser(null);
      },
    }),
    [user, isLoading],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider.");
  return ctx;
}
