import { useState, useEffect, useCallback } from "react";
import type { ReactNode } from "react";
import { api } from "../api/client";
import type { ReportTemplateDefinition, UserResponse } from "../types/api";
import { AuthContext, TOKEN_KEY } from "./authShared";

async function readAuthError(res: Response, fallback: string): Promise<Error> {
  const body = await res.json().catch(() => ({ detail: fallback }));
  return new Error(typeof body.detail === "string" ? body.detail : fallback);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY));
  const [loading, setLoading] = useState(!!localStorage.getItem(TOKEN_KEY));

  const fetchMe = useCallback(async (_token: string) => {
    try {
      const data = await api.getCurrentUser();
      setUser(data);
    } catch {
      localStorage.removeItem(TOKEN_KEY);
      setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (token) fetchMe(token);
  }, [token, fetchMe]);

  const login = useCallback(async (email: string, password: string) => {
    const res = await fetch(`${api.baseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) {
      throw await readAuthError(res, "Login failed");
    }
    const data = await res.json();
    localStorage.setItem(TOKEN_KEY, data.access_token);
    setToken(data.access_token);
    setLoading(true);
  }, []);

  const register = useCallback(async (email: string, password: string, fullName: string) => {
    const res = await fetch(`${api.baseUrl}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, full_name: fullName }),
    });
    if (!res.ok) {
      throw await readAuthError(res, "Registration failed");
    }
    await login(email, password);
  }, [login]);

  const requestPasswordReset = useCallback(async (email: string) => {
    const res = await fetch(`${api.baseUrl}/auth/request-password-reset`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) {
      throw await readAuthError(res, "Password reset request failed");
    }
    return res.json() as Promise<{ detail: string; reset_token?: string }>;
  }, []);

  const resetPassword = useCallback(async (resetToken: string, newPassword: string) => {
    const res = await fetch(`${api.baseUrl}/auth/reset-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: resetToken, new_password: newPassword }),
    });
    if (!res.ok) {
      throw await readAuthError(res, "Password reset failed");
    }
    return res.json() as Promise<{ detail: string }>;
  }, []);

  const verifyEmail = useCallback(async (email: string, code: string) => {
    const res = await fetch(`${api.baseUrl}/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code }),
    });
    if (!res.ok) {
      throw await readAuthError(res, "Email verification failed");
    }
    const data = await res.json() as { detail: string };
    if (token && user?.email.toLowerCase() === email.toLowerCase()) {
      void fetchMe(token);
    }
    return data;
  }, [fetchMe, token, user?.email]);

  const updateReportTemplateLibrary = useCallback(
    async (reportTemplateLibrary: ReportTemplateDefinition[]) => {
      const updatedUser = await api.updateReportTemplateLibrary(reportTemplateLibrary);
      setUser(updatedUser);
    },
    []
  );

  const logout = useCallback(() => {
    const currentToken = localStorage.getItem(TOKEN_KEY);
    if (currentToken) {
      void fetch(`${api.baseUrl}/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${currentToken}` },
      }).catch(() => {
        // Local logout must still complete if the network request fails.
      });
    }
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        login,
        register,
        requestPasswordReset,
        resetPassword,
        verifyEmail,
        updateReportTemplateLibrary,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
