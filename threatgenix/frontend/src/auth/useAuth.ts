import { useContext } from "react";
import { AuthContext } from "./authShared";
import type { AuthState } from "./authShared";

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
