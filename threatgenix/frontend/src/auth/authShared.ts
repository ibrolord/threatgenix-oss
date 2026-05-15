import { createContext } from "react";
import type { ReportTemplateDefinition, UserResponse } from "../types/api";

export interface AuthState {
  user: UserResponse | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName: string) => Promise<void>;
  requestPasswordReset: (email: string) => Promise<{ detail: string; reset_token?: string }>;
  resetPassword: (token: string, newPassword: string) => Promise<{ detail: string }>;
  verifyEmail: (email: string, code: string) => Promise<{ detail: string }>;
  updateReportTemplateLibrary: (
    reportTemplateLibrary: ReportTemplateDefinition[]
  ) => Promise<void>;
  logout: () => void;
}

export const TOKEN_KEY = "tg_token";

export const AuthContext = createContext<AuthState | null>(null);
