import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import LoginPage from "./LoginPage";

const authMocks = vi.hoisted(() => ({
  login: vi.fn(),
  register: vi.fn(),
  requestPasswordReset: vi.fn(),
  resetPassword: vi.fn(),
  verifyEmail: vi.fn(),
}));

vi.mock("../auth/useAuth", () => ({
  useAuth: () => ({
    user: null,
    token: null,
    loading: false,
    login: authMocks.login,
    register: authMocks.register,
    requestPasswordReset: authMocks.requestPasswordReset,
    resetPassword: authMocks.resetPassword,
    verifyEmail: authMocks.verifyEmail,
    updateReportTemplateLibrary: vi.fn(),
    logout: vi.fn(),
  }),
}));

function renderLogin(initialEntry = "/login") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LoginPage />
    </MemoryRouter>
  );
}

describe("LoginPage SaaS account flows", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authMocks.requestPasswordReset.mockResolvedValue({
      detail: "If that email exists, a reset link has been sent.",
      reset_token: "dev-reset-token",
    });
    authMocks.resetPassword.mockResolvedValue({ detail: "Password has been reset successfully" });
    authMocks.verifyEmail.mockResolvedValue({ detail: "Email verified successfully" });
  });

  it("surfaces password reset and moves local development tokens into the reset form", async () => {
    const user = userEvent.setup();
    renderLogin();

    await user.click(screen.getByRole("button", { name: /forgot password/i }));
    await user.type(screen.getByLabelText(/account email/i), "analyst@example.com");
    await user.click(screen.getByRole("button", { name: /send reset link/i }));

    await waitFor(() => {
      expect(authMocks.requestPasswordReset).toHaveBeenCalledWith("analyst@example.com");
    });
    expect(await screen.findByDisplayValue("dev-reset-token")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /reset password/i })).toBeInTheDocument();
  });

  it("supports unauthenticated email verification from the login surface", async () => {
    const user = userEvent.setup();
    renderLogin("/login?mode=verify");

    await user.type(screen.getByLabelText(/^email$/i), "analyst@example.com");
    await user.type(screen.getByLabelText(/verification code/i), "abc123");
    await user.click(screen.getByRole("button", { name: /verify email/i }));

    await waitFor(() => {
      expect(authMocks.verifyEmail).toHaveBeenCalledWith("analyst@example.com", "ABC123");
    });
    expect(await screen.findByText("Email verified successfully")).toBeInTheDocument();
  });

  it("moves registration into verify mode when production requires email verification", async () => {
    const user = userEvent.setup();
    authMocks.register.mockRejectedValue(new Error("Email verification required"));
    renderLogin("/login?mode=register");

    await user.type(screen.getByLabelText(/full name/i), "Priya Sharma");
    await user.type(screen.getByLabelText(/^email$/i), "priya@example.com");
    await user.type(screen.getByLabelText(/^password$/i), "ThreatGenix2026!");
    await user.click(screen.getByRole("button", { name: /create account/i }));

    await waitFor(() => {
      expect(authMocks.register).toHaveBeenCalledWith(
        "priya@example.com",
        "ThreatGenix2026!",
        "Priya Sharma",
      );
    });
    expect(await screen.findByRole("button", { name: /verify email/i })).toBeInTheDocument();
    expect(screen.getByDisplayValue("priya@example.com")).toBeInTheDocument();
    expect(screen.getByText(/account created/i)).toBeInTheDocument();
  });
});
