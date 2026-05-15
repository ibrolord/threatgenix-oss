import { useState, useCallback, useMemo } from "react";
import type { FormEvent } from "react";
import { Building2, Cloud, KeyRound, LockKeyhole, MailCheck, ShieldCheck } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../auth/useAuth";

type AuthMode = "login" | "register" | "forgot" | "reset" | "verify";

interface PasswordStrength {
  score: number; // 0-4
  label: string;
  color: string;
}

function getPasswordStrength(password: string): PasswordStrength {
  let score = 0;
  if (password.length >= 10) score++;
  if (password.length >= 14) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  score = Math.min(score, 4);
  const labels: { label: string; color: string }[] = [
    { label: "Too short", color: "#dc2626" },
    { label: "Weak", color: "#f59e0b" },
    { label: "Fair", color: "#eab308" },
    { label: "Good", color: "#22c55e" },
    { label: "Strong", color: "#16a34a" },
  ];
  const entry = labels[score] ?? { label: "Too short", color: "#dc2626" };
  return { score, label: entry.label, color: entry.color };
}

export default function LoginPage() {
  const {
    login,
    register,
    requestPasswordReset,
    resetPassword,
    verifyEmail,
  } = useAuth();
  const [searchParams] = useSearchParams();
  const initialResetToken = searchParams.get("reset_token") ?? searchParams.get("token") ?? "";
  const requestedMode = searchParams.get("mode");
  const initialMode: AuthMode =
    initialResetToken
      ? "reset"
      : requestedMode === "register" || requestedMode === "forgot" || requestedMode === "verify"
        ? requestedMode
        : "login";
  const [mode, setMode] = useState<AuthMode>(initialMode);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [resetToken, setResetToken] = useState(initialResetToken);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const strength = useMemo(() => getPasswordStrength(password), [password]);
  const needsPassword = mode === "login" || mode === "register" || mode === "reset";
  const showPasswordStrength = (mode === "register" || mode === "reset") && password.length > 0;
  const title = {
    login: "Sign in",
    register: "Create account",
    forgot: "Reset password",
    reset: "Choose a new password",
    verify: "Verify email",
  }[mode];
  const subtitle = {
    login: "Access your organization threat-model workspace.",
    register: "Create a pilot workspace for secure model reviews.",
    forgot: "Send a reset link to the account email.",
    reset: "Paste the reset token from email and set a strong password.",
    verify: "Enter the six-character code sent during account setup.",
  }[mode];

  const handleSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setError(null);
      setSuccess(null);
      setLoading(true);
      try {
        const normalizedEmail = email.trim();
        if (mode === "register") {
          try {
            await register(normalizedEmail, password, fullName.trim());
          } catch (registerError) {
            const message = registerError instanceof Error ? registerError.message : "";
            if (/email verification required/i.test(message)) {
              setPassword("");
              setVerificationCode("");
              setMode("verify");
              setSuccess("Account created. Enter the verification code sent during account setup.");
              return;
            }
            throw registerError;
          }
        } else if (mode === "forgot") {
          const result = await requestPasswordReset(normalizedEmail);
          if (result.reset_token) {
            setResetToken(result.reset_token);
            setMode("reset");
            setSuccess(`${result.detail} Local development token loaded below.`);
          } else {
            setSuccess(result.detail);
          }
        } else if (mode === "reset") {
          const result = await resetPassword(resetToken.trim(), password);
          setPassword("");
          setMode("login");
          setSuccess(`${result.detail}. Sign in with your new password.`);
        } else if (mode === "verify") {
          const result = await verifyEmail(normalizedEmail, verificationCode.trim());
          setVerificationCode("");
          setSuccess(result.detail);
        } else {
          await login(normalizedEmail, password);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Something went wrong");
      } finally {
        setLoading(false);
      }
    },
    [
      email,
      fullName,
      login,
      mode,
      password,
      register,
      requestPasswordReset,
      resetPassword,
      resetToken,
      verificationCode,
      verifyEmail,
    ]
  );

  const switchMode = (nextMode: AuthMode) => {
    setMode(nextMode);
    setError(null);
    setSuccess(null);
    if (nextMode !== "reset") {
      setResetToken("");
    }
    if (nextMode !== "verify") {
      setVerificationCode("");
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <p className="login-product-name">ThreatGenix</p>
        <h2>{title}</h2>
        <p className="login-subtitle">{subtitle}</p>
        <div className="login-trust-strip">
          <span className="login-trust-badge">
            <ShieldCheck size={12} aria-hidden="true" />
            Provider controls in Settings
          </span>
          <span className="login-trust-sep" aria-hidden="true">·</span>
          <span className="login-trust-badge">
            <LockKeyhole size={12} aria-hidden="true" />
            No AI training on your data
          </span>
          <span className="login-trust-sep" aria-hidden="true">·</span>
          <span className="login-trust-badge">
            <Cloud size={12} aria-hidden="true" />
            Tenant-level AI opt-in
          </span>
        </div>
        <div className="login-saas-note">
          <Building2 size={16} aria-hidden="true" />
          <span>Organization-scoped pilot access with audit-ready evidence and SaaS-safe validation controls.</span>
        </div>

        <form onSubmit={handleSubmit}>
          {mode === "register" && (
            <div className="form-field">
              <label htmlFor="fullName">Full Name</label>
              <input
                id="fullName"
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Priya Sharma"
                required
              />
            </div>
          )}
          {mode === "reset" && (
            <div className="form-field">
              <label htmlFor="resetToken">Reset Token</label>
              <input
                id="resetToken"
                type="text"
                value={resetToken}
                onChange={(e) => setResetToken(e.target.value)}
                placeholder="Paste reset token"
                required
              />
            </div>
          )}
          <div className="form-field">
            <label htmlFor="email">{mode === "forgot" ? "Account Email" : "Email"}</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@example.test"
              required
              autoFocus
            />
          </div>
          {needsPassword && (
            <div className="form-field">
              <label htmlFor="password">{mode === "reset" ? "New Password" : "Password"}</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={mode === "login" ? "Enter your password" : "At least 10 characters"}
                required
                minLength={mode === "login" ? 1 : 10}
              />
              {showPasswordStrength && (
                <div className="password-strength">
                  <div className="password-strength-bar">
                    {[0, 1, 2, 3].map((i) => (
                      <div
                        key={i}
                        className="password-strength-segment"
                        style={{
                          background: i < strength.score ? strength.color : "#e2e8f0",
                        }}
                      />
                    ))}
                  </div>
                  <span className="password-strength-label" style={{ color: strength.color }}>
                    {strength.label}
                  </span>
                </div>
              )}
              {(mode === "register" || mode === "reset") && (
                <p className="login-field-help">
                  Must include at least 10 characters, uppercase, lowercase, and a number.
                </p>
              )}
            </div>
          )}
          {mode === "verify" && (
            <div className="form-field">
              <label htmlFor="verificationCode">Verification Code</label>
              <input
                id="verificationCode"
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.toUpperCase())}
                placeholder="ABC123"
                required
                minLength={6}
                maxLength={6}
              />
            </div>
          )}

          {error && <p className="form-error" role="alert" aria-live="assertive">{error}</p>}
          {success && <p className="form-success" role="status" aria-live="polite">{success}</p>}

          <button type="submit" className="btn-create login-btn" disabled={loading}>
            {loading
              ? "Please wait..."
              : mode === "register"
                ? "Create Account"
                : mode === "forgot"
                  ? "Send Reset Link"
                  : mode === "reset"
                    ? "Reset Password"
                    : mode === "verify"
                      ? "Verify Email"
                      : "Sign in"}
          </button>
        </form>

        {mode === "login" ? (
          <div className="login-aux-actions">
            <button type="button" className="link-btn" onClick={() => switchMode("forgot")}>
              <KeyRound size={14} aria-hidden="true" />
              Forgot password?
            </button>
            <button type="button" className="link-btn" onClick={() => switchMode("verify")}>
              <MailCheck size={14} aria-hidden="true" />
              Verify email
            </button>
          </div>
        ) : null}

        <p className="login-toggle">
          {mode === "register" ? "Already have an account?" : "Need an account?"}{" "}
          <button
            type="button"
            className="link-btn"
            onClick={() => switchMode(mode === "register" ? "login" : "register")}
          >
            {mode === "register" ? "Sign in" : "Register"}
          </button>
        </p>
        {mode !== "login" ? (
          <p className="login-toggle login-toggle-secondary">
            <button type="button" className="link-btn" onClick={() => switchMode("login")}>
              Back to sign in
            </button>
          </p>
        ) : null}
      </div>
    </div>
  );
}
