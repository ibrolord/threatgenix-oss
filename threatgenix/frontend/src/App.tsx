import { Component, Suspense, lazy } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { Routes, Route, Navigate, Link, useLocation } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { useAuth } from "./auth/useAuth";
import type { UserResponse } from "./types/api";
import LoginPage from "./pages/LoginPage";
import ModelSelector from "./components/ModelSelector";
import TMACReferencePage from "./pages/TMACReferencePage";
import HelpPage from "./pages/HelpPage";
import { shouldReloadForLazyChunkError } from "./utils/lazyChunkReload";

const HomePage = lazy(() => import("./pages/HomePage"));
const ThreatModelPage = lazy(() => import("./pages/ThreatModelPage"));
const ValidationLabPage = lazy(() => import("./pages/ValidationLabPage"));
const ThreatDetailPage = lazy(() => import("./pages/ThreatDetailPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const SecurityReviewPage = lazy(() => import("./pages/SecurityReviewPage"));
const ApplicationReviewPage = lazy(() => import("./pages/ApplicationReviewPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage"));
const buildCommit = import.meta.env.VITE_SOURCE_VERSION?.slice(0, 7);

class ErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("ThreatGenix uncaught error:", error, info);
    if (shouldReloadForLazyChunkError(error, window.sessionStorage, buildCommit)) {
      console.warn("Reloading once after stale application chunk load failure.");
      window.location.reload();
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="not-found-page">
          <div className="not-found-card">
            <h2 className="not-found-code">Error</h2>
            <h3 className="not-found-title">Something went wrong</h3>
            <p className="not-found-copy">
              An unexpected error occurred. Please reload the page or return to the dashboard.
            </p>
            <a href="/dashboard" className="btn-create not-found-link">
              Back to Dashboard
            </a>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function PageLoadingFallback() {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "60vh", gap: "0.75rem", color: "var(--c-text-muted, #94a3b8)" }}>
      <div className="dfd-spinner" />
      Loading...
    </div>
  );
}

function workspaceName(user: UserResponse): string {
  return user.organization_name || "Personal pilot workspace";
}

function planLabel(user: UserResponse): string {
  const tier = user.organization_subscription_tier?.trim();
  if (!user.organization_id) {
    return "Personal pilot";
  }
  return tier ? `${tier.charAt(0).toUpperCase()}${tier.slice(1)} workspace` : "Organization workspace";
}

function UserMenu({ user, logout }: { user: UserResponse; logout: () => void }) {
  const initials = (user.full_name || user.email)
    .split(" ")
    .map((w: string) => w[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
  return (
    <div className="user-menu">
      <ModelSelector />
      <span className="app-plan-badge" title="Current SaaS entitlement tier">{planLabel(user)}</span>
      <div className="user-avatar" title={`${user.full_name || user.email} · ${workspaceName(user)}`}>{initials}</div>
      <button className="app-nav-link user-logout-btn" onClick={logout}>Sign out</button>
    </div>
  );
}

function SaaSAccountBanner({ user }: { user: UserResponse }) {
  const needsVerification = user.email_verified === false;
  const needsOrg = !user.organization_id;
  if (!needsVerification && !needsOrg) return null;

  return (
    <div className="saas-account-banner" role="status">
      <div>
        <strong>
          {needsVerification ? "Email verification pending" : "Personal workspace"}
        </strong>
        <p>
          {needsVerification
            ? "Verify your email to keep account recovery and audit notifications tied to a trusted address."
            : "Create or join an organization workspace before using team governance, shared evidence, and enterprise entitlements."}
        </p>
      </div>
      <Link className="saas-banner-link" to="/settings">
        {needsVerification ? "Verify Email" : "Review Settings"}
      </Link>
    </div>
  );
}

function ProtectedApp() {
  const { user, loading, logout } = useAuth();
  const location = useLocation();

  if (loading) return <PageLoadingFallback />;
  if (!user) return <LoginPage />;

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-header-inner">
          <Link to="/dashboard" className="app-header-brand">ThreatGenix</Link>
          <nav className="app-nav">
            <Link to="/dashboard" className={`app-nav-link${location.pathname === "/dashboard" || location.pathname === "/" ? " app-nav-link-active" : ""}`}>
              Dashboard
            </Link>
            <Link to="/new" className={`app-nav-link${location.pathname === "/new" ? " app-nav-link-active" : ""}`}>
              Start Review
            </Link>
            <Link to="/help" className={`app-nav-link${location.pathname === "/help" ? " app-nav-link-active" : ""}`}>
              Help
            </Link>
            <Link to="/settings" className={`app-nav-link${location.pathname === "/settings" ? " app-nav-link-active" : ""}`}>
              Settings
            </Link>
            <UserMenu user={user} logout={logout} />
          </nav>
        </div>
      </header>
      <SaaSAccountBanner user={user} />
      <main>
        <Suspense fallback={<PageLoadingFallback />}>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/login" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/new" element={<HomePage />} />
            <Route path="/help" element={<HelpPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/docs/tmac" element={<TMACReferencePage />} />
            <Route path="/threat-models/:id" element={<ThreatModelPage />} />
            <Route path="/threat-models/:id/validation-lab" element={<ValidationLabPage />} />
            <Route path="/threat-models/:id/review" element={<SecurityReviewPage />} />
            <Route path="/reviews/:reviewId" element={<ApplicationReviewPage />} />
            <Route path="/threat-models/:threatModelId/threats/:threatId" element={<ThreatDetailPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Suspense>
      </main>
      <footer className="app-footer">
        <span>ThreatGenix v0.1.0</span>
        {buildCommit ? (
          <>
            <span className="app-footer-sep">&middot;</span>
            <span>Build {buildCommit}</span>
          </>
        ) : null}
        <span className="app-footer-sep">&middot;</span>
        <span>&copy; {new Date().getFullYear()} ThreatGenix Inc.</span>
        <span className="app-footer-sep">&middot;</span>
        <span className="app-footer-residency" title="Review Settings for the active AI provider, residency mode, and external-provider opt-in posture.">
          AI residency in Settings
        </span>
      </footer>
    </div>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <ProtectedApp />
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;
