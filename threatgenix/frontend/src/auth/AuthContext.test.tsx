import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "./AuthContext";
import { TOKEN_KEY } from "./authShared";
import { useAuth } from "./useAuth";

const apiMocks = vi.hoisted(() => ({
  getCurrentUser: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: {
    baseUrl: "http://api.test/api",
    getCurrentUser: apiMocks.getCurrentUser,
  },
}));

function LogoutButton() {
  const { logout } = useAuth();
  return <button onClick={logout}>Sign out</button>;
}

describe("AuthProvider logout", () => {
  let storage: Map<string, string>;

  beforeEach(() => {
    vi.clearAllMocks();
    storage = new Map();
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => storage.get(key) ?? null),
      setItem: vi.fn((key: string, value: string) => {
        storage.set(key, value);
      }),
      removeItem: vi.fn((key: string) => {
        storage.delete(key);
      }),
      clear: vi.fn(() => {
        storage.clear();
      }),
    });
    apiMocks.getCurrentUser.mockResolvedValue({
      id: "00000000-0000-0000-0000-000000000001",
      email: "analyst@example.com",
      full_name: "Analyst User",
      role: "admin",
      is_active: true,
      email_verified: true,
      report_template_library: [],
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("invalidates the server token and still clears local auth state", () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("offline"));
    vi.stubGlobal("fetch", fetchMock);
    localStorage.setItem(TOKEN_KEY, "session-token");

    render(
      <AuthProvider>
        <LogoutButton />
      </AuthProvider>
    );

    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));

    expect(fetchMock).toHaveBeenCalledWith("http://api.test/api/auth/logout", {
      method: "POST",
      headers: { Authorization: "Bearer session-token" },
    });
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });
});
