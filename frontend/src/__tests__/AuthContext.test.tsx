/**
 * AuthContext.test.tsx
 * Tests for AuthProvider: initial loading state, user population,
 * login/logout mutations, and the useAuth guard.
 */
import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { AuthProvider, useAuth } from '../context/AuthContext';

// ── Helpers ───────────────────────────────────────────────────────────────────
const mockUser = {
  id: 1,
  email: 'test@example.com',
  full_name: 'Test User',
  created_at: '2026-01-01T00:00:00Z',
};

/** Small consumer component that surfaces auth state as test-ids. */
const AuthConsumer: React.FC = () => {
  const { user, loading } = useAuth();
  if (loading) return <div data-testid="loading">loading</div>;
  if (!user)   return <div data-testid="no-user">no user</div>;
  return <div data-testid="user-email">{user.email}</div>;
};

// ── Module mock — replace `api` so tests never hit the network ────────────────
vi.mock('../services/api', () => ({
  api: {
    getMe:   vi.fn(),
    login:   vi.fn(),
    logout:  vi.fn(),
    register: vi.fn(),
  },
}));

// Import *after* mock is declared so the mock is active when the module loads
import { api } from '../services/api';

// ── Tests ─────────────────────────────────────────────────────────────────────
describe('AuthContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('starts in loading=true state, then resolves to no-user when getMe rejects', async () => {
    (api.getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Unauthorized'));

    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>
    );

    // Initially loading
    expect(screen.getByTestId('loading')).toBeDefined();

    // After getMe rejects, user should be null
    await waitFor(() => {
      expect(screen.getByTestId('no-user')).toBeDefined();
    });
  });

  it('populates user state when getMe resolves', async () => {
    (api.getMe as ReturnType<typeof vi.fn>).mockResolvedValue({ user: mockUser });

    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('user-email').textContent).toBe(mockUser.email);
    });
  });

  it('updates user on login()', async () => {
    // getMe rejects initially (not logged in)
    (api.getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('401'));
    (api.login as ReturnType<typeof vi.fn>).mockResolvedValue({ user: mockUser });

    /** Component that also exposes the login action. */
    const LoginTrigger: React.FC = () => {
      const { user, loading, login } = useAuth();
      if (loading) return <div data-testid="loading">loading</div>;
      return (
        <div>
          <div data-testid="user-state">{user ? user.email : 'logged-out'}</div>
          <button
            data-testid="login-btn"
            onClick={() => login({ email: 'test@example.com', password: 'secret' })}
          >
            Login
          </button>
        </div>
      );
    };

    render(
      <AuthProvider>
        <LoginTrigger />
      </AuthProvider>
    );

    await waitFor(() => expect(screen.getByTestId('user-state').textContent).toBe('logged-out'));

    await act(async () => {
      screen.getByTestId('login-btn').click();
    });

    await waitFor(() => {
      expect(screen.getByTestId('user-state').textContent).toBe(mockUser.email);
    });
  });

  it('clears user on logout()', async () => {
    (api.getMe as ReturnType<typeof vi.fn>).mockResolvedValue({ user: mockUser });
    (api.logout as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    const LogoutTrigger: React.FC = () => {
      const { user, loading, logout } = useAuth();
      if (loading) return <div data-testid="loading">loading</div>;
      return (
        <div>
          <div data-testid="user-state">{user ? user.email : 'logged-out'}</div>
          <button data-testid="logout-btn" onClick={logout}>Logout</button>
        </div>
      );
    };

    render(
      <AuthProvider>
        <LogoutTrigger />
      </AuthProvider>
    );

    await waitFor(() => expect(screen.getByTestId('user-state').textContent).toBe(mockUser.email));

    await act(async () => {
      screen.getByTestId('logout-btn').click();
    });

    await waitFor(() => {
      expect(screen.getByTestId('user-state').textContent).toBe('logged-out');
    });
  });

  it('useAuth throws when called outside AuthProvider', () => {
    const BadConsumer: React.FC = () => {
      useAuth(); // must throw
      return null;
    };
    expect(() => render(<BadConsumer />)).toThrow();
  });
});

