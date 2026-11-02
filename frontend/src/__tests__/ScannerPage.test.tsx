/**
 * ScannerPage.test.tsx
 * Render and interaction tests for ScannerPage.
 *
 * The component depends on react-router-dom hooks (useSearchParams, useNavigate).
 * We wrap in MemoryRouter to satisfy those dependencies.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

// ── Mock api so tests never hit the network ────────────────────────────────────
vi.mock('../services/api', () => ({
  api: {
    // scanUrl takes a plain string, not an object
    scanUrl: vi.fn(),
    getMe:   vi.fn().mockResolvedValue({ user: null }),
    logout:  vi.fn(),
  },
}));

import { api } from '../services/api';
import { ScannerPage } from '../pages/ScannerPage';

// ── Helper: render inside MemoryRouter ─────────────────────────────────────────
function renderScanner(path = '/scanner') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ScannerPage />
    </MemoryRouter>
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────
describe('ScannerPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the URL input field', () => {
    renderScanner();
    const input = screen.getByRole('textbox');
    expect(input).toBeDefined();
    expect((input as HTMLInputElement).value).toBe('');
  });

  it('renders at least one button', () => {
    renderScanner();
    const buttons = screen.getAllByRole('button');
    expect(buttons.length).toBeGreaterThan(0);
  });

  it('shows a validation error when submitting an empty URL', async () => {
    renderScanner();

    // Submit with empty input
    const form = document.querySelector('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      // validateScanUrl returns "URL cannot be empty…" and the component
      // renders it inside the error div
      expect(screen.getByText(/empty|invalid/i)).toBeDefined();
    });
  });

  it('shows a validation error for a localhost URL', async () => {
    renderScanner();

    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: 'http://localhost:8000' } });

    const form = document.querySelector('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      // The error message contains "local development destinations"
      const errorEl = screen.queryByText(/local development destinations/i);
      expect(errorEl).toBeTruthy();
    });
  });

  it('does NOT call api.scanUrl for a javascript: scheme URL', async () => {
    renderScanner();

    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: 'javascript:alert(1)' } });

    const form = document.querySelector('form')!;
    fireEvent.submit(form);

    // validateScanUrl rejects this before api.scanUrl is ever called
    await waitFor(() => {
      expect(api.scanUrl).not.toHaveBeenCalled();
    });
  });

  it('calls api.scanUrl with the sanitized URL string for valid input', async () => {
    (api.scanUrl as ReturnType<typeof vi.fn>).mockResolvedValue({
      scan_id: 'test-uuid-1234',
      risk_score: 10,
      verdict: 'Legitimate',
      is_phishing: false,
      confidence: 0.9,
      features: {},
      threat_intel: {},
    });

    renderScanner();

    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: 'https://example.com' } });

    const form = document.querySelector('form')!;
    fireEvent.submit(form);

    // api.scanUrl receives the sanitized URL as a plain string
    await waitFor(() => {
      expect(api.scanUrl).toHaveBeenCalledWith(
        expect.stringMatching(/^https:\/\/example\.com\/?$/)
      );
    });
  });

  it('pre-fills the input from the ?url= query parameter', async () => {
    (api.scanUrl as ReturnType<typeof vi.fn>).mockResolvedValue({
      scan_id: 'test-uuid-prefill',
      risk_score: 5,
      verdict: 'Legitimate',
      is_phishing: false,
      confidence: 0.95,
      features: {},
      threat_intel: {},
    });

    render(
      <MemoryRouter initialEntries={['/scanner?url=https://prefill.example.com']}>
        <ScannerPage />
      </MemoryRouter>
    );

    const input = screen.getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe('https://prefill.example.com');

    await waitFor(() => {
      expect(api.scanUrl).toHaveBeenCalledWith('https://prefill.example.com');
    });
  });
});
