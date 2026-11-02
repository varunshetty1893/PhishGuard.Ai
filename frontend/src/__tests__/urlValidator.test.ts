/**
 * urlValidator.test.ts
 * Unit tests for validateScanUrl — the client-side URL guard used by ScannerPage.
 */
import { describe, it, expect } from 'vitest';
import { validateScanUrl } from '../utils/urlValidator';

describe('validateScanUrl', () => {
  // ── Valid URLs ────────────────────────────────────────────────────────────────
  it('accepts a normal HTTPS URL', () => {
    const result = validateScanUrl('https://example.com');
    expect(result.isValid).toBe(true);
    // sanitizedUrl is the testUrl passed to the URL constructor; jsdom may or
    // may not append a trailing slash — accept both forms.
    expect(result.sanitizedUrl).toMatch(/^https:\/\/example\.com\/?$/);
  });

  it('accepts an HTTP URL', () => {
    const result = validateScanUrl('http://phishing-test.com/login');
    expect(result.isValid).toBe(true);
  });

  it('prepends https:// when scheme is omitted', () => {
    const result = validateScanUrl('example.com');
    expect(result.isValid).toBe(true);
    expect(result.sanitizedUrl).toMatch(/^https:\/\//);
  });

  it('trims surrounding whitespace before validating', () => {
    const result = validateScanUrl('  https://example.com  ');
    expect(result.isValid).toBe(true);
  });

  // ── Empty / whitespace ────────────────────────────────────────────────────────
  it('rejects empty string', () => {
    const result = validateScanUrl('');
    expect(result.isValid).toBe(false);
    expect(result.error).toMatch(/empty/i);
  });

  it('rejects whitespace-only input', () => {
    const result = validateScanUrl('   ');
    expect(result.isValid).toBe(false);
    expect(result.error).toMatch(/empty/i);
  });

  // ── Length limit ──────────────────────────────────────────────────────────────
  it('rejects URLs longer than 2,048 characters', () => {
    const long = 'https://example.com/' + 'a'.repeat(2050);
    const result = validateScanUrl(long);
    expect(result.isValid).toBe(false);
    expect(result.error).toMatch(/2,048/);
  });

  it('accepts exactly 2,048 characters', () => {
    const url = 'https://example.com/' + 'a'.repeat(2048 - 'https://example.com/'.length);
    expect(url.length).toBe(2048);
    const result = validateScanUrl(url);
    expect(result.isValid).toBe(true);
  });

  // ── Forbidden schemes ─────────────────────────────────────────────────────────
  it.each([
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'file:///etc/passwd',
    'vbscript:msgbox(1)',
    'ftp://files.example.com',
  ])('rejects forbidden scheme: %s', (url) => {
    const result = validateScanUrl(url);
    expect(result.isValid).toBe(false);
  });

  // ── Private / internal IPs ────────────────────────────────────────────────────
  it('rejects 127.0.0.1 (loopback)', () => {
    const result = validateScanUrl('http://127.0.0.1/admin');
    expect(result.isValid).toBe(false);
  });

  it('rejects 192.168.x.x (RFC 1918)', () => {
    const result = validateScanUrl('http://192.168.1.1');
    expect(result.isValid).toBe(false);
  });

  it('rejects 10.x.x.x (RFC 1918)', () => {
    const result = validateScanUrl('http://10.0.0.1');
    expect(result.isValid).toBe(false);
  });

  it('rejects localhost', () => {
    const result = validateScanUrl('http://localhost:8000/scan');
    expect(result.isValid).toBe(false);
    expect(result.error).toMatch(/local/i);
  });

  // ── Email / social handles ────────────────────────────────────────────────────
  it('rejects email addresses', () => {
    const result = validateScanUrl('user@example.com');
    expect(result.isValid).toBe(false);
    expect(result.error).toMatch(/email/i);
  });

  it('rejects social handles (@username)', () => {
    const result = validateScanUrl('@phishguard');
    expect(result.isValid).toBe(false);
    expect(result.error).toMatch(/username/i);
  });

  // ── Malformed / no TLD ────────────────────────────────────────────────────────
  it('rejects single-label hostnames (no TLD)', () => {
    const result = validateScanUrl('http://intranet/path');
    expect(result.isValid).toBe(false);
  });

  it('rejects URLs with spaces in the middle', () => {
    const result = validateScanUrl('https://example .com');
    expect(result.isValid).toBe(false);
  });
});
