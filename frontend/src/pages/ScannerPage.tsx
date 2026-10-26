import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Terminal, Shield, ArrowRight, CheckCircle2, Loader2, Sparkles, AlertOctagon } from 'lucide-react';
import { api } from '../services/api';
import type { ScanResult } from '../types';
import { validateScanUrl } from '../utils/urlValidator';

export const ScannerPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [urlInput, setUrlInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [errorMessage, setErrorMessage] = useState('');

  // Benchmark test scenarios for testing diverse URL categories
  const benchmarkSamples = [
    {
      title: 'Legitimate Web Portal',
      url: 'https://www.google.com',
      badge: 'Legitimate',
      badgeColor: 'text-[#39FF88] border-[#39FF88]/40 bg-[#0E1A12]',
      description: 'Authentic apex domain with standard HTTPS encryption and high reputation'
    },
    {
      title: 'Phishing Impersonation',
      url: 'http://login.paypal.com.account-verify.xyz/signin',
      badge: 'Phishing',
      badgeColor: 'text-[#FF525C] border-[#FF525C]/40 bg-[#1A0D0F]',
      description: 'Chained subdomains, deceptive keywords, and unencrypted HTTP scheme'
    },
    {
      title: 'External Public IP Hostname',
      url: 'http://203.0.113.195/secure/login.php',
      badge: 'Suspicious IP',
      badgeColor: 'text-[#FFD54A] border-[#FFD54A]/40 bg-[#1A170A]',
      description: 'Direct numeric IPv4 destination bypassing standard domain name resolution'
    },
    {
      title: 'Deceptive Banking Domain',
      url: 'https://secure-update-banking.co.uk/verify/index.html',
      badge: 'Anomalous',
      badgeColor: 'text-[#FFD54A] border-[#FFD54A]/40 bg-[#1A170A]',
      description: 'Compound hyphenated brand keywords and suspicious lexical structure'
    }
  ];

  // Quick tests for validation rejection behavior
  const rejectionTests = [
    { label: 'Test Localhost', value: 'http://localhost:5173' },
    { label: 'Test Internal IP', value: 'http://192.168.1.1' },
    { label: 'Test Local Route', value: '/scanner' },
    { label: 'Test Malformed String', value: 'jhsahjvahvhasvkhgksghewvfv' }
  ];

  const scanStages = [
    { title: 'Safe Ingestion & Normalization', desc: 'Validating scheme and sanitizing control characters' },
    { title: 'Checking the Address', desc: 'Looking for common warning signs in the web address' },
    { title: 'Checking for Phishing Patterns', desc: 'Comparing the address with patterns the system was trained to spot' },
    { title: 'Checking Known Threats', desc: 'Checking Google Safe Browsing and URLhaus for reported threats' },
  ];

  // Auto-fill from query parameter if present
  useEffect(() => {
    const qUrl = searchParams.get('url');
    if (qUrl) {
      setUrlInput(qUrl);
      executeScan(qUrl);
    }
  }, [searchParams]);

  const executeScan = async (targetUrl: string) => {
    const validation = validateScanUrl(targetUrl);
    if (!validation.isValid) {
      setErrorMessage(validation.error || 'Invalid URL entered.');
      return;
    }

    const sanitized = validation.sanitizedUrl || targetUrl.trim();

    setErrorMessage('');
    setIsLoading(true);
    setCurrentStep(0);

    // Simulated progress steps for smooth visual feedback
    const stepInterval = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev < scanStages.length - 1) return prev + 1;
        return prev;
      });
    }, 450);

    try {
      const result: ScanResult = await api.scanUrl(sanitized);
      clearInterval(stepInterval);
      setCurrentStep(scanStages.length);
      // Navigate to detailed results report
      navigate(`/results/${result.scan_id}`, { state: { result } });
    } catch (err: any) {
      clearInterval(stepInterval);
      setIsLoading(false);
      setErrorMessage(err.message || 'Scan evaluation failed. Please check backend connection.');
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeScan(urlInput);
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-[#111111] border border-[#39FF88]/40 text-xs font-medium text-[#39FF88]">
          <Terminal className="w-3.5 h-3.5 text-[#39FF88]" />
          <span>Website Address Check</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#F5F5F5]">
          Check a Suspicious Link Safely
        </h1>
        <p className="text-xs sm:text-sm text-[#A3A3A3] max-w-xl mx-auto">
          Paste a link here to check it without opening it. We look for warning signs and known threats; we never visit the address.
        </p>
      </div>

      {/* Main Scanner Box */}
      <div className="p-6 sm:p-8 rounded bg-[#111111] border border-[#292929] space-y-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <label htmlFor="url-input" className="block text-xs font-semibold uppercase tracking-wider text-[#A3A3A3]">
            Target Web Address (URL)
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
              <Terminal className="h-5 w-5 text-[#39FF88]" />
            </div>
            <input
              id="url-input"
              type="text"
              value={urlInput}
              onChange={(e) => {
                setUrlInput(e.target.value);
                if (errorMessage) setErrorMessage('');
              }}
              disabled={isLoading}
              placeholder="https://example.com/login?token=xyz or http://paypal.security-update.com"
              className="w-full pl-11 pr-4 py-3.5 rounded bg-[#0A0A0A] border border-[#292929] text-[#F5F5F5] placeholder-[#737373] text-sm focus:border-[#39FF88] transition-colors disabled:opacity-50"
            />
          </div>

          {errorMessage && (
            <div className="p-3.5 rounded bg-[#181010] border border-[#FF525C]/40 text-xs text-[#FF525C] flex items-start gap-2.5">
              <AlertOctagon className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-semibold">Input Validation Rejection:</span>
                <p className="text-[#F5F5F5] leading-relaxed">{errorMessage}</p>
              </div>
            </div>
          )}

          {/* Quick Rejection Test Buttons */}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="text-[10px] uppercase font-semibold text-[#737373] mr-1">Quick Validation Checks:</span>
            {rejectionTests.map((test, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setUrlInput(test.value);
                  executeScan(test.value);
                }}
                className="text-[11px] font-mono px-2.5 py-1 rounded bg-[#0A0A0A] hover:bg-[#181818] border border-[#292929] hover:border-[#FF525C] text-[#A3A3A3] hover:text-[#FF525C] transition-colors"
              >
                {test.label}
              </button>
            ))}
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
            <div className="flex items-center gap-2 text-[11px] text-[#A3A3A3]">
              <Shield className="w-3.5 h-3.5 text-[#39FF88]" />
              <span>Strict Zero-Crawl Rule: Target URL is parsed strictly in-memory and never fetched.</span>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full sm:w-auto px-6 py-3 rounded bg-[#39FF88] hover:bg-[#16C96A] text-[#050505] font-bold text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2 disabled:opacity-50 shadow-[0_0_15px_rgba(57,255,136,0.15)]"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-[#050505]" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <span>Execute Analysis</span>
                  <ArrowRight className="w-4 h-4 text-[#050505]" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Live Scan Stages Indicator */}
        {isLoading && (
          <div className="p-5 rounded bg-[#0A0A0A] border border-[#292929] space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-[#39FF88] flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Pipeline Execution In Progress
              </span>
              <span className="text-[11px] text-[#A3A3A3]">Stage {currentStep + 1} of 4</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
              {scanStages.map((stage, idx) => {
                const isDone = currentStep > idx;
                const isCurrent = currentStep === idx;
                return (
                  <div
                    key={idx}
                    className={`p-3 rounded border text-xs transition-all ${
                      isDone
                        ? 'bg-[#0E1A12] border-[#39FF88]/40 text-[#F5F5F5]'
                        : isCurrent
                        ? 'bg-[#181818] border-[#39FF88] text-[#39FF88]'
                        : 'bg-[#050505] border-[#292929] text-[#737373]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold">{stage.title}</span>
                      {isDone && <CheckCircle2 className="w-3.5 h-3.5 text-[#39FF88]" />}
                      {isCurrent && <Loader2 className="w-3.5 h-3.5 animate-spin text-[#39FF88]" />}
                    </div>
                    <p className="text-[10px] text-[#A3A3A3]">{stage.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Preset Test Scenarios */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#A3A3A3]">
          <Sparkles className="w-3.5 h-3.5 text-[#FFD54A]" />
          <span>Benchmark Test Scenarios</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {benchmarkSamples.map((sample, idx) => (
            <div
              key={idx}
              onClick={() => {
                setUrlInput(sample.url);
                executeScan(sample.url);
              }}
              className="p-4 rounded bg-[#111111] hover:bg-[#181818] border border-[#292929] hover:border-[#39FF88] cursor-pointer transition-all space-y-2 group"
            >
              <div className="flex items-center justify-between">
                <h3 className="font-medium text-xs text-[#F5F5F5] group-hover:text-[#39FF88]">
                  {sample.title}
                </h3>
                <span className={`text-[10px] uppercase font-semibold px-2 py-0.5 rounded border ${sample.badgeColor}`}>
                  {sample.badge}
                </span>
              </div>
              <p className="text-xs font-mono text-[#A3A3A3] truncate bg-[#050505] px-2 py-1 rounded border border-[#292929]">
                {sample.url}
              </p>
              <p className="text-[11px] text-[#737373]">
                {sample.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
