import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Terminal, Shield, ArrowRight, AlertTriangle, CheckCircle2, Loader2, Sparkles } from 'lucide-react';
import { api } from '../services/api';
import type { ScanResult } from '../types';

export const ScannerPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [urlInput, setUrlInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [errorMessage, setErrorMessage] = useState('');

  // Sample demo URLs representing distinct security profiles
  const demoSamples = [
    {
      title: 'Phishing Attack Demo',
      url: 'http://login.paypal.com.account-verify.xyz/signin',
      description: 'Chained subdomains, suspicious keywords, unencrypted HTTP'
    },
    {
      title: 'Legitimate Portal Demo',
      url: 'https://wikipedia.org/wiki/Computer_science',
      description: 'Authentic HTTPS portal with clean semantic directory structure'
    },
    {
      title: 'Raw IP Hostname Demo',
      url: 'http://192.168.1.105:8080/admin/login.php',
      description: 'Direct IPv4 address and non-standard network port'
    },
    {
      title: 'Shortened Link Demo',
      url: 'https://bit.ly/3xY9kL1-secure-banking',
      description: 'URL shortening service concealing true destination'
    }
  ];

  const scanStages = [
    { title: 'Safe Ingestion & Normalization', desc: 'Validating scheme and sanitizing control characters' },
    { title: '16-D Feature Extraction', desc: 'Computing lexical, structural, and semantic vector metrics' },
    { title: 'Random Forest Inference', desc: 'Evaluating vector through 150-tree decision ensemble' },
    { title: 'Threat Intelligence Feeds', desc: 'Querying Google Safe Browsing and URLhaus adapters' },
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
    const trimmed = targetUrl.trim();
    if (!trimmed) {
      setErrorMessage('Please enter a URL to scan.');
      return;
    }
    if (trimmed.length > 2048) {
      setErrorMessage('URL exceeds maximum permitted limit of 2,048 characters.');
      return;
    }
    if (/\s/.test(trimmed)) {
      setErrorMessage('A web address cannot contain spaces. Please check your input.');
      return;
    }

    // Validate that the input contains a valid domain, IP, or localhost
    let domainCandidate = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '').split('/')[0].split('?')[0].split('#')[0];
    domainCandidate = domainCandidate.replace(/:\d+$/, '');

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(domainCandidate) || /^\[[0-9a-fA-F:]+\]$/.test(domainCandidate);
    const isLocalhost = domainCandidate.toLowerCase() === 'localhost';
    const isDomain = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(domainCandidate);

    if (!isIp && !isLocalhost && !isDomain) {
      setErrorMessage(
        `"${trimmed}" is not a recognized web address. Please enter a valid URL with a proper domain extension (e.g. example.com or https://company.org).`
      );
      return;
    }

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
      const result: ScanResult = await api.scanUrl(trimmed);
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
          <span>Real-Time URL Risk Scanner</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#F5F5F5]">
          Inspect Suspicious URLs Safely
        </h1>
        <p className="text-xs sm:text-sm text-[#A3A3A3] max-w-xl mx-auto">
          Treat untrusted URLs with caution. Our scanner extracts lexical features and evaluates ML risk tiers without executing remote code.
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
            <div className="p-3 rounded bg-[#181010] border border-[#FF525C]/40 text-xs text-[#FF525C] flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
            <div className="flex items-center gap-2 text-[11px] text-[#A3A3A3]">
              <Shield className="w-3.5 h-3.5 text-[#39FF88]" />
              <span>Strict Zero-Crawl Rule: Target URL is never fetched or visited.</span>
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
          {demoSamples.map((sample, idx) => (
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
                <span className="text-[10px] text-[#39FF88] uppercase font-semibold">Test Sample</span>
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
