import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Terminal,
  Cpu,
  ArrowRight,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';

export const LandingPage: React.FC = () => {
  const [inputUrl, setInputUrl] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleQuickScan = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = inputUrl.trim();
    if (!trimmed) {
      setError('Please provide a URL to analyze.');
      return;
    }
    setError('');
    navigate(`/scanner?url=${encodeURIComponent(trimmed)}`);
  };

  const sampleUrls = [
    { label: 'Verified Phishing Demo', url: 'http://login.paypal.com.account-verify.xyz/signin' },
    { label: 'Legitimate Portal Demo', url: 'https://wikipedia.org/wiki/Computer_science' },
    { label: 'Obfuscated Shortener Demo', url: 'https://tinyurl.com/secure-banking-login-test' },
  ];

  return (
    <div className="space-y-20 pb-16">
      {/* Hero Section */}
      <section className="relative pt-12 pb-16 px-4 sm:px-6 lg:px-8 border-b border-[#181818] cyber-grid">
        <div className="max-w-4xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#111111] border border-[#39FF88]/40 text-xs font-medium text-[#39FF88]">
            <span className="w-2 h-2 rounded-full bg-[#39FF88] animate-pulse" />
            <span>PhishGuard AI v1.0 • Academic Capstone Edition</span>
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-[#F5F5F5] leading-tight">
            One Link Can Hide a Threat.{' '}
            <span className="text-[#39FF88]">Detect It Before You Click.</span>
          </h1>

          <p className="text-base sm:text-lg text-[#A3A3A3] max-w-2xl mx-auto leading-relaxed">
            Autonomous phishing URL assessment combining a 16-feature Machine Learning classifier
            with multi-source threat intelligence feeds. Inspect suspicious links without executing untrusted code.
          </p>

          {/* Quick Scanner Box */}
          <div className="max-w-3xl mx-auto pt-4">
            <form onSubmit={handleQuickScan} className="relative flex flex-col sm:flex-row gap-2">
              <div className="relative flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <Terminal className="h-5 w-5 text-[#39FF88]" />
                </div>
                <input
                  type="text"
                  value={inputUrl}
                  onChange={(e) => {
                    setInputUrl(e.target.value);
                    if (error) setError('');
                  }}
                  placeholder="Paste any untrusted URL (e.g. http://paypal.com.verify-login.xyz)..."
                  className="w-full pl-11 pr-4 py-3.5 rounded bg-[#0A0A0A] border border-[#292929] text-[#F5F5F5] placeholder-[#737373] text-sm focus:border-[#39FF88] transition-colors"
                />
              </div>
              <button
                type="submit"
                className="px-6 py-3.5 rounded bg-[#39FF88] hover:bg-[#16C96A] text-[#050505] font-bold text-sm tracking-wider uppercase transition-all flex items-center justify-center gap-2 shrink-0 shadow-[0_0_20px_rgba(57,255,136,0.2)]"
              >
                <span>Analyze URL</span>
                <ArrowRight className="w-4 h-4 text-[#050505]" />
              </button>
            </form>

            {error && (
              <p className="text-left text-xs text-[#FF525C] mt-2 flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                {error}
              </p>
            )}

            {/* Quick Demo Links */}
            <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-xs">
              <span className="text-[#A3A3A3]">Try sample URL:</span>
              {sampleUrls.map((s, idx) => (
                <button
                  key={idx}
                  onClick={() => setInputUrl(s.url)}
                  type="button"
                  className="px-2.5 py-1 rounded bg-[#111111] hover:bg-[#181818] border border-[#292929] text-[#F5F5F5] hover:border-[#39FF88] transition-colors text-[11px]"
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Detection Workflow Pipeline */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center space-y-3 mb-12">
          <h2 className="text-2xl sm:text-3xl font-bold text-[#F5F5F5] tracking-tight">
            How PhishGuard AI Protects You
          </h2>
          <p className="text-sm text-[#A3A3A3] max-w-xl mx-auto">
            A sandboxed, multi-tier inspection pipeline that analyzes links safely in milliseconds.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="p-5 rounded bg-[#111111] border border-[#292929] relative space-y-3">
            <div className="w-8 h-8 rounded bg-[#181818] border border-[#39FF88]/40 flex items-center justify-center text-[#39FF88] font-bold text-xs">
              01
            </div>
            <h3 className="font-semibold text-sm text-[#F5F5F5]">Safe Ingestion</h3>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              The input string is sanitized and validated. No browser rendering or network sockets are opened to the destination.
            </p>
          </div>

          <div className="p-5 rounded bg-[#111111] border border-[#292929] relative space-y-3">
            <div className="w-8 h-8 rounded bg-[#181818] border border-[#39FF88]/40 flex items-center justify-center text-[#39FF88] font-bold text-xs">
              02
            </div>
            <h3 className="font-semibold text-sm text-[#F5F5F5]">Feature Extraction</h3>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              Extracts 16 deterministic lexical dimensions: dots, hyphens, subdomains, raw IP presence, shortening services, and authentication keywords.
            </p>
          </div>

          <div className="p-5 rounded bg-[#111111] border border-[#292929] relative space-y-3">
            <div className="w-8 h-8 rounded bg-[#181818] border border-[#39FF88]/40 flex items-center justify-center text-[#39FF88] font-bold text-xs">
              03
            </div>
            <h3 className="font-semibold text-sm text-[#F5F5F5]">Random Forest ML</h3>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              The extracted vector is evaluated by the genuinely trained 150-tree Random Forest classifier, yielding class prediction and probability.
            </p>
          </div>

          <div className="p-5 rounded bg-[#111111] border border-[#292929] relative space-y-3">
            <div className="w-8 h-8 rounded bg-[#181818] border border-[#39FF88]/40 flex items-center justify-center text-[#39FF88] font-bold text-xs">
              04
            </div>
            <h3 className="font-semibold text-sm text-[#F5F5F5]">Threat Feeds & Report</h3>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              Cross-references Google Safe Browsing and URLhaus threat feeds. Delivers an explainable report with actionable safety recommendations.
            </p>
          </div>
        </div>
      </section>

      {/* Feature Pillars: ML + Threat Intel */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* Column 1: Genuine Machine Learning */}
          <div className="p-8 rounded bg-[#0A0A0A] border border-[#292929] space-y-6">
            <div className="inline-flex p-3 rounded bg-[#111111] border border-[#39FF88]/40">
              <Cpu className="w-6 h-6 text-[#39FF88]" />
            </div>
            <h3 className="text-xl font-bold text-[#F5F5F5]">
              Genuine Supervised Machine Learning
            </h3>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              Trained on a curated benchmark of verified phishing URLs (Mitchell Krogza Phishing.Database)
              and high-reputation domains (Tranco/Alexa). Evaluated on held-out test splits with exact metrics.
            </p>
            <ul className="space-y-3 text-xs text-[#F5F5F5]">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#39FF88] shrink-0" />
                <span>16 Lexical & Structural Feature Dimensions</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#39FF88] shrink-0" />
                <span>Calibrated Risk Scoring (Low Risk, Suspicious, High Risk)</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#39FF88] shrink-0" />
                <span>Deterministic offline inference in under 15ms</span>
              </li>
            </ul>
          </div>

          {/* Column 2: External Threat Intelligence */}
          <div className="p-8 rounded bg-[#0A0A0A] border border-[#292929] space-y-6">
            <div className="inline-flex p-3 rounded bg-[#111111] border border-[#FFD54A]/40">
              <Shield className="w-6 h-6 text-[#FFD54A]" />
            </div>
            <h3 className="text-xl font-bold text-[#F5F5F5]">
              Multi-Source Threat Intelligence
            </h3>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              Server-side adapters query industry-standard threat databases. Each provider maintains an independent status,
              and external network failures never disrupt local machine learning classification.
            </p>
            <ul className="space-y-3 text-xs text-[#F5F5F5]">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#FFD54A] shrink-0" />
                <span>Google Safe Browsing API v4 Integration</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#FFD54A] shrink-0" />
                <span>abuse.ch URLhaus Malware Repository Adapter</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#FFD54A] shrink-0" />
                <span>Zero Mandatory Paid APIs — Fully operational offline</span>
              </li>
            </ul>
          </div>
        </div>
      </section>

      {/* Security & Architecture Highlights */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="p-8 rounded bg-[#111111] border border-[#292929] space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h3 className="text-lg font-bold text-[#F5F5F5]">
                Zero-Execution Security Sandbox
              </h3>
              <p className="text-xs text-[#A3A3A3] mt-1">
                PhishGuard AI treats every URL as potentially hostile untrusted input.
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="px-3 py-1 rounded bg-[#0E1A12] text-[#39FF88] border border-[#39FF88]/30 font-medium">
                SSRF-Immune
              </span>
              <span className="px-3 py-1 rounded bg-[#181818] text-[#F5F5F5] border border-[#292929] font-medium">
                No Crawlers
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4 border-t border-[#181818] text-xs">
            <div className="space-y-2">
              <h4 className="font-semibold text-[#39FF88]">No Webpage Rendering</h4>
              <p className="text-[#A3A3A3] leading-relaxed">
                Untrusted HTML or JavaScript is never executed. Drive-by malware and browser exploit payloads cannot trigger.
              </p>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-[#39FF88]">No Outbound Target Connections</h4>
              <p className="text-[#A3A3A3] leading-relaxed">
                Backend feature extraction inspects strings purely in-memory. Zero TCP sockets or DNS requests are opened toward target hosts.
              </p>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-[#39FF88]">Decoupled Architecture</h4>
              <p className="text-[#A3A3A3] leading-relaxed">
                FastAPI REST endpoints handle inference, with persistent audit logging in SQLite and reactive visualization via React & Recharts.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
