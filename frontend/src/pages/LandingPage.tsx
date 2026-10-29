import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Terminal,
  Cpu,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
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
    { label: 'Phishing-style example', url: 'http://login.paypal.com.account-verify.xyz/signin', badge: 'EXAMPLE', color: '#FF525C' },
    { label: 'Known-site example', url: 'https://wikipedia.org/wiki/Computer_science', badge: 'EXAMPLE', color: '#39FF88' },
    { label: 'Short-link example', url: 'https://tinyurl.com/secure-banking-login-test', badge: 'EXAMPLE', color: '#FFD54A' },
  ];

  return (
    <div className="space-y-0 pb-16">
      {/* Hero Section */}
      <section className="relative pt-12 pb-16 px-4 sm:px-6 lg:px-8 border-b border-[#181818] cyber-grid">
        <div className="max-w-4xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#111111] border border-[#39FF88]/40 text-xs font-medium text-[#39FF88]">
            <span className="w-2 h-2 rounded-full bg-[#39FF88] animate-pulse" />
            <span>PhishGuard AI — Link Safety Check</span>
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-[#F5F5F5] leading-tight">
            One Link Can Hide a Threat.{' '}
            <span className="text-[#39FF88]">Detect It Before You Click.</span>
          </h1>

          <p className="text-base sm:text-lg text-[#A3A3A3] max-w-2xl mx-auto leading-relaxed">
            Paste any suspicious link below. We check it for common phishing warning signs without opening it.
            — <strong className="text-[#F5F5F5]">without ever visiting the website</strong>.
            Get a clear result without opening the submitted link.
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
                  placeholder="Paste any suspicious URL here (e.g. http://paypal.com.verify-login.xyz)..."
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
              <p className="mt-2 text-xs text-[#FF525C] flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                {error}
              </p>
            )}

            {/* Sample URLs */}
            <div className="mt-4 flex flex-wrap gap-2 justify-center">
              <span className="text-xs text-[#737373]">Try a demo:</span>
              {sampleUrls.map((s) => (
                <button
                  key={s.url}
                  onClick={() => {
                    setInputUrl(s.url);
                    setError('');
                  }}
                  className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded bg-[#111111] border border-[#292929] hover:border-[#39FF88]/50 text-[#A3A3A3] hover:text-[#F5F5F5] transition-all"
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ backgroundColor: s.color }}
                  />
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* How-it-works steps: Technical */}
      <section className="bg-[#0A0A0A] border-y border-[#181818]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-6">
          <h2 className="text-base font-bold text-[#F5F5F5]">Technical Detection Pipeline</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { num: '01', title: 'Safe Ingestion', desc: 'URL is sanitized and validated in-memory. No browser rendering or network connection to the target.' },
              { num: '02', title: 'Look for Warning Signs', desc: 'We check the address for signs such as unusual dots, hyphens, subdomains, number-based addresses, shorteners, and sign-in words.' },
              { num: '03', title: 'Compare Phishing Patterns', desc: 'Our detection system compares these signs with examples of phishing and safe links.' },
              { num: '04', title: 'Check Known Threats', desc: 'We check local OpenPhish and Phishing.Database feeds, PhishDestroy and PhishStats, and Google Safe Browsing when configured.' },
            ].map((item) => (
              <div key={item.num} className="p-5 rounded bg-[#111111] border border-[#292929] relative space-y-3">
                <div className="w-8 h-8 rounded bg-[#181818] border border-[#39FF88]/40 flex items-center justify-center text-[#39FF88] font-bold text-xs">
                  {item.num}
                </div>
                <h3 className="font-semibold text-sm text-[#F5F5F5]">{item.title}</h3>
                <p className="text-xs text-[#A3A3A3] leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Feature Pillars: ML + Threat Intel */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
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
              The current model was trained on 40,000 links and tested on 7,118 separate links. It is a guide, not a guarantee.
            </p>
            <ul className="space-y-3 text-xs text-[#F5F5F5]">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#39FF88] shrink-0" />
                <span>16 common address warning signs</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#39FF88] shrink-0" />
                <span>Clear results: Likely Safe, Suspicious, or Likely Phishing</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#39FF88] shrink-0" />
                <span>Your submitted link is never opened</span>
              </li>
            </ul>
          </div>

          {/* Column 2: Known threat checks */}
          <div className="p-8 rounded bg-[#0A0A0A] border border-[#292929] space-y-6">
            <div className="inline-flex p-3 rounded bg-[#111111] border border-[#FFD54A]/40">
              <Shield className="w-6 h-6 text-[#FFD54A]" />
            </div>
            <h3 className="text-xl font-bold text-[#F5F5F5]">
              Known Threat Check
            </h3>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              When configured, we check trusted threat databases. Each service reports its own status,
              and a failed external check does not stop the address-pattern check.
            </p>
            <ul className="space-y-3 text-xs text-[#F5F5F5]">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#FFD54A] shrink-0" />
                <span>Optional Google Safe Browsing check</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#FFD54A] shrink-0" />
                <span>OpenPhish and Phishing.Database feed checks</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#FFD54A] shrink-0" />
                <span>The address-pattern check works without these services</span>
              </li>
            </ul>
          </div>
        </div>
      </section>

          {/* Safety highlights */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 pb-4">
        <div className="p-8 rounded bg-[#111111] border border-[#292929] space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h3 className="text-lg font-bold text-[#F5F5F5]">
                🔒 Address Safety Design
              </h3>
              <p className="text-xs text-[#A3A3A3] mt-1">
                PhishGuard AI treats every submitted address as untrusted input.
                <strong className="text-[#F5F5F5]"> The scanner does not fetch the submitted website.</strong>
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="px-3 py-1 rounded bg-[#0E1A12] text-[#39FF88] border border-[#39FF88]/30 font-medium">
                No target fetch
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
                The scanner does not render the submitted webpage or run its HTML and JavaScript.
              </p>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-[#39FF88]">No Outbound Target Connections</h4>
              <p className="text-[#A3A3A3] leading-relaxed">
                The address-pattern check inspects the URL text in memory. Optional known-threat checks contact only their own configured service endpoints.
              </p>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-[#39FF88]">Your Link Stays Closed</h4>
              <p className="text-[#A3A3A3] leading-relaxed">
                We examine the text of the address without opening it in your browser.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
