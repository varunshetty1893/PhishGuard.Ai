import React from 'react';
import { Shield, Lock, Terminal, FileText, Database } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Footer: React.FC = () => {
  return (
    <footer className="bg-[#050505] border-t border-[#292929] text-[#A3A3A3] text-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          {/* Brand Col */}
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#111111] border border-[#39FF88]/40 flex items-center justify-center">
                <Shield className="w-3.5 h-3.5 text-[#39FF88]" />
              </div>
              <span className="font-bold text-sm tracking-tight text-[#F5F5F5]">
                PhishGuard<span className="text-[#39FF88]">.AI</span>
              </span>
            </div>
            <p className="text-xs text-[#A3A3A3] max-w-md leading-relaxed">
              Academic capstone project engineered for transparent machine learning-based phishing URL risk assessment.
              Combines an offline Random Forest lexical classifier with multi-source threat intelligence lookup adapters.
            </p>
            <div className="flex items-center gap-4 text-[11px] text-[#A3A3A3]">
              <span className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-[#39FF88]" />
                Zero-Crawl / SSRF Protected
              </span>
              <span className="flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-[#39FF88]" />
                Local SQLite Persistence
              </span>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] mb-3">
              Application Modules
            </h4>
            <ul className="space-y-2">
              <li>
                <Link to="/scanner" className="hover:text-[#39FF88] transition-colors flex items-center gap-1.5">
                  <Terminal className="w-3 h-3 text-[#39FF88]" />
                  Dedicated URL Scanner
                </Link>
              </li>
              <li>
                <Link to="/dashboard" className="hover:text-[#39FF88] transition-colors">
                  Threat Analytics Dashboard
                </Link>
              </li>
              <li>
                <Link to="/history" className="hover:text-[#39FF88] transition-colors">
                  Scan History & CSV Export
                </Link>
              </li>
              <li>
                <Link to="/ml-lab" className="hover:text-[#39FF88] transition-colors">
                  Machine Learning Lab & Metrics
                </Link>
              </li>
              <li>
                <Link to="/settings" className="hover:text-[#39FF88] transition-colors">
                  Settings, Health & Architecture
                </Link>
              </li>
            </ul>
          </div>

          {/* Academic Context */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] mb-3">
              Academic Evaluation
            </h4>
            <p className="text-[11px] text-[#A3A3A3] leading-relaxed mb-2">
              Master of Computer Applications (MCA) Individual Project. Built with Scikit-learn, FastAPI, React 18, and SQLite.
            </p>
            <a
              href="/api/v1/health"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-[11px] text-[#39FF88] hover:underline"
            >
              <FileText className="w-3 h-3" />
              API Health & Spec Check
            </a>
          </div>
        </div>

        {/* Responsible Use Disclaimer Banner */}
        <div className="pt-6 border-t border-[#181818] text-[11px] text-[#737373] leading-normal flex flex-col md:flex-row justify-between items-center gap-4">
          <p>
            <strong>Responsible-Use Disclaimer:</strong> PhishGuard AI provides statistical probability estimates and third-party lookups.
            A legitimate rating is never an absolute guarantee of website safety. Never download unexpected software or submit credentials blindly.
          </p>
          <p className="shrink-0 text-[#A3A3A3]">
            PhishGuard AI © {new Date().getFullYear()} — All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
};
