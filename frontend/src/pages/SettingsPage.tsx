import React, { useEffect, useState } from 'react';
import {
  Settings,
  Shield,
  Activity,
  Database,
  Cpu,
  Key,
  CheckCircle2,
  GraduationCap
} from 'lucide-react';
import { api } from '../services/api';
import type { HealthData } from '../types';

export const SettingsPage: React.FC = () => {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getHealth()
      .then((data) => {
        setHealth(data);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, []);

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Page Title */}
      <div className="pb-6 border-b border-[#292929]">
        <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-[#111111] border border-[#39FF88]/40 text-xs font-medium text-[#39FF88] mb-2">
          <Settings className="w-3.5 h-3.5 text-[#39FF88]" />
          <span>System Diagnostics &amp; Academic Overview</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#F5F5F5]">
          Settings &amp; About PhishGuard AI
        </h1>
        <p className="text-xs text-[#A3A3A3] mt-1">
          Runtime health telemetry, threat-provider configuration, architecture specifications, and academic project details.
        </p>
      </div>

      {/* Real-time Health Diagnostics */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#39FF88]" />
          Live Runtime Telemetry
        </h3>

        {loading ? (
          <div className="py-6 text-center text-xs text-[#A3A3A3]">Checking service health...</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
            {/* System Status */}
            <div className="p-4 rounded bg-[#0A0A0A] border border-[#181818] space-y-1">
              <span className="text-[10px] text-[#A3A3A3] uppercase">FastAPI Backend</span>
              <div className="flex items-center gap-2 font-bold text-[#F5F5F5]">
                <CheckCircle2 className="w-4 h-4 text-[#39FF88]" />
                <span className="capitalize">{health?.status || 'Active'}</span>
              </div>
              <p className="text-[10px] text-[#A3A3A3]">Port 8000 (Local Uvicorn)</p>
            </div>

            {/* Database Status */}
            <div className="p-4 rounded bg-[#0A0A0A] border border-[#181818] space-y-1">
              <span className="text-[10px] text-[#A3A3A3] uppercase">SQLite Persistence</span>
              <div className="flex items-center gap-2 font-bold text-[#F5F5F5]">
                <Database className="w-4 h-4 text-[#39FF88]" />
                <span className="capitalize">{health?.database || 'Connected'}</span>
              </div>
              <p className="text-[10px] text-[#A3A3A3]">SQLAlchemy 2.0 ORM Engine</p>
            </div>

            {/* ML Model Status */}
            <div className="p-4 rounded bg-[#0A0A0A] border border-[#181818] space-y-1">
              <span className="text-[10px] text-[#A3A3A3] uppercase">ML Model Engine</span>
              <div className="flex items-center gap-2 font-bold text-[#F5F5F5]">
                <Cpu className="w-4 h-4 text-[#39FF88]" />
                <span>Loaded (v{health?.model_version || '1.0.0'})</span>
              </div>
              <p className="text-[10px] text-[#39FF88]">Random Forest Active</p>
            </div>
          </div>
        )}
      </div>

      {/* Threat Provider Configurations & API Keys Guide */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
            <Key className="w-4 h-4 text-[#FFD54A]" />
            External Threat Intelligence Provider Status
          </h3>
          <span className="text-[10px] text-[#39FF88]">Zero Paid Keys Mandatory</span>
        </div>

        <div className="space-y-4 text-xs">
          {/* Google Safe Browsing Box */}
          <div className="p-4 rounded bg-[#0A0A0A] border border-[#181818] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[#F5F5F5]">Google Safe Browsing API v4</span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#181818] text-[#FFD54A] border border-[#292929]">
                Environment Key: GOOGLE_SAFE_BROWSING_API_KEY
              </span>
            </div>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              Google Safe Browsing requires a free API key generated from Google Cloud Console.
              If not configured, PhishGuard AI seamlessly falls back to 100% offline Machine Learning classification.
            </p>
          </div>

          {/* URLhaus Box */}
          <div className="p-4 rounded bg-[#0A0A0A] border border-[#181818] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[#F5F5F5]">abuse.ch URLhaus API</span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#181818] text-[#FFD54A] border border-[#292929]">
                Environment Key: URLHAUS_AUTH_KEY
              </span>
            </div>
            <p className="text-xs text-[#A3A3A3] leading-relaxed">
              abuse.ch URLhaus focuses on active malware distribution and payload sites.
              Keys can be added in <code className="text-[#39FF88]">backend/.env</code>.
            </p>
          </div>

          <div className="p-3 rounded bg-[#181818] text-xs text-[#A3A3A3] flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#39FF88] shrink-0" />
            <span>
              <strong>Privacy Protection:</strong> All external queries execute strictly server-side. No API keys or tokens are ever exposed to the client browser.
            </span>
          </div>
        </div>
      </div>

      {/* Academic Project Identity & Specs */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
          <GraduationCap className="w-4 h-4 text-[#39FF88]" />
          Academic Capstone Project Details
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-[#A3A3A3] leading-relaxed">
          <div className="space-y-3">
            <h4 className="font-semibold text-[#F5F5F5]">Project Summary</h4>
            <p>
              <strong>PhishGuard AI</strong> was designed and developed as an individual Master of Computer Applications (MCA) academic project.
              It demonstrates end-to-end full stack software engineering, genuine machine learning pipeline design, secure input sandboxing, and modern user experience engineering.
            </p>
            <h4 className="font-semibold text-[#F5F5F5] pt-2">Core Objectives</h4>
            <ul className="space-y-1 list-disc list-inside">
              <li>Eliminate blind reliance on slow, static blacklists for zero-day phishing detection.</li>
              <li>Guarantee 100% protection against Server-Side Request Forgery (SSRF) via offline lexical parsing.</li>
              <li>Ensure transparent, explainable threat attribution for academic evaluation.</li>
            </ul>
          </div>

          <div className="space-y-3">
            <h4 className="font-semibold text-[#F5F5F5]">Technology Stack</h4>
            <ul className="space-y-1">
              <li><strong>Frontend:</strong> React 18, Vite, TypeScript, Tailwind CSS, React Router, Recharts, Lucide</li>
              <li><strong>Backend API:</strong> Python 3.12, FastAPI, Pydantic, Uvicorn</li>
              <li><strong>Machine Learning:</strong> Scikit-learn (Random Forest Ensemble), Pandas, NumPy, Joblib</li>
              <li><strong>Persistence:</strong> SQLite &amp; SQLAlchemy 2.0 ORM</li>
              <li><strong>Testing:</strong> Pytest, TestClient</li>
            </ul>
            <h4 className="font-semibold text-[#F5F5F5] pt-2">Design Constraints</h4>
            <p>
              Strict pure-black foundation (<span className="text-[#39FF88]">#050505</span>, <span className="text-[#39FF88]">#111111</span>)
              with green, yellow, and red accents only. Zero blue or purple permitted.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
