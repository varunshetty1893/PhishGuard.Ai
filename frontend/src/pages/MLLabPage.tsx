import React, { useEffect, useState } from 'react';
import {
  Cpu,
  AlertTriangle,
  Layers,
  Target,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { api } from '../services/api';
import type { ModelMetadata } from '../types';

export const MLLabPage: React.FC = () => {
  const [modelInfo, setModelInfo] = useState<ModelMetadata | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api.getModelInfo()
      .then((data) => {
        setModelInfo(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Could not load detection-system details.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-20 text-center space-y-4">
        <div className="inline-block w-8 h-8 border-2 border-[#39FF88] border-t-transparent rounded-full animate-spin" />
        <p className="text-sm text-[#A3A3A3]">Loading detection-system details...</p>
      </div>
    );
  }

  if (error || !modelInfo) {
    return (
      <div className="max-w-xl mx-auto px-4 py-20 text-center space-y-4">
        <AlertTriangle className="w-8 h-8 text-[#FF525C] mx-auto" />
        <h2 className="text-lg font-bold text-[#F5F5F5]">Detection Details Unavailable</h2>
        <p className="text-xs text-[#A3A3A3]">{error || 'Could not load detection-system details.'}</p>
      </div>
    );
  }

  // Format feature importances for chart
  const importanceData = Object.entries(modelInfo.feature_importances || {})
    .map(([feature, weight]) => ({
      feature,
      importance: Number((weight * 100).toFixed(2))
    }))
    .sort((a, b) => b.importance - a.importance);

  const cm = modelInfo.confusion_matrix || { tn: 3793, fp: 76, fn: 150, tp: 3099 };
  const metrics = modelInfo.evaluation_metrics || {
    accuracy: 0.9682,
    precision: 0.9761,
    recall: 0.9538,
    f1_score: 0.9648,
    roc_auc: 0.9928,
    false_positive_rate: 0.0196,
    false_negative_rate: 0.0462,
    long_tail_legit_fpr: 0.1306,
    hard_phishing_recall: 0.9667
  };

  const fpr = metrics.false_positive_rate ?? (cm.fp / (cm.fp + cm.tn));
  const fnr = metrics.false_negative_rate ?? (cm.fn / (cm.fn + cm.tp));

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Page Title */}
      <div className="pb-6 border-b border-[#292929]">
        <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-[#111111] border border-[#39FF88]/40 text-xs font-medium text-[#39FF88] mb-2">
          <Cpu className="w-3.5 h-3.5 text-[#39FF88]" />
          <span>How the Detection System Is Tested</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#F5F5F5]">
          Detection System Details
        </h1>
        <p className="text-xs text-[#A3A3A3] mt-1">
          Test results, the examples used to train the system, and the situations where it may be less reliable.
        </p>
      </div>

      {/* Domain-Isolated 3-Split Protocol Banner */}
      <div className="p-6 rounded bg-[#0E1A12] border border-[#39FF88]/40 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck className="w-5 h-5 text-[#39FF88]" />
              <h2 className="text-base font-bold text-[#F5F5F5]">Domain-Isolated 3-Way Partitioning (Zero Domain Leakage)</h2>
            </div>
            <p className="text-xs text-[#A3A3A3] leading-relaxed max-w-3xl">
              The current model used separate website groups for training, validation, and testing: <strong>60% training (18,384 website groups)</strong>,
              <strong> 20% validation (6,128 groups)</strong>, and <strong>20% testing (6,128 groups)</strong>. The risk cutoff (0.640)
              was selected using the validation set, not the test set.
            </p>
          </div>
          <span className="self-start px-2.5 py-1 rounded bg-[#111111] border border-[#39FF88]/40 text-[#39FF88] font-mono text-[11px] font-semibold">
            No shared website groups between splits
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3 rounded bg-[#111111] border border-[#292929] text-center">
            <div className="text-2xl font-bold font-mono text-[#39FF88]">{modelInfo.total_samples?.toLocaleString() || '40,000'}</div>
            <div className="text-[11px] text-[#A3A3A3] mt-1">Current model samples</div>
          </div>
          <div className="p-3 rounded bg-[#111111] border border-[#292929] text-center">
            <div className="text-2xl font-bold font-mono text-[#39FF88]">{modelInfo.train_samples?.toLocaleString() || '23,913'}</div>
            <div className="text-[11px] text-[#A3A3A3] mt-1">Train Partition (60%)</div>
          </div>
          <div className="p-3 rounded bg-[#111111] border border-[#292929] text-center">
            <div className="text-2xl font-bold font-mono text-[#FFD54A]">8,969</div>
            <div className="text-[11px] text-[#A3A3A3] mt-1">Validation Partition (20%)</div>
          </div>
          <div className="p-3 rounded bg-[#111111] border border-[#292929] text-center">
            <div className="text-2xl font-bold font-mono text-[#39FF88]">{modelInfo.test_samples?.toLocaleString() || '7,118'}</div>
            <div className="text-[11px] text-[#A3A3A3] mt-1">Held-Out Test Partition (20%)</div>
          </div>
        </div>
      </div>

      {/* Model Spec Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-1">
          <span className="text-[10px] uppercase font-semibold text-[#A3A3A3]">Active Classifier</span>
          <div className="text-sm font-bold text-[#F5F5F5]">{modelInfo.algorithm}</div>
          <p className="text-[10px] text-[#39FF88]">200 decision trees; scores are adjusted for consistency</p>
        </div>

        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-1">
          <span className="text-[10px] uppercase font-semibold text-[#A3A3A3]">Detection System Version</span>
          <div className="text-sm font-bold text-[#F5F5F5]">v{modelInfo.model_version}</div>
          <p className="text-[10px] text-[#A3A3A3]">Decision Threshold: 0.640</p>
        </div>

        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-1">
          <span className="text-[10px] uppercase font-semibold text-[#A3A3A3]">Collection Windows</span>
          <div className="text-sm font-bold text-[#F5F5F5]">Training and evaluation dates</div>
          <p className="text-[10px] text-[#A3A3A3]">Training links: 2020–2023 | Extra checks: October 2026</p>
        </div>

        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-1">
          <span className="text-[10px] uppercase font-semibold text-[#A3A3A3]">Decision Principle</span>
          <div className="text-sm font-bold text-[#F5F5F5]">Result categories</div>
          <p className="text-[10px] text-[#39FF88]">Likely Safe / Suspicious / Likely Phishing</p>
        </div>
      </div>

      {/* Primary Empirical Held-Out Test Metrics */}
      <div className="space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#A3A3A3] flex items-center gap-2">
          <Target className="w-4 h-4 text-[#39FF88]" />
          Held-Out Test Results (7,118 links from separate website groups)
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          <div className="p-4 rounded bg-[#0A0A0A] border border-[#292929] text-center space-y-1">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">Accuracy</span>
            <div className="text-2xl font-bold font-mono text-[#39FF88]">
              {(metrics.accuracy * 100).toFixed(2)}%
            </div>
            <span className="text-[10px] text-[#737373]">Overall Correct</span>
          </div>

          <div className="p-4 rounded bg-[#0A0A0A] border border-[#292929] text-center space-y-1">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">Precision</span>
            <div className="text-2xl font-bold font-mono text-[#39FF88]">
              {(metrics.precision * 100).toFixed(2)}%
            </div>
            <span className="text-[10px] text-[#737373]">TP / (TP + FP)</span>
          </div>

          <div className="p-4 rounded bg-[#0A0A0A] border border-[#292929] text-center space-y-1">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">Phishing Recall</span>
            <div className="text-2xl font-bold font-mono text-[#39FF88]">
              {(metrics.recall * 100).toFixed(2)}%
            </div>
            <span className="text-[10px] text-[#737373]">Threats Caught</span>
          </div>

          <div className="p-4 rounded bg-[#0A0A0A] border border-[#292929] text-center space-y-1">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[#39FF88]">Safe Links Incorrectly Flagged</span>
            <div className="text-2xl font-bold font-mono text-[#39FF88]">
              {(fpr * 100).toFixed(2)}%
            </div>
            <span className="text-[10px] text-[#737373]">{cm.fp} / {cm.fp + cm.tn} Legit</span>
          </div>

          <div className="p-4 rounded bg-[#0A0A0A] border border-[#292929] text-center space-y-1">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[#FF525C]">Missed Threats (FNR)</span>
            <div className="text-2xl font-bold font-mono text-[#FF525C]">
              {(fnr * 100).toFixed(2)}%
            </div>
            <span className="text-[10px] text-[#737373]">{cm.fn} / {cm.fn + cm.tp} Phish</span>
          </div>

          <div className="p-4 rounded bg-[#0A0A0A] border border-[#292929] text-center space-y-1">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[#39FF88]">ROC-AUC</span>
            <div className="text-2xl font-bold font-mono text-[#39FF88]">
              {(metrics.roc_auc * 100).toFixed(2)}%
            </div>
            <span className="text-[10px] text-[#737373]">Discrimination</span>
          </div>
        </div>
      </div>

      {/* Out-of-Distribution Stress Test Highlights: Long-Tail Legit vs Hard Phishing */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#FFD54A]" />
              Hard Long-Tail Legitimate Stress Test (1,080 URLs)
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#181818] text-[#FFD54A]">
              13.06% flagged incorrectly (141 of 1,080)
            </span>
          </div>
          <p className="text-xs text-[#A3A3A3] leading-relaxed">
            Tested on 1,080 legitimate links outside the main training selection, including lower-ranked websites, real sign-in pages, small organizations, and links with account-related words.
          </p>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1.5 border-b border-[#1A1A1A]">
              <span className="text-[#A3A3A3]">Tranco Ranks 200k-1M (Bare Domains)</span>
              <span className="font-mono text-[#39FF88] font-bold">0.55% FPR (3/550 FP)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-[#1A1A1A]">
              <span className="text-[#A3A3A3]">SMBs / Schools / Hyphen &amp; Digit Hostnames</span>
              <span className="font-mono text-[#39FF88] font-bold">3.00% FPR (6/200 FP)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-[#1A1A1A]">
              <span className="text-[#A3A3A3]">Authentic Login &amp; SSO Portals (Google, MS, MIT)</span>
              <span className="font-mono text-[#FF525C] font-bold">46.67% FPR (14/30 FP)</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-[#A3A3A3]">Legitimate URLs with Security Keywords (/billing, /portal)</span>
              <span className="font-mono text-[#FF525C] font-bold">36.00% - 52.00% FPR</span>
            </div>
          </div>
        </div>

        <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-[#39FF88]" />
              Hard Phishing Test Set (600 URLs, Live 2026 Feeds)
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#181818] text-[#39FF88]">
              Flagged 580 of 600 known phishing links (96.67%)
            </span>
          </div>
          <p className="text-xs text-[#A3A3A3] leading-relaxed">
            Checked against an October 2026 OpenPhish collection and other phishing links kept out of the training selection.
          </p>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1.5 border-b border-[#1A1A1A]">
              <span className="text-[#A3A3A3]">All HTTPS Phishing (No HTTP shortcut)</span>
              <span className="font-mono text-[#39FF88] font-bold">95.34% Recall (389/408)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-[#1A1A1A]">
              <span className="text-[#A3A3A3]">Bare-Domain Phishing (No Path)</span>
              <span className="font-mono text-[#39FF88] font-bold">98.70% Recall (303/307)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-[#1A1A1A]">
              <span className="text-[#A3A3A3]">Compromised Legitimate Sites (CMS/WordPress)</span>
              <span className="font-mono text-[#39FF88] font-bold">99.33% Recall (149/150)</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-[#A3A3A3]">Platform-Hosted Phishing (Cloud/PaaS Subdomains)</span>
              <span className="font-mono text-[#39FF88] font-bold">98.02% Recall (247/252)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Honest Limitations & Failure Modes Section */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#FF525C] flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-[#FF525C]" />
            What This Check May Miss
          </h3>
          <span className="text-[10px] text-[#A3A3A3]">Important limits</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs leading-relaxed">
          <div className="p-3.5 rounded bg-[#0A0A0A] border border-[#292929] space-y-1.5">
            <div className="font-semibold text-[#FFD54A]">1. The Risk Score Is Not a Guarantee</div>
            <p className="text-[#A3A3A3]">
              The system was trained with a balanced mix of safe and phishing links. A score of 65/100 means the address has many warning signs; it does not mean there is a 65% chance the site is phishing. Read scores as <strong>Likely Safe</strong>, <strong>Suspicious</strong>, or <strong>Likely Phishing</strong>.
            </p>
          </div>
          <div className="p-3.5 rounded bg-[#0A0A0A] border border-[#292929] space-y-1.5">
            <div className="font-semibold text-[#FFD54A]">2. Authentic Login Portals &amp; Security Keywords</div>
            <p className="text-[#A3A3A3]">
              Real sign-in pages (for example <code>accounts.google.com</code> or <code>login.microsoftonline.com</code>) and paths like <code>/billing/invoices</code> can resemble fake sign-in pages. This can cause safe links to be flagged incorrectly.
            </p>
          </div>
          <div className="p-3.5 rounded bg-[#0A0A0A] border border-[#292929] space-y-1.5">
            <div className="font-semibold text-[#FF525C]">3. Shortened Links &amp; Clean Cloud Portfolios</div>
            <p className="text-[#A3A3A3]">
              Phishing links hidden behind shorteners (such as <code>e.vg/xxx</code>) or developer project pages (such as <code>github.io</code>) can look normal. The address check may miss them, so the known-threat checks are especially useful.
            </p>
          </div>
          <div className="p-3.5 rounded bg-[#0A0A0A] border border-[#292929] space-y-1.5">
            <div className="font-semibold text-[#FF525C]">4. New Phishing Patterns Can Change</div>
            <p className="text-[#A3A3A3]">
              Attackers change their links and techniques over time. This model is not continuously retrained, so its performance may change as new phishing patterns appear.
            </p>
          </div>
        </div>
      </div>

      {/* Feature Importance Bar Chart */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#39FF88]" />
            16-Dimensional Feature Attribution &amp; Gini Importance
          </h3>
          <span className="text-[10px] text-[#A3A3A3]">Random Forest Feature Weighting</span>
        </div>

        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={importanceData}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 100, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#292929" horizontal={false} />
              <XAxis type="number" unit="%" stroke="#737373" fontSize={10} />
              <YAxis
                type="category"
                dataKey="feature"
                stroke="#A3A3A3"
                fontSize={10}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#050505',
                  border: '1px solid #292929',
                  borderRadius: '4px',
                  fontSize: '11px',
                  color: '#F5F5F5'
                }}
                formatter={(value: any) => [`${value}%`, 'Importance Weight']}
              />
              <Bar dataKey="importance" fill="#39FF88" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
