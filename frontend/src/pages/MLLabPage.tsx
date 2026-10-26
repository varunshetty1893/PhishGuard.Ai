import React, { useEffect, useState } from 'react';
import {
  Cpu,
  BarChart2,
  AlertTriangle,
  Layers,
  Target
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
        setError(err.message || 'Failed to load model transparency metadata.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-20 text-center space-y-4">
        <div className="inline-block w-8 h-8 border-2 border-[#39FF88] border-t-transparent rounded-full animate-spin" />
        <p className="text-sm text-[#A3A3A3]">Loading machine learning laboratory metadata...</p>
      </div>
    );
  }

  if (error || !modelInfo) {
    return (
      <div className="max-w-xl mx-auto px-4 py-20 text-center space-y-4">
        <AlertTriangle className="w-8 h-8 text-[#FF525C] mx-auto" />
        <h2 className="text-lg font-bold text-[#F5F5F5]">ML Metadata Unavailable</h2>
        <p className="text-xs text-[#A3A3A3]">{error || 'Could not load model info from backend.'}</p>
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

  const cm = modelInfo.confusion_matrix || { tn: 0, fp: 0, fn: 0, tp: 0 };
  const metrics = modelInfo.evaluation_metrics || {
    accuracy: 0,
    precision: 0,
    recall: 0,
    f1_score: 0,
    roc_auc: 0
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Page Title */}
      <div className="pb-6 border-b border-[#292929]">
        <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-[#111111] border border-[#39FF88]/40 text-xs font-medium text-[#39FF88] mb-2">
          <Cpu className="w-3.5 h-3.5 text-[#39FF88]" />
          <span>Algorithmic Transparency &amp; Validation</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#F5F5F5]">
          Machine Learning Laboratory
        </h1>
        <p className="text-xs text-[#A3A3A3] mt-1">
          Complete empirical audit trail, dataset provenance, held-out evaluation metrics, and feature weights.
        </p>
      </div>

      {/* Model Spec Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-1">
          <span className="text-[10px] uppercase font-semibold text-[#A3A3A3]">Active Classifier</span>
          <div className="text-sm font-bold text-[#F5F5F5]">{modelInfo.algorithm}</div>
          <p className="text-[10px] text-[#39FF88]">Ensemble of 150 Decision Trees</p>
        </div>

        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-1">
          <span className="text-[10px] uppercase font-semibold text-[#A3A3A3]">Model Version</span>
          <div className="text-sm font-bold text-[#F5F5F5]">v{modelInfo.model_version}</div>
          <p className="text-[10px] text-[#A3A3A3]">Trained: {new Date(modelInfo.training_date).toLocaleDateString()}</p>
        </div>

        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-1">
          <span className="text-[10px] uppercase font-semibold text-[#A3A3A3]">Dataset Split</span>
          <div className="text-sm font-bold text-[#F5F5F5]">
            {modelInfo.total_samples.toLocaleString()} URLs
          </div>
          <p className="text-[10px] text-[#A3A3A3]">
            {modelInfo.train_samples.toLocaleString()} Train (80%) / {modelInfo.test_samples.toLocaleString()} Test (20%)
          </p>
        </div>

        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-1">
          <span className="text-[10px] uppercase font-semibold text-[#A3A3A3]">Dataset Provenance</span>
          <div className="text-sm font-bold text-[#F5F5F5] truncate" title={modelInfo.dataset_name}>
            PhishGuard Benchmark
          </div>
          <p className="text-[10px] text-[#39FF88]">Curated Mitchell Krogza + Tranco</p>
        </div>
      </div>

      {/* Primary Empirical Metrics (Cards) */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
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
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">Recall</span>
          <div className="text-2xl font-bold font-mono text-[#39FF88]">
            {(metrics.recall * 100).toFixed(2)}%
          </div>
          <span className="text-[10px] text-[#737373]">TP / (TP + FN)</span>
        </div>

        <div className="p-4 rounded bg-[#0A0A0A] border border-[#292929] text-center space-y-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">F1-Score</span>
          <div className="text-2xl font-bold font-mono text-[#39FF88]">
            {(metrics.f1_score * 100).toFixed(2)}%
          </div>
          <span className="text-[10px] text-[#737373]">Harmonic Mean</span>
        </div>

        <div className="p-4 rounded bg-[#0A0A0A] border border-[#292929] text-center space-y-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">ROC-AUC</span>
          <div className="text-2xl font-bold font-mono text-[#39FF88]">
            {metrics.roc_auc.toFixed(4)}
          </div>
          <span className="text-[10px] text-[#737373]">Discrimination</span>
        </div>
      </div>

      {/* Confusion Matrix and Comparison */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Confusion Matrix Card */}
        <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <Target className="w-4 h-4 text-[#39FF88]" />
              Confusion Matrix (Held-Out Test Set: {modelInfo.test_samples.toLocaleString()} Samples)
            </h3>
          </div>

          <div className="grid grid-cols-2 gap-3 text-center">
            {/* True Negative */}
            <div className="p-4 rounded bg-[#0E1A12] border border-[#39FF88]/40 space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-[#39FF88]">
                True Negatives (TN)
              </span>
              <div className="text-2xl font-bold font-mono text-[#F5F5F5]">{cm.tn}</div>
              <p className="text-[10px] text-[#A3A3A3]">Legitimate correctly identified</p>
            </div>

            {/* False Positive */}
            <div className="p-4 rounded bg-[#181010] border border-[#FF525C]/30 space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-[#FF525C]">
                False Positives (FP)
              </span>
              <div className="text-2xl font-bold font-mono text-[#FF525C]">{cm.fp}</div>
              <p className="text-[10px] text-[#A3A3A3]">Legitimate falsely flagged</p>
            </div>

            {/* False Negative */}
            <div className="p-4 rounded bg-[#181010] border border-[#FF525C]/30 space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-[#FF525C]">
                False Negatives (FN)
              </span>
              <div className="text-2xl font-bold font-mono text-[#FF525C]">{cm.fn}</div>
              <p className="text-[10px] text-[#A3A3A3]">Phishing attack missed</p>
            </div>

            {/* True Positive */}
            <div className="p-4 rounded bg-[#0E1A12] border border-[#39FF88]/40 space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-[#39FF88]">
                True Positives (TP)
              </span>
              <div className="text-2xl font-bold font-mono text-[#F5F5F5]">{cm.tp}</div>
              <p className="text-[10px] text-[#A3A3A3]">Phishing attack caught</p>
            </div>
          </div>

          <p className="text-[11px] text-[#737373] leading-relaxed">
            * Test set evaluated with zero training record overlap, maintaining identical 50/50 class stratification.
          </p>
        </div>

        {/* Algorithm Benchmarking Comparison */}
        <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-[#FFD54A]" />
              Candidate Classifier Comparison
            </h3>
          </div>

          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#181818] text-[#737373]">
                <th className="py-2">Metric</th>
                <th className="py-2 text-[#39FF88]">Random Forest (Selected)</th>
                <th className="py-2 text-[#A3A3A3]">Logistic Regression (Baseline)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181818] text-[#F5F5F5]">
              <tr>
                <td className="py-2 text-[#A3A3A3]">Accuracy</td>
                <td className="py-2 font-mono font-bold text-[#39FF88]">100.0%</td>
                <td className="py-2 font-mono text-[#A3A3A3]">99.90%</td>
              </tr>
              <tr>
                <td className="py-2 text-[#A3A3A3]">Recall (Sensitivity)</td>
                <td className="py-2 font-mono font-bold text-[#39FF88]">100.0%</td>
                <td className="py-2 font-mono text-[#A3A3A3]">99.80%</td>
              </tr>
              <tr>
                <td className="py-2 text-[#A3A3A3]">Precision</td>
                <td className="py-2 font-mono font-bold text-[#39FF88]">100.0%</td>
                <td className="py-2 font-mono text-[#A3A3A3]">100.0%</td>
              </tr>
              <tr>
                <td className="py-2 text-[#A3A3A3]">F1-Score</td>
                <td className="py-2 font-mono font-bold text-[#39FF88]">100.0%</td>
                <td className="py-2 font-mono text-[#A3A3A3]">99.90%</td>
              </tr>
              <tr>
                <td className="py-2 text-[#A3A3A3]">ROC-AUC</td>
                <td className="py-2 font-mono font-bold text-[#39FF88]">1.0000</td>
                <td className="py-2 font-mono text-[#A3A3A3]">1.0000</td>
              </tr>
            </tbody>
          </table>

          <div className="p-3 rounded bg-[#0A0A0A] border border-[#181818] text-xs text-[#A3A3A3] space-y-1">
            <span className="font-semibold text-[#F5F5F5]">Selection Rationale:</span>
            <p className="text-[11px] leading-relaxed">
              Random Forest provides non-linear threshold boundary resolution (e.g. subdomain depths and dot frequency)
              and delivers built-in Gini feature importance rankings without feature scaling dependencies.
            </p>
          </div>
        </div>
      </div>

      {/* Feature Importances (Recharts Bar Chart) */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#39FF88]" />
              Mean Decrease in Impurity (Feature Importance Ranking)
            </h3>
            <p className="text-[11px] text-[#A3A3A3] mt-0.5">
              Empirical relative contribution of each lexical feature toward classification decision splits.
            </p>
          </div>
        </div>

        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={importanceData}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 100, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#181818" horizontal={false} />
              <XAxis type="number" stroke="#737373" fontSize={11} unit="%" />
              <YAxis
                type="category"
                dataKey="feature"
                stroke="#A3A3A3"
                fontSize={11}
                width={120}
              />
              <Tooltip
                contentStyle={{ backgroundColor: '#0A0A0A', borderColor: '#292929', color: '#F5F5F5', fontSize: '12px' }}
                formatter={(val: any) => [`${val}%`, 'Importance Weight']}
              />
              <Bar dataKey="importance" fill="#39FF88" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Model Limitations & Defensive Architecture */}
      <div className="p-6 rounded bg-[#0A0A0A] border border-[#292929] space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#FFD54A] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          Documented Model Limitations &amp; Adversarial Evasion
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded bg-[#111111] border border-[#181818] space-y-2">
            <h4 className="font-semibold text-[#F5F5F5]">Clean Domain Camouflage</h4>
            <p className="text-[#A3A3A3] leading-relaxed">
              An attacker registering a brand-new clean domain without hyphens, dots, or suspicious keywords can evade purely lexical analysis.
            </p>
          </div>

          <div className="p-4 rounded bg-[#111111] border border-[#181818] space-y-2">
            <h4 className="font-semibold text-[#F5F5F5]">URL Shorteners</h4>
            <p className="text-[#A3A3A3] leading-relaxed">
              Shorteners conceal destination paths. PhishGuard flags known shorteners as a distinct suspicious feature to alert users.
            </p>
          </div>

          <div className="p-4 rounded bg-[#111111] border border-[#181818] space-y-2">
            <h4 className="font-semibold text-[#F5F5F5]">Defense in Depth</h4>
            <p className="text-[#A3A3A3] leading-relaxed">
              To mitigate these bounds, PhishGuard pairs the offline ML model with external threat intelligence (Safe Browsing & URLhaus).
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
