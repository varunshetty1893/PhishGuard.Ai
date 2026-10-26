import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate, useLocation } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  RotateCcw,
  Copy,
  Check,
  Clock,
  Shield,
  CheckCircle2,
  XCircle,
  Layers,
  Info
} from 'lucide-react';
import { api } from '../services/api';
import type { ScanResult } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const ResultsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();

  const [result, setResult] = useState<ScanResult | null>(
    (location.state as { result?: ScanResult })?.result || null
  );
  const [loading, setLoading] = useState<boolean>(!result);
  const [error, setError] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    if (!result && id) {
      setLoading(true);
      api
        .getScanById(id)
        .then((res) => {
          setResult(res);
          setError('');
        })
        .catch((err) => {
          setError(err.message || 'Failed to retrieve scan report.');
        })
        .finally(() => {
          setLoading(false);
        });
    }
  }, [id, result]);

  const handleCopy = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-20 text-center space-y-4">
        <div className="inline-block w-8 h-8 border-2 border-[#39FF88] border-t-transparent rounded-full animate-spin" />
        <p className="text-sm text-[#A3A3A3]">Retrieving security scan report...</p>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-20 text-center space-y-6">
        <div className="w-12 h-12 rounded-full bg-[#181010] border border-[#FF525C] flex items-center justify-center mx-auto text-[#FF525C]">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <h2 className="text-xl font-bold text-[#F5F5F5]">Scan Record Not Found</h2>
        <p className="text-xs text-[#A3A3A3] max-w-md mx-auto">
          {error || 'The requested scan ID does not exist or was deleted.'}
        </p>
        <Link
          to="/scanner"
          className="inline-flex items-center gap-2 px-4 py-2 rounded bg-[#39FF88] text-[#050505] font-semibold text-xs uppercase"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Run New Scan</span>
        </Link>
      </div>
    );
  }

  const isHighRisk = result.risk_level === 'High Risk';
  const isSuspicious = result.risk_level === 'Suspicious';
  const isVerifiedDomain = Boolean(result.is_verified_domain || result.extracted_features?.is_verified_domain);
  const apexDomain = result.apex_domain || result.extracted_features?.apex_domain || '';

  const scorePercent = result.model_score !== null ? (result.model_score * 100).toFixed(1) : null;
  const rawScorePercent = result.raw_ml_score !== null && result.raw_ml_score !== undefined
    ? (result.raw_ml_score * 100).toFixed(1)
    : null;

  // Determine cautious, professional headline text
  let verdictHeadline = 'Legitimate Structure';
  let verdictSubtext = 'Conforms to expected web address patterns';
  if (isVerifiedDomain) {
    verdictHeadline = 'Verified Domain Authority';
    verdictSubtext = `Authenticated enterprise infrastructure (${apexDomain})`;
  } else if (isHighRisk) {
    verdictHeadline = 'Elevated Phishing Risk';
    verdictSubtext = `Heuristic pattern match (${scorePercent}% statistical probability)`;
  } else if (isSuspicious) {
    verdictHeadline = 'Suspicious URL Structure';
    verdictSubtext = `Anomalous structural attributes detected (${scorePercent}% risk score)`;
  }

  const bannerTheme = isHighRisk
    ? 'bg-[#181010] border-[#FF525C]/50'
    : isSuspicious
    ? 'bg-[#1A1810] border-[#FFD54A]/50'
    : 'bg-[#0E1A12] border-[#39FF88]/50';

  const iconTheme = isHighRisk
    ? 'bg-[#FF525C]/10 border-[#FF525C]/40 text-[#FF525C]'
    : isSuspicious
    ? 'bg-[#FFD54A]/10 border-[#FFD54A]/40 text-[#FFD54A]'
    : 'bg-[#39FF88]/10 border-[#39FF88]/40 text-[#39FF88]';

  const scoreColor = isHighRisk
    ? 'text-[#FF525C]'
    : isSuspicious
    ? 'text-[#FFD54A]'
    : 'text-[#39FF88]';

  const gaugeBarColor = isHighRisk
    ? 'bg-[#FF525C]'
    : isSuspicious
    ? 'bg-[#FFD54A]'
    : 'bg-[#39FF88]';

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      {/* Top Navigation & Actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <button
          onClick={() => navigate('/scanner')}
          className="inline-flex items-center gap-2 text-xs text-[#A3A3A3] hover:text-[#39FF88] transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Scanner</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="px-3 py-1.5 rounded bg-[#111111] hover:bg-[#181818] border border-[#292929] hover:border-[#39FF88] text-xs text-[#F5F5F5] flex items-center gap-1.5 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#39FF88]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Link Copied' : 'Share Report'}</span>
          </button>
          <Link
            to="/scanner"
            className="px-3 py-1.5 rounded bg-[#39FF88] hover:bg-[#16C96A] text-[#050505] font-semibold text-xs flex items-center gap-1.5 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Scan Another</span>
          </Link>
        </div>
      </div>

      {/* Target URL Header Card */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-[#A3A3A3]">
          <span className="flex items-center gap-1.5 font-mono">
            <span className="text-[#39FF88]">ID:</span> {result.scan_id}
          </span>
          <span className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5" />
            {new Date(result.created_at).toUTCString()}
          </span>
        </div>

        <div>
          <label className="text-[10px] uppercase tracking-wider font-semibold text-[#A3A3A3]">
            Analyzed Web Address (Untrusted Input)
          </label>
          <div className="mt-1 p-3 rounded bg-[#050505] border border-[#292929] font-mono text-sm text-[#F5F5F5] break-all select-all">
            {result.submitted_url}
          </div>
        </div>

        {isVerifiedDomain && apexDomain && (
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-[#0E1A12] border border-[#39FF88]/40 text-[#39FF88] text-xs">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>
              <strong>Verified Domain Authority:</strong> This link points to genuine infrastructure under{' '}
              <strong className="underline">{apexDomain}</strong>.
            </span>
          </div>
        )}
      </div>

      {/* Primary Verdict Hero Banner */}
      <div className={`p-6 sm:p-8 rounded border ${bannerTheme} space-y-6`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <div className={`p-2.5 rounded border ${iconTheme}`}>
                {isHighRisk ? (
                  <ShieldAlert className="w-8 h-8" />
                ) : isSuspicious ? (
                  <AlertTriangle className="w-8 h-8" />
                ) : (
                  <ShieldCheck className="w-8 h-8" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-2xl font-bold tracking-tight text-[#F5F5F5]">
                    {verdictHeadline}
                  </h2>
                  <StatusBadge type="risk" value={result.risk_level} size="md" />
                </div>
                <p className="text-xs text-[#A3A3A3] mt-0.5">
                  {verdictSubtext} &bull; Model v{result.model_version}
                </p>
              </div>
            </div>
          </div>

          {/* Model Probability Gauge */}
          {scorePercent !== null && (
            <div className="bg-[#050505] p-4 rounded border border-[#292929] min-w-[240px] space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-[#A3A3A3]">
                  {isVerifiedDomain ? 'Calibrated Risk Score' : 'Phishing Probability'}
                </span>
                <span className={`font-mono font-bold ${scoreColor}`}>
                  {scorePercent}%
                </span>
              </div>
              <div className="w-full bg-[#181818] rounded-full h-2.5 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${gaugeBarColor}`}
                  style={{ width: `${Math.min(100, Math.max(2, Number(scorePercent)))}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] text-[#737373]">
                <span>Low &lt;45%</span>
                <span>Suspicious 45-74%</span>
                <span>High &ge;75%</span>
              </div>
              {isVerifiedDomain && rawScorePercent && Number(rawScorePercent) > 50 && (
                <p className="text-[10px] text-[#A3A3A3] pt-1 border-t border-[#181818]">
                  * Raw lexical complexity score: {rawScorePercent}%. Calibrated to safe due to verified domain authority.
                </p>
              )}
            </div>
          )}
        </div>

        {/* Plain Language Interpretation */}
        <div className="pt-4 border-t border-[#292929]/50 text-xs text-[#F5F5F5] leading-relaxed">
          <strong>Security Analysis Summary:</strong> {result.combined_interpretation}
        </div>
      </div>

      {/* Two Column Grid: Threat Intel vs Heuristic Warnings */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Threat Intelligence Findings */}
        <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#FFD54A]" />
              External Threat Intelligence
            </h3>
            <span className="text-[10px] text-[#A3A3A3]">Third-Party Blacklists</span>
          </div>

          <div className="space-y-4">
            {/* Google Safe Browsing */}
            <div className="p-4 rounded bg-[#0A0A0A] border border-[#181818] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-[#F5F5F5]">Google Safe Browsing v4</span>
                <StatusBadge type="threat" value={result.threat_intelligence.google_safe_browsing.status} size="sm" />
              </div>
              <p className="text-xs text-[#A3A3A3] leading-relaxed">
                {result.threat_intelligence.google_safe_browsing.details || 'Lookup status available in report.'}
              </p>
              {result.threat_intelligence.google_safe_browsing.category && (
                <span className="inline-block text-[10px] font-mono px-2 py-0.5 rounded bg-[#1A0D0F] text-[#FF525C] border border-[#FF525C]/30">
                  Category: {result.threat_intelligence.google_safe_browsing.category}
                </span>
              )}
            </div>

            {/* URLhaus */}
            <div className="p-4 rounded bg-[#0A0A0A] border border-[#181818] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-[#F5F5F5]">abuse.ch URLhaus</span>
                <StatusBadge type="threat" value={result.threat_intelligence.urlhaus.status} size="sm" />
              </div>
              <p className="text-xs text-[#A3A3A3] leading-relaxed">
                {result.threat_intelligence.urlhaus.details || 'Malware and distribution lookup status.'}
              </p>
              {result.threat_intelligence.urlhaus.category && (
                <span className="inline-block text-[10px] font-mono px-2 py-0.5 rounded bg-[#1A0D0F] text-[#FF525C] border border-[#FF525C]/30">
                  Tag: {result.threat_intelligence.urlhaus.category}
                </span>
              )}
            </div>

            <p className="text-[11px] text-[#737373] leading-tight pt-1">
              * A &quot;No Match Reported&quot; result indicates the URL has not been indexed in active malware feeds yet; zero-day phishing is detected by lexical ML.
            </p>
          </div>
        </div>

        {/* Explainable Heuristics & Anomaly Indicators */}
        <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#FF525C]" />
              Detected Anomaly Explanations
            </h3>
            <span className="text-[10px] text-[#A3A3A3]">
              {result.suspicious_reasons.length} Flag{result.suspicious_reasons.length === 1 ? '' : 's'}
            </span>
          </div>

          {result.suspicious_reasons.length > 0 ? (
            <ul className="space-y-2.5">
              {result.suspicious_reasons.map((reason, idx) => (
                <li
                  key={idx}
                  className={`p-2.5 rounded border text-xs text-[#F5F5F5] flex items-start gap-2.5 ${
                    isVerifiedDomain
                      ? 'bg-[#0E1A12] border-[#39FF88]/20'
                      : 'bg-[#181010] border-[#FF525C]/20'
                  }`}
                >
                  {isVerifiedDomain ? (
                    <Info className="w-4 h-4 text-[#39FF88] shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-[#FF525C] shrink-0 mt-0.5" />
                  )}
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="p-6 rounded bg-[#0E1A12] border border-[#39FF88]/20 text-center space-y-2">
              <CheckCircle2 className="w-6 h-6 text-[#39FF88] mx-auto" />
              <p className="text-xs text-[#F5F5F5] font-medium">No Structural Anomalies Detected</p>
              <p className="text-[11px] text-[#A3A3A3]">
                The URL structure adheres to expected domain formatting without deceptive character patterns.
              </p>
            </div>
          )}

          {/* Recommended Precautions */}
          <div className="pt-3 border-t border-[#181818] space-y-2">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-[#A3A3A3]">
              Recommended Precautions
            </h4>
            <ul className="space-y-1.5 text-xs text-[#A3A3A3]">
              {result.recommended_precautions.map((p, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-[#39FF88]">&bull;</span>
                  <span>{p}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* 16 Extracted Security Features Table */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#39FF88]" />
              Extracted Lexical Feature Matrix (16 Dimensions)
            </h3>
            <p className="text-[11px] text-[#A3A3A3] mt-0.5">
              Exact numerical vector evaluated by the Random Forest decision ensemble.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          {Object.entries(result.extracted_features)
            .filter(([key]) => !['apex_domain', 'is_verified_domain'].includes(key))
            .map(([key, val]) => {
              const isHighlight =
                (typeof val === 'number' && val > 0 && ['has_ip', 'count_at', 'has_suspicious_keywords'].includes(key)) ||
                (key === 'is_https' && val === 0) ||
                (typeof val === 'number' && val >= 3 && ['count_hyphens', 'count_subdomains'].includes(key)) ||
                (key === 'count_dots' && typeof val === 'number' && val >= 4);

              return (
                <div
                  key={key}
                  className={`p-3 rounded border ${
                    isHighlight
                      ? 'bg-[#181010] border-[#FF525C]/30 text-[#FF525C]'
                      : 'bg-[#0A0A0A] border-[#181818] text-[#F5F5F5]'
                  }`}
                >
                  <div className="text-[10px] text-[#A3A3A3] font-mono truncate" title={key}>
                    {key}
                  </div>
                  <div className="text-base font-bold font-mono mt-1">
                    {typeof val === 'number' ? val : String(val)}
                  </div>
                </div>
              );
            })}
        </div>

        {/* Responsible Disclaimer */}
        <p className="text-[11px] text-[#737373] leading-relaxed pt-3 border-t border-[#181818]">
          <strong className="text-[#A3A3A3]">Methodology Note:</strong> PhishGuard AI evaluates lexical and structural features without downloading or rendering untrusted web content. Automated probability scores serve as statistical guidance and do not guarantee the presence or absence of novel threats.
        </p>
      </div>
    </div>
  );
};
