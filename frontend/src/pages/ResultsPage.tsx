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
  HelpCircle,
  Info,
  Cpu,
  Database
} from 'lucide-react';
import { api } from '../services/api';
import type { ScanResult } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const ResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const location = useLocation();

  const [result, setResult] = useState<ScanResult | null>(
    (location.state as { result?: ScanResult })?.result || null
  );
  const [loading, setLoading] = useState<boolean>(!result && !!scanId);
  const [error, setError] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    if (!result && scanId) {
      setLoading(true);
      api
        .getScanById(scanId)
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
    } else if (!result && !scanId) {
      setLoading(false);
      setError('No scan ID provided in URL.');
    }
  }, [scanId, result]);

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

  const hasThreatMatch = Boolean(
    result.threat_intel_match ||
    result.threat_intelligence?.google_safe_browsing?.threat_found ||
    result.threat_intelligence?.urlhaus?.threat_found
  );

  // This is the calibrated score used for the final assessment. A raw lexical
  // score can be high for a known, verified domain with a complex URL.
  const assessedMlProbability = typeof result.ml_probability === 'number'
    ? result.ml_probability
    : (result.model_score ?? result.raw_ml_score ?? 0);
  const assessedMlPercent = (assessedMlProbability * 100).toFixed(1);

  // Calibrated score for display
    // Determine cautious, professional headline text
  let verdictHeadline = 'Legitimate Structure';
  let verdictSubtext = 'Conforms to expected web address patterns';

  if (hasThreatMatch) {
    verdictHeadline = 'Confirmed Threat Match';
    verdictSubtext = 'Flagged by external security threat intelligence database';
  } else if (isVerifiedDomain) {
    verdictHeadline = 'Verified Domain Authority';
    verdictSubtext = `Authenticated high-reputation infrastructure (${apexDomain})`;
  } else if (isHighRisk) {
    verdictHeadline = 'Elevated Phishing Risk';
    verdictSubtext = `High Risk Tier · Deceptive lexical anomalies detected (Decision index: ${assessedMlPercent}%)`;
  } else if (isSuspicious) {
    verdictHeadline = 'Suspicious URL Structure';
    verdictSubtext = `Medium Risk Tier · Borderline lexical attributes detected (Decision index: ${assessedMlPercent}%)`;
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

  // Keep the colour language aligned with the final risk assessment:
  // safe = green, borderline = amber/orange, unsafe = red.
  const mlScoreColor = (hasThreatMatch || isHighRisk)
    ? 'text-[#FF525C]'
    : isSuspicious
    ? 'text-[#FF8C42]'
    : 'text-[#39FF88]';

  const mlGaugeColor = (hasThreatMatch || isHighRisk)
    ? 'bg-gradient-to-r from-[#FF525C] to-[#FF1A2E]'
    : isSuspicious
    ? 'bg-gradient-to-r from-[#FF8C42] to-[#FFD54A]'
    : 'bg-gradient-to-r from-[#39FF88] to-[#00E676]';

  // Helper for provider state styling
  const renderProviderState = (name: string, provider: any) => {
    const status = provider?.status || 'Not Configured';
    const isThreat = provider?.threat_found;
    const isNoMatch = status === 'No Match Reported';
    const isUnavailable = status === 'Unavailable';
    const isInvalidKey = (
      (provider?.details || '').includes('unknown_auth_key') ||
      (provider?.details || '').includes('Invalid URLhaus Auth-Key') ||
      status === 'Invalid Auth Key'
    );
        let cardBg = 'bg-[#0A0A0A] border-[#181818]';
    let icon = <HelpCircle className="w-4 h-4 text-[#737373]" />;
    let stateBadge = <span className="text-[11px] px-2 py-0.5 rounded bg-[#181818] border border-[#292929] text-[#737373]">Not Configured</span>;

    if (isThreat) {
      cardBg = 'bg-[#1A0D0F] border-[#FF525C]/40';
      icon = <XCircle className="w-4 h-4 text-[#FF525C]" />;
      stateBadge = <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-[#2A0E12] border border-[#FF525C] text-[#FF525C]">Threat Reported</span>;
    } else if (isNoMatch) {
      cardBg = 'bg-[#0A0A0A] border-[#292929]';
      icon = <CheckCircle2 className="w-4 h-4 text-[#39FF88]" />;
      stateBadge = <span className="text-[11px] px-2 py-0.5 rounded bg-[#0E1A12] border border-[#39FF88]/40 text-[#39FF88]">No Match Reported</span>;
    } else if (isInvalidKey) {
      // Orange: API key is present but rejected by the provider
      cardBg = 'bg-[#1A1100] border-[#FF8C42]/40';
      icon = <AlertTriangle className="w-4 h-4 text-[#FF8C42]" />;
      stateBadge = (
        <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-[#2A1A00] border border-[#FF8C42] text-[#FF8C42]">
          Invalid API Key
        </span>
      );
    } else if (isUnavailable) {
      cardBg = 'bg-[#14120A] border-[#FFD54A]/30';
      icon = <AlertTriangle className="w-4 h-4 text-[#FFD54A]" />;
      stateBadge = <span className="text-[11px] px-2 py-0.5 rounded bg-[#1A170A] border border-[#FFD54A]/40 text-[#FFD54A]">Unavailable</span>;
    }

    return (
      <div className={`p-4 rounded border ${cardBg} space-y-2`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {icon}
            <span className="text-xs font-semibold text-[#F5F5F5]">{name}</span>
          </div>
          {stateBadge}
        </div>
        <p className="text-xs text-[#A3A3A3] leading-relaxed">
          {isInvalidKey ? (
            <>
              Auth Key rejected (unknown_auth_key). Generate a new key at{' '}
              <a
                href="https://urlhaus.abuse.ch/api/"
                target="_blank"
                rel="noreferrer"
                className="text-[#FF8C42] underline hover:text-[#FFD54A] transition-colors"
              >
                urlhaus.abuse.ch/api
              </a>{' '}
              and update <code className="text-[#F5F5F5] bg-[#292929] px-1 rounded">URLHAUS_AUTH_KEY</code> in backend .env.
            </>
          ) : (
            provider?.details || 'Provider query evaluation record.'
          )}
        </p>
        {provider?.category && (
          <span className="inline-block text-[10px] font-mono px-2 py-0.5 rounded bg-[#181010] text-[#FF525C] border border-[#FF525C]/30">
            Identified Threat Category: {provider.category}
          </span>
        )}
      </div>
    );
  };

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
              <strong>Verified Domain Authority:</strong> This link points to authentic enterprise infrastructure under{' '}
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

          {/* Dedicated Side-by-Side: ML Probability vs Final Risk Assessment */}
          <div className="flex flex-col sm:flex-row gap-3">
            {/* 1. Machine Learning Probability Box */}
            <div className="bg-[#050505] p-4 rounded border border-[#292929] min-w-[210px] space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-[#A3A3A3] flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-[#39FF88]" />
                  ML Probability
                </span>
                <span className={`font-mono font-bold ${mlScoreColor}`}>
                  {assessedMlPercent}%
                </span>
              </div>
              <div className="w-full bg-[#181818] rounded-full h-2 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${mlGaugeColor}`}
                  style={{ width: `${Math.min(100, Math.max(2, Number(assessedMlPercent)))}%` }}
                />
              </div>
              <p className="text-[10px] text-[#737373]">
                Green = safe, amber = borderline, red = unsafe. Calibrated on a 50/50 dataset.
              </p>
            </div>

            {/* 2. Final Risk Assessment Box */}
            <div className="bg-[#050505] p-4 rounded border border-[#292929] min-w-[210px] space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-[#A3A3A3] flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-[#FFD54A]" />
                  Final Assessment
                </span>
                <span className="font-semibold text-xs text-[#F5F5F5]">
                  {result.risk_level}
                </span>
              </div>
              <div className="flex items-center gap-2 pt-0.5">
                <StatusBadge type="class" value={result.predicted_class} size="sm" />
                {hasThreatMatch && (
                  <span className="text-[10px] uppercase font-bold text-[#FF525C] px-1.5 py-0.5 rounded bg-[#1A0D0F] border border-[#FF525C]/30">
                    Feed Match
                  </span>
                )}
              </div>
              <p className="text-[10px] text-[#737373]">
                Synthesized from ML, domain authority &amp; threat feeds
              </p>
            </div>
          </div>
        </div>

        {/* Plain Language Interpretation */}
        <div className="pt-4 border-t border-[#292929]/50 text-xs text-[#F5F5F5] leading-relaxed">
          <strong className="text-[#39FF88]">Security Synthesis:</strong> {result.combined_interpretation}
        </div>
      </div>

      {/* Two Column Grid: Threat Intel vs Heuristic Warnings */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Threat Intelligence Findings */}
        <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
              <Database className="w-4 h-4 text-[#FFD54A]" />
              Threat Intelligence Feeds
            </h3>
            <span className="text-[10px] text-[#A3A3A3]">Active Databases</span>
          </div>

          <div className="space-y-4">
            {/* Google Safe Browsing */}
            {renderProviderState('Google Safe Browsing v4', result.threat_intelligence.google_safe_browsing)}

            {/* URLhaus */}
            {renderProviderState('abuse.ch URLhaus', result.threat_intelligence.urlhaus)}

            {/* Critical Security Clarification Notice */}
            <div className="p-3 rounded bg-[#0A0A0A] border border-[#292929] space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-[#FFD54A]">
                <Info className="w-3.5 h-3.5 shrink-0" />
                <span>Absence From Databases Does Not Imply Safety</span>
              </div>
              <p className="text-[11px] text-[#A3A3A3] leading-relaxed">
                Threat databases are retrospective registries. Zero-day phishing campaigns and newly registered domains are absent from threat feeds initially. A &quot;No Match Reported&quot; result simply confirms the URL is not yet indexed; our ML engine independently evaluates structural risks.
              </p>
            </div>
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
              {result.suspicious_reasons.length} Indicator{result.suspicious_reasons.length === 1 ? '' : 's'}
            </span>
          </div>

          {result.suspicious_reasons.length > 0 ? (
            <ul className="space-y-2.5">
              {result.suspicious_reasons.map((reason, idx) => (
                <li
                  key={idx}
                  className={`p-3 rounded border text-xs text-[#F5F5F5] flex items-start gap-2.5 ${
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
                  <span className="leading-relaxed">{reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="p-6 rounded bg-[#0E1A12] border border-[#39FF88]/20 text-center space-y-2">
              <CheckCircle2 className="w-6 h-6 text-[#39FF88] mx-auto" />
              <p className="text-xs text-[#F5F5F5] font-medium">No Structural Anomalies Detected</p>
              <p className="text-[11px] text-[#A3A3A3]">
                The URL adheres to clean conventions with no deceptive keywords, raw IP address structures, or suspicious token lengths.
              </p>
            </div>
          )}

          {/* Recommended Protective Action Checklist */}
          {result.recommended_precautions && result.recommended_precautions.length > 0 && (
            <div className="pt-3 border-t border-[#181818] space-y-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">
                Actionable Protective Guidance
              </span>
              <ul className="space-y-1.5">
                {result.recommended_precautions.map((precaution, idx) => (
                  <li key={idx} className="text-xs text-[#A3A3A3] flex items-start gap-2">
                    <span className="text-[#39FF88] font-mono mt-0.5">&bull;</span>
                    <span>{precaution}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};



