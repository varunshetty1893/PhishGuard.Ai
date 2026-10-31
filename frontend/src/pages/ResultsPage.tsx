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
  Database,
  Globe,
  Lock,
  WifiOff
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
  const isNxDomain = result.extracted_features?.dns_resolved === 0 || result.suspicious_reasons.some(r => /NXDOMAIN|does not exist/i.test(r));

  const hasThreatMatch = Boolean(
    result.threat_intel_match ||
    Object.values(result.threat_intelligence || {}).some((provider) => provider?.threat_found)
  );

  const assessedMlProbability = typeof result.ml_probability === 'number'
    ? result.ml_probability
    : (result.model_score ?? result.raw_ml_score ?? 0);
  const assessedMlPercent = (assessedMlProbability * 100).toFixed(1);

  // Determine cautious, professional headline text
  let verdictHeadline = 'Likely Safe';
  let verdictSubtext = 'No major warning signs were found. Safety is not guaranteed.';

  if (hasThreatMatch) {
    verdictHeadline = 'Confirmed Dangerous Link';
    verdictSubtext = 'A known-threat service has flagged this address. Do not open it or enter information.';
  } else if (isHighRisk) {
    if (isNxDomain) {
      verdictHeadline = 'Likely Phishing (Non-Existent Typosquat)';
      verdictSubtext = `Mimics a known brand but does not resolve in public DNS (risk score: ${assessedMlPercent}/100).`;
    } else {
      verdictHeadline = 'Likely Phishing';
      verdictSubtext = `Strong warning signs were found (risk score: ${assessedMlPercent}/100). Do not enter passwords or payment details.`;
    }
  } else if (isNxDomain) {
    verdictHeadline = 'Inactive / Non-Existent Website';
    verdictSubtext = `This domain does not resolve in public DNS (NXDOMAIN). The site cannot be reached.`;
  } else if (isVerifiedDomain) {
    verdictHeadline = 'Website Identity Check Passed';
    verdictSubtext = `This address uses the verified ${apexDomain} domain. This alone does not guarantee safety.`;
  } else if (isSuspicious) {
    verdictHeadline = 'Suspicious';
    verdictSubtext = `Some warning signs were found (risk score: ${assessedMlPercent}/100). Verify the link before entering information.`;
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

  // Translate warning signs accurately to plain, friendly English
  const plainWarning = (reason: string): string => {
    if (/does not exist|NXDOMAIN/i.test(reason)) return 'This website address does not exist or has no active DNS records (cannot be reached).';
    if (/Raw IP address/i.test(reason)) return 'This address uses numbers instead of a normal website name.';
    if (/Contains '@'/i.test(reason)) return 'This address uses an @ symbol, which can hide the real website name.';
    if (/subdomain nesting/i.test(reason)) return 'This address has many sections before the main website name, which can be misleading.';
    if (/hyphens/i.test(reason)) return 'This address has many hyphens, which are sometimes used to imitate a trusted name.';
    if (/dot count/i.test(reason)) return 'This address has an unusual number of dots.';
    if (/unencrypted HTTP/i.test(reason)) return 'This website uses an unencrypted connection.';
    if (/sensitive keywords/i.test(reason)) return `This address contains words often used to trick people into signing in.${reason.match(/: (.+)\.$/) ? ` (${reason.match(/: (.+)\.$/)![1]})` : ''}`;
    if (/shortening service/i.test(reason)) return 'This shortened link hides where it leads.';
    if (/special characters/i.test(reason)) return 'This address contains an unusual number of special characters.';
    if (/High-risk TLD/i.test(reason)) return 'This address ends in a domain type that is often abused for phishing.';
    if (/resembles a well-known brand|typosquat/i.test(reason)) return 'This address uses a name that resembles a well-known company (possible typosquatting).';
    if (/trusted brand name appears/i.test(reason)) return 'This address mentions a trusted brand in a misleading part of the name.';
    if (/Punycode/i.test(reason)) return 'This address uses encoded characters that can make a fake name look real.';
    if (/hostname entropy/i.test(reason)) return 'This address has a random-looking website name.';
    return reason;
  };

  // Strictly deduplicate translated warning signs so the same bullet point never repeats
  const uniqueWarnings = Array.from(
    new Set((result.suspicious_reasons || []).map(plainWarning))
  );

  // Helper for compact provider state styling
  const renderProviderState = (name: string, provider: any) => {
    const status = provider?.status || 'Not Configured';
    const isThreat = provider?.threat_found;
    const isNoMatch = status === 'No Match Reported';
    const isUnverifiedReport = status === 'Unverified Reported';
    const isUnavailable = status === 'Unavailable';

    let cardBg = 'bg-[#0A0A0A] border-[#181818]';
    let icon = <HelpCircle className="w-3.5 h-3.5 text-[#737373] shrink-0" />;
    let stateBadge = (
      <span className="text-[10px] px-2 py-0.5 rounded bg-[#181818] border border-[#292929] text-[#737373]">
        Not Set Up
      </span>
    );

    if (isThreat) {
      cardBg = 'bg-[#1A0D0F] border-[#FF525C]/40';
      icon = <XCircle className="w-3.5 h-3.5 text-[#FF525C] shrink-0" />;
      stateBadge = isUnverifiedReport ? (
        <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-[#2A0E12] border border-[#FF525C] text-[#FF525C]">
          Harmful
        </span>
      ) : (
        <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-[#2A0E12] border border-[#FF525C] text-[#FF525C]">
          Threat Reported
        </span>
      );
    } else if (isNoMatch) {
      cardBg = 'bg-[#0A0A0A] border-[#202020]';
      icon = <CheckCircle2 className="w-3.5 h-3.5 text-[#39FF88] shrink-0" />;
      stateBadge = (
        <span className="text-[10px] px-2 py-0.5 rounded bg-[#0E1A12] border border-[#39FF88]/40 text-[#39FF88]">
          No Match
        </span>
      );
    } else if (isUnverifiedReport) {
      cardBg = 'bg-[#14120A] border-[#FFD54A]/30';
      icon = <AlertTriangle className="w-3.5 h-3.5 text-[#FFD54A] shrink-0" />;
      stateBadge = (
        <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-[#1A170A] border border-[#FFD54A]/40 text-[#FFD54A]">
          Reported
        </span>
      );
    } else if (isUnavailable) {
      cardBg = 'bg-[#14120A] border-[#FFD54A]/30';
      icon = <AlertTriangle className="w-3.5 h-3.5 text-[#FFD54A] shrink-0" />;
      stateBadge = (
        <span className="text-[10px] px-2 py-0.5 rounded bg-[#1A170A] border border-[#FFD54A]/40 text-[#FFD54A]">
          Unavailable
        </span>
      );
    }

    return (
      <div className={`p-2.5 sm:p-3 rounded-lg border ${cardBg} space-y-1 transition-colors`}>
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0 truncate">
            {icon}
            <span className="text-xs font-semibold text-[#F5F5F5] truncate">{name}</span>
          </div>
          {stateBadge}
        </div>
        <p className="text-[11px] text-[#A3A3A3] line-clamp-2 leading-tight">
          {provider?.details || 'No records returned.'}
        </p>
      </div>
    );
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-5">
      {/* Top Header & Fast Actions */}
      <div className="flex items-center justify-between gap-3">
        <button
          onClick={() => navigate('/scanner')}
          className="inline-flex items-center gap-1.5 text-xs text-[#A3A3A3] hover:text-[#39FF88] transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Scanner</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="px-2.5 py-1.5 rounded bg-[#111111] hover:bg-[#181818] border border-[#292929] hover:border-[#39FF88] text-xs text-[#F5F5F5] flex items-center gap-1.5 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#39FF88]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Share Report'}</span>
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

      {/* Target URL Header Card - Compact & Clean */}
      <div className="p-4 rounded-xl bg-[#111111] border border-[#292929] space-y-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-[#A3A3A3]">
          <span className="flex items-center gap-1 font-mono">
            <span className="text-[#39FF88]">SCAN ID:</span> {result.scan_id}
          </span>
          <span className="flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-[#737373]" />
            {new Date(result.created_at).toUTCString()}
          </span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1">
          <div className="min-w-0 flex-1">
            <span className="text-[10px] uppercase tracking-wider font-semibold text-[#737373] block mb-1">
              Analyzed Web Address
            </span>
            <div className="p-2.5 rounded-lg bg-[#050505] border border-[#242424] font-mono text-xs text-[#F5F5F5] break-all select-all flex items-center justify-between gap-2">
              <span className="truncate">{result.submitted_url}</span>
              <button
                onClick={() => navigator.clipboard.writeText(result.submitted_url)}
                className="text-[#737373] hover:text-[#39FF88] text-[11px] shrink-0"
                title="Copy URL"
              >
                Copy
              </button>
            </div>
          </div>
        </div>

        {/* Status flags row */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          {isVerifiedDomain && apexDomain && (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#0E1A12] border border-[#39FF88]/40 text-[#39FF88] text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
              <span>Verified Authority: <strong>{apexDomain}</strong></span>
            </div>
          )}
          {isNxDomain && (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#201010] border border-[#FF525C]/50 text-[#FF525C] text-[11px]">
              <WifiOff className="w-3.5 h-3.5 shrink-0" />
              <span>Domain Does Not Exist (NXDOMAIN)</span>
            </div>
          )}
        </div>
      </div>

      {/* Primary Verdict Hero Banner - Ergonomic & Responsive */}
      <div className={`p-5 sm:p-6 rounded-xl border ${bannerTheme} space-y-4 shadow-lg`}>
        <div className="grid grid-cols-1 md:grid-cols-12 gap-5 items-center">
          {/* Main Verdict & Subtitle */}
          <div className="md:col-span-6 flex items-start gap-3.5">
            <div className={`p-2.5 rounded-xl border ${iconTheme} shrink-0 mt-0.5`}>
              {isHighRisk ? (
                <ShieldAlert className="w-7 h-7" />
              ) : isSuspicious ? (
                <AlertTriangle className="w-7 h-7" />
              ) : (
                <ShieldCheck className="w-7 h-7" />
              )}
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-[#F5F5F5]">
                  {verdictHeadline}
                </h2>
                <StatusBadge type="risk" value={result.risk_level} size="sm" />
              </div>
              <p className="text-xs text-[#A3A3A3] leading-relaxed">
                {verdictSubtext}
              </p>
            </div>
          </div>

          {/* Risk Gauge Bar */}
          <div className="md:col-span-3 bg-[#050505]/80 p-3.5 rounded-xl border border-[#242424] space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#A3A3A3] flex items-center gap-1 text-[11px]">
                <Cpu className="w-3 h-3 text-[#39FF88]" />
                Phishing Risk Score
              </span>
              <span className={`font-mono font-bold text-sm ${mlScoreColor}`}>
                {assessedMlPercent}/100
              </span>
            </div>
            <div className="w-full bg-[#181818] rounded-full h-2 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${mlGaugeColor}`}
                style={{ width: `${Math.min(100, Math.max(3, Number(assessedMlPercent)))}%` }}
              />
            </div>
            <p className="text-[10px] text-[#737373] leading-tight">
              Calculated structural probability calibrated with verified domain authority.
            </p>
          </div>

          {/* Plain Verdict Badge */}
          <div className="md:col-span-3 bg-[#050505]/80 p-3.5 rounded-xl border border-[#242424] space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#A3A3A3] flex items-center gap-1 text-[11px]">
                <Shield className="w-3 h-3 text-[#FFD54A]" />
                Our Verdict
              </span>
              <span className="font-semibold text-xs text-[#F5F5F5]">
                {isHighRisk ? 'Likely Phishing' : isSuspicious ? 'Suspicious' : 'Likely Safe'}
              </span>
            </div>
            <div className="flex items-center gap-2 pt-0.5">
              <StatusBadge type="class" value={result.predicted_class} size="sm" />
              {hasThreatMatch && (
                <span className="text-[10px] uppercase font-bold text-[#FF525C] px-1.5 py-0.5 rounded bg-[#1A0D0F] border border-[#FF525C]/30">
                  Blocklisted
                </span>
              )}
            </div>
            <p className="text-[10px] text-[#737373] leading-tight">
              Multi-layered assessment: lexical ML + domain authority + threat feeds.
            </p>
          </div>
        </div>

        {/* Clear Explanation Callout */}
        <div className="p-3 rounded-lg bg-[#050505]/60 border border-[#292929]/50 text-xs text-[#F5F5F5] leading-relaxed flex items-start gap-2">
          <Info className="w-4 h-4 text-[#39FF88] shrink-0 mt-0.5" />
          <span>
            <strong className="text-[#39FF88]">What this means:</strong> {result.combined_interpretation}
          </span>
        </div>
      </div>

      {/* Balanced 12-Column Content Grid: No Dead Vertical Space */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column (Primary Findings & Guidance, 7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Card 1: What Looks Suspicious */}
          <div className="p-4 sm:p-5 rounded-xl bg-[#111111] border border-[#292929] space-y-3">
            <div className="flex items-center justify-between pb-2.5 border-b border-[#1C1C1C]">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#FF525C]" />
                <span>What Looks Suspicious</span>
              </h3>
              <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                uniqueWarnings.length > 0
                  ? 'bg-[#1F1214] text-[#FF525C] border border-[#FF525C]/30'
                  : 'bg-[#0E1A12] text-[#39FF88] border border-[#39FF88]/30'
              }`}>
                {uniqueWarnings.length} Warning Sign{uniqueWarnings.length === 1 ? '' : 's'}
              </span>
            </div>

            {uniqueWarnings.length > 0 ? (
              <ul className="space-y-2">
                {uniqueWarnings.map((warningText, idx) => (
                  <li
                    key={idx}
                    className={`p-2.5 rounded-lg border text-xs text-[#F5F5F5] flex items-start gap-2.5 ${
                      isVerifiedDomain
                        ? 'bg-[#0E1A12] border-[#39FF88]/20'
                        : 'bg-[#181010] border-[#FF525C]/20'
                    }`}
                  >
                    {isVerifiedDomain ? (
                      <Info className="w-3.5 h-3.5 text-[#39FF88] shrink-0 mt-0.5" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-[#FF525C] shrink-0 mt-0.5" />
                    )}
                    <span className="leading-relaxed">{warningText}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="p-4 rounded-lg bg-[#0E1A12] border border-[#39FF88]/20 text-center space-y-1.5">
                <CheckCircle2 className="w-5 h-5 text-[#39FF88] mx-auto" />
                <p className="text-xs text-[#F5F5F5] font-medium">No Major Warning Signs Found</p>
                <p className="text-[11px] text-[#A3A3A3]">
                  This address does not show common deception patterns. Still remain alert if prompted for credentials.
                </p>
              </div>
            )}
          </div>

          {/* Card 2: Actionable Protective Guidance */}
          {result.recommended_precautions && result.recommended_precautions.length > 0 && (
            <div className="p-4 sm:p-5 rounded-xl bg-[#0E1210] border border-[#39FF88]/20 space-y-2.5">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-[#39FF88] flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" />
                <span>Actionable Protective Guidance</span>
              </span>
              <ul className="space-y-1.5">
                {result.recommended_precautions.map((precaution, idx) => (
                  <li key={idx} className="text-xs text-[#D4D4D4] flex items-start gap-2 leading-relaxed">
                    <span className="text-[#39FF88] font-bold mt-0.5">&bull;</span>
                    <span>{precaution}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Card 3: Domain & Infrastructure Indicators */}
          <div className="p-4 rounded-xl bg-[#111111] border border-[#292929] space-y-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[#737373]">
              Infrastructure Verification
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
              <div className="p-2.5 rounded-lg bg-[#0A0A0A] border border-[#202020] space-y-1">
                <span className="text-[10px] text-[#737373] flex items-center gap-1">
                  <Globe className="w-3 h-3 text-[#39FF88]" />
                  DNS Reachability
                </span>
                <p className={`font-semibold text-[11px] ${isNxDomain ? 'text-[#FF525C]' : 'text-[#39FF88]'}`}>
                  {isNxDomain ? 'Non-Existent (NXDOMAIN)' : 'Active in Public DNS'}
                </p>
              </div>

              <div className="p-2.5 rounded-lg bg-[#0A0A0A] border border-[#202020] space-y-1">
                <span className="text-[10px] text-[#737373] flex items-center gap-1">
                  <Lock className="w-3 h-3 text-[#39FF88]" />
                  Protocol Security
                </span>
                <p className="font-semibold text-[11px] text-[#F5F5F5]">
                  {result.submitted_url.startsWith('https://') ? 'HTTPS Encrypted' : 'Insecure HTTP'}
                </p>
              </div>

              <div className="col-span-2 sm:col-span-1 p-2.5 rounded-lg bg-[#0A0A0A] border border-[#202020] space-y-1">
                <span className="text-[10px] text-[#737373] flex items-center gap-1">
                  <Shield className="w-3 h-3 text-[#FFD54A]" />
                  Domain Authority
                </span>
                <p className="font-semibold text-[11px] text-[#F5F5F5] truncate">
                  {isVerifiedDomain ? 'Verified Organization' : 'Standard Web Domain'}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (Threat Feeds & Blocklists, 5 Cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="p-4 sm:p-5 rounded-xl bg-[#111111] border border-[#292929] space-y-3">
            <div className="flex items-center justify-between pb-2.5 border-b border-[#1C1C1C]">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
                <Database className="w-4 h-4 text-[#FFD54A]" />
                <span>Known Threat Feeds</span>
              </h3>
              <span className="text-[10px] text-[#737373]">5 Engines Checked</span>
            </div>

            <div className="space-y-2">
              {([
                ['openphish', 'OpenPhish'],
                ['phishing_database', 'Phishing.Database'],
                ['phish_destroy', 'PhishDestroy'],
                ['cert_pl', 'CERT-PL Warning List'],
                ['google_safe_browsing', 'Google Safe Browsing v4'],
              ] as const).map(([key, label]) => {
                const provider = result.threat_intelligence[key];
                return provider ? (
                  <React.Fragment key={key}>
                    {renderProviderState(label, provider)}
                  </React.Fragment>
                ) : null;
              })}
            </div>

            {/* Compact Security Clarification Notice */}
            <div className="p-2.5 rounded-lg bg-[#0A0A0A] border border-[#242424] space-y-1">
              <div className="flex items-center gap-1.5 text-[10px] font-semibold text-[#FFD54A]">
                <Info className="w-3 h-3 shrink-0" />
                <span>Blocklist Clarification</span>
              </div>
              <p className="text-[10px] text-[#808080] leading-snug">
                Threat databases list links that have already been reported. Newly created zero-day phishing sites may not appear in blocklists immediately.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
