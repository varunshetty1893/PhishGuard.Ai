import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, HelpCircle, CheckCircle, XCircle } from 'lucide-react';

interface StatusBadgeProps {
  type: 'class' | 'risk' | 'threat';
  value: string;
  size?: 'sm' | 'md' | 'lg';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ type, value, size = 'md' }) => {
  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3.5 py-1.5 gap-2'
  }[size];

  // Colors strictly limited to:
  // Green: #39FF88
  // Yellow: #FFD54A
  // Red: #FF525C
  // Neutral: #A3A3A3 / #292929

  if (type === 'class') {
    const isPhish = value.toLowerCase() === 'phishing';
    return (
      <span
        className={`inline-flex items-center font-medium rounded border ${sizeClasses} ${
          isPhish
            ? 'bg-[#181010] text-[#FF525C] border-[#FF525C]/40'
            : 'bg-[#0E1A12] text-[#39FF88] border-[#39FF88]/40'
        }`}
      >
        {isPhish ? <ShieldAlert className="w-3.5 h-3.5" /> : <ShieldCheck className="w-3.5 h-3.5" />}
        <span>{value}</span>
      </span>
    );
  }

  if (type === 'risk') {
    const v = value.toLowerCase();
    if (v.includes('high')) {
      return (
        <span className={`inline-flex items-center font-medium rounded border bg-[#1A0D0F] text-[#FF525C] border-[#FF525C]/40 ${sizeClasses}`}>
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Likely Phishing</span>
        </span>
      );
    }
    if (v.includes('suspicious')) {
      return (
        <span className={`inline-flex items-center font-medium rounded border bg-[#1A170A] text-[#FFD54A] border-[#FFD54A]/40 ${sizeClasses}`}>
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>Suspicious</span>
        </span>
      );
    }
    return (
      <span className={`inline-flex items-center font-medium rounded border bg-[#0E1A12] text-[#39FF88] border-[#39FF88]/40 ${sizeClasses}`}>
        <ShieldCheck className="w-3.5 h-3.5" />
        <span>Likely Safe</span>
      </span>
    );
  }

  // Threat provider status
  const v = value.toLowerCase();
  if (v.includes('threat') || v.includes('match') && !v.includes('no match')) {
    return (
      <span className={`inline-flex items-center font-medium rounded border bg-[#1A0D0F] text-[#FF525C] border-[#FF525C]/40 ${sizeClasses}`}>
        <XCircle className="w-3.5 h-3.5" />
        <span>Threat Reported</span>
      </span>
    );
  }
  if (v.includes('no match')) {
    return (
      <span className={`inline-flex items-center font-medium rounded border bg-[#0E1A12] text-[#39FF88] border-[#39FF88]/40 ${sizeClasses}`}>
        <CheckCircle className="w-3.5 h-3.5" />
        <span>No Known Threat Found</span>
      </span>
    );
  }
  if (v.includes('not configured')) {
    return (
      <span className={`inline-flex items-center font-medium rounded border bg-[#181818] text-[#A3A3A3] border-[#292929] ${sizeClasses}`}>
        <HelpCircle className="w-3.5 h-3.5" />
        <span>Not Set Up Yet</span>
      </span>
    );
  }
  return (
    <span className={`inline-flex items-center font-medium rounded border bg-[#1A170A] text-[#FFD54A] border-[#FFD54A]/40 ${sizeClasses}`}>
      <AlertTriangle className="w-3.5 h-3.5" />
      <span>{value}</span>
    </span>
  );
};
