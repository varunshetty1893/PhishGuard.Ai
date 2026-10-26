import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Cpu,
  Terminal,
  Clock,
  ArrowRight,
  Database,
  RefreshCw,
  BarChart2,
  PieChart as PieIcon,
  AlertTriangle,
  Shield
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  LineChart,
  Line,
  CartesianGrid
} from 'recharts';
import { api } from '../services/api';
import type { AnalyticsData, ScanListItem } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const DashboardPage: React.FC = () => {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [recentScans, setRecentScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');

  const fetchData = async () => {
    try {
      setError('');
      const [analyticsData, scanListData] = await Promise.all([
        api.getAnalytics(),
        api.getScans({ page: 1, page_size: 5 })
      ]);
      setAnalytics(analyticsData);
      setRecentScans(scanListData.items);
    } catch (err: any) {
      setError(err.message || 'Failed to load live analytics.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-20 text-center space-y-4">
        <div className="inline-block w-8 h-8 border-2 border-[#39FF88] border-t-transparent rounded-full animate-spin" />
        <p className="text-sm text-[#A3A3A3]">Computing live analytics from SQLite database...</p>
      </div>
    );
  }

  if (error || !analytics) {
    return (
      <div className="max-w-xl mx-auto px-4 py-20 text-center space-y-6">
        <div className="w-12 h-12 rounded-full bg-[#181010] border border-[#FF525C] flex items-center justify-center mx-auto text-[#FF525C]">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <h2 className="text-xl font-bold text-[#F5F5F5]">Analytics Unavailable</h2>
        <p className="text-xs text-[#A3A3A3]">{error || 'Could not query backend database.'}</p>
        <button
          onClick={fetchData}
          className="px-4 py-2 rounded bg-[#39FF88] text-[#050505] font-semibold text-xs uppercase"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const isEmpty = analytics.total_scans === 0;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-[#292929]">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-[#111111] border border-[#39FF88]/40 text-xs font-medium text-[#39FF88] mb-2">
            <Activity className="w-3.5 h-3.5 text-[#39FF88]" />
            <span>Real-Time Security Intelligence</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#F5F5F5]">
            Threat Analytics Dashboard
          </h1>
          <p className="text-xs text-[#A3A3A3] mt-1">
            Aggregated metrics derived dynamically from SQLite persistence. Zero synthetic counts.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="px-3 py-2 rounded bg-[#111111] hover:bg-[#181818] border border-[#292929] hover:border-[#39FF88] text-xs text-[#F5F5F5] flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-[#39FF88]' : ''}`} />
            <span>Refresh</span>
          </button>
          <Link
            to="/scanner"
            className="px-4 py-2 rounded bg-[#39FF88] hover:bg-[#16C96A] text-[#050505] font-semibold text-xs uppercase tracking-wider flex items-center gap-2 transition-colors"
          >
            <Terminal className="w-3.5 h-3.5 text-[#050505]" />
            <span>Scan URL</span>
          </Link>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* Total Scanned */}
        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">
            Total Scanned
          </span>
          <div className="text-2xl font-bold font-mono text-[#F5F5F5]">
            {analytics.total_scans.toLocaleString()}
          </div>
          <div className="text-[10px] text-[#A3A3A3] flex items-center gap-1">
            <Database className="w-3 h-3 text-[#39FF88]" />
            <span>Database Records</span>
          </div>
        </div>

        {/* Phishing Detected */}
        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#FF525C]">
            Phishing URLs
          </span>
          <div className="text-2xl font-bold font-mono text-[#FF525C]">
            {analytics.phishing_count.toLocaleString()}
          </div>
          <div className="text-[10px] text-[#A3A3A3]">
            {analytics.total_scans > 0
              ? `${((analytics.phishing_count / analytics.total_scans) * 100).toFixed(1)}% of total`
              : '0.0%'}
          </div>
        </div>

        {/* Legitimate URLs */}
        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#39FF88]">
            Legitimate URLs
          </span>
          <div className="text-2xl font-bold font-mono text-[#39FF88]">
            {analytics.legitimate_count.toLocaleString()}
          </div>
          <div className="text-[10px] text-[#A3A3A3]">
            {analytics.total_scans > 0
              ? `${((analytics.legitimate_count / analytics.total_scans) * 100).toFixed(1)}% of total`
              : '0.0%'}
          </div>
        </div>

        {/* High Risk Volume */}
        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#FF525C]">
            High-Risk Tiers
          </span>
          <div className="text-2xl font-bold font-mono text-[#FF525C]">
            {analytics.high_risk_count.toLocaleString()}
          </div>
          <div className="text-[10px] text-[#A3A3A3]">Severe anomaly score</div>
        </div>

        {/* Threat Intel Matches */}
        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#FFD54A]">
            Threat Intel Hits
          </span>
          <div className="text-2xl font-bold font-mono text-[#FFD54A]">
            {analytics.threat_intel_matches.toLocaleString()}
          </div>
          <div className="text-[10px] text-[#A3A3A3]">Safe Browsing / URLhaus</div>
        </div>

        {/* Provider Failures */}
        <div className="p-4 rounded bg-[#111111] border border-[#292929] space-y-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#A3A3A3]">
            Check Failures
          </span>
          <div className="text-2xl font-bold font-mono text-[#A3A3A3]">
            {analytics.threat_intel_failures.toLocaleString()}
          </div>
          <div className="text-[10px] text-[#737373]">Network timeouts/unavailable</div>
        </div>
      </div>

      {/* Empty State Guard if No Scans Exist */}
      {isEmpty ? (
        <div className="p-12 rounded bg-[#111111] border border-[#292929] text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-[#181818] border border-[#292929] flex items-center justify-center mx-auto text-[#39FF88]">
            <Terminal className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-[#F5F5F5]">No Scans In Database Yet</h3>
          <p className="text-xs text-[#A3A3A3] max-w-md mx-auto">
            Scan your first URL to populate real-time metrics, risk distribution charts, and temporal trends.
          </p>
          <Link
            to="/scanner"
            className="inline-flex items-center gap-2 px-4 py-2 rounded bg-[#39FF88] text-[#050505] font-semibold text-xs uppercase"
          >
            <span>Scan First URL</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      ) : (
        <>
          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Classification Pie */}
            <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
                  <PieIcon className="w-4 h-4 text-[#39FF88]" />
                  Classification Distribution
                </h3>
              </div>

              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={analytics.classification_distribution}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={85}
                      paddingAngle={4}
                    >
                      {analytics.classification_distribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} stroke="#111111" strokeWidth={2} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0A0A0A', borderColor: '#292929', color: '#F5F5F5', fontSize: '12px' }}
                    />
                    <Legend wrapperStyle={{ fontSize: '11px', color: '#A3A3A3' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Risk Tier Bar */}
            <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
                  <BarChart2 className="w-4 h-4 text-[#FFD54A]" />
                  Risk Category Breakdown
                </h3>
              </div>

              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={analytics.risk_distribution}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#181818" />
                    <XAxis dataKey="name" stroke="#737373" fontSize={11} />
                    <YAxis stroke="#737373" fontSize={11} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0A0A0A', borderColor: '#292929', color: '#F5F5F5', fontSize: '12px' }}
                    />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {analytics.risk_distribution.map((entry, index) => (
                        <Cell key={`bar-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Temporal Activity Line */}
            <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#39FF88]" />
                  Scan Activity (Last 7 Days)
                </h3>
              </div>

              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={analytics.scans_over_time}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#181818" />
                    <XAxis dataKey="date" stroke="#737373" fontSize={10} />
                    <YAxis stroke="#737373" fontSize={11} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0A0A0A', borderColor: '#292929', color: '#F5F5F5', fontSize: '12px' }}
                    />
                    <Line type="monotone" dataKey="scans" name="Total Scans" stroke="#39FF88" strokeWidth={2} dot={{ fill: '#39FF88', r: 3 }} />
                    <Line type="monotone" dataKey="phishing" name="Phishing Hits" stroke="#FF525C" strokeWidth={2} dot={{ fill: '#FF525C', r: 3 }} />
                    <Legend wrapperStyle={{ fontSize: '11px', color: '#A3A3A3' }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Recent Scans Table */}
          <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F5] flex items-center gap-2">
                  <Clock className="w-4 h-4 text-[#39FF88]" />
                  Recent Scan Activity
                </h3>
                <p className="text-[11px] text-[#A3A3A3] mt-0.5">Most recent evaluated URL records</p>
              </div>
              <Link to="/history" className="text-xs text-[#39FF88] hover:underline flex items-center gap-1">
                <span>View Full History</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#181818] text-[#737373]">
                    <th className="py-2.5 px-3">Target URL</th>
                    <th className="py-2.5 px-3">Classification</th>
                    <th className="py-2.5 px-3">Risk Tier</th>
                    <th className="py-2.5 px-3">Confidence</th>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#181818]">
                  {recentScans.map((scan) => (
                    <tr key={scan.scan_id} className="hover:bg-[#181818]/50 transition-colors">
                      <td className="py-3 px-3 font-mono text-[#F5F5F5] max-w-[280px] truncate" title={scan.submitted_url}>
                        {scan.submitted_url}
                      </td>
                      <td className="py-3 px-3">
                        <StatusBadge type="class" value={scan.predicted_class} size="sm" />
                      </td>
                      <td className="py-3 px-3">
                        <StatusBadge type="risk" value={scan.risk_level} size="sm" />
                      </td>
                      <td className="py-3 px-3 font-mono text-[#A3A3A3]">
                        {scan.model_score !== null ? `${(scan.model_score * 100).toFixed(1)}%` : 'N/A'}
                      </td>
                      <td className="py-3 px-3 text-[#737373]">
                        {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <Link
                          to={`/results/${scan.scan_id}`}
                          className="text-[#39FF88] hover:underline text-xs"
                        >
                          View Report
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* Model & Providers Status Card */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-5 rounded bg-[#0A0A0A] border border-[#292929] space-y-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#39FF88] flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5" />
            Active ML Engine
          </span>
          <div className="text-sm font-semibold text-[#F5F5F5]">
            {analytics.model_status.algorithm}
          </div>
          <p className="text-xs text-[#A3A3A3]">
            Semantic version v{analytics.model_status.version} • Status: <span className="text-[#39FF88]">{analytics.model_status.status}</span>
          </p>
        </div>

        <div className="p-5 rounded bg-[#0A0A0A] border border-[#292929] space-y-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#FFD54A] flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5" />
            Threat Intelligence Adapters
          </span>
          <div className="text-xs text-[#F5F5F5] space-y-1">
            <div className="flex justify-between">
              <span className="text-[#A3A3A3]">Google Safe Browsing:</span>
              <span className={analytics.threat_provider_status.google_safe_browsing === 'Active' ? 'text-[#39FF88]' : 'text-[#FFD54A]'}>
                {analytics.threat_provider_status.google_safe_browsing}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#A3A3A3]">abuse.ch URLhaus:</span>
              <span className={analytics.threat_provider_status.urlhaus.includes('Active') ? 'text-[#39FF88]' : 'text-[#FFD54A]'}>
                {analytics.threat_provider_status.urlhaus}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
