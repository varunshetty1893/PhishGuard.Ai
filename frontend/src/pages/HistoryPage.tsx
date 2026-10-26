import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  History,
  Search,
  Download,
  Trash2,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  RotateCcw,
  Terminal
} from 'lucide-react';
import { api } from '../services/api';
import type { ScanListResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const HistoryPage: React.FC = () => {
  const [data, setData] = useState<ScanListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Filter States
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [predictedClass, setPredictedClass] = useState('All');
  const [riskLevel, setRiskLevel] = useState('All');
  const [threatStatus, setThreatStatus] = useState('All');

  // Confirmation Modals
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [showClearModal, setShowClearModal] = useState(false);
  const [actionMessage, setActionMessage] = useState('');

  const fetchHistory = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await api.getScans({
        page,
        page_size: 10,
        search: search.trim() || undefined,
        predicted_class: predictedClass,
        risk_level: riskLevel,
        threat_status: threatStatus
      });
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve scan history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page, predictedClass, riskLevel, threatStatus]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchHistory();
  };

  const handleDeleteOne = async (scanId: string) => {
    try {
      await api.deleteScan(scanId);
      setDeletingId(null);
      setActionMessage('Record deleted.');
      setTimeout(() => setActionMessage(''), 2500);
      fetchHistory();
    } catch (err: any) {
      setError(err.message || 'Failed to delete record.');
    }
  };

  const handleClearAll = async () => {
    try {
      await api.clearAllScans();
      setShowClearModal(false);
      setActionMessage('All scan history cleared.');
      setTimeout(() => setActionMessage(''), 2500);
      setPage(1);
      fetchHistory();
    } catch (err: any) {
      setError(err.message || 'Failed to clear history.');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      {/* Page Title & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-[#292929]">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-[#111111] border border-[#39FF88]/40 text-xs font-medium text-[#39FF88] mb-2">
            <History className="w-3.5 h-3.5 text-[#39FF88]" />
            <span>SQLite Audit Records</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#F5F5F5]">
            Scan History &amp; Audit Logs
          </h1>
          <p className="text-xs text-[#A3A3A3] mt-1">
            Persisted history of inspected URLs, classification outcomes, and threat intelligence matches.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <a
            href={api.getExportCsvUrl()}
            download="phishguard_scan_history.csv"
            className="px-3 py-2 rounded bg-[#111111] hover:bg-[#181818] border border-[#292929] hover:border-[#39FF88] text-xs text-[#F5F5F5] flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-[#39FF88]" />
            <span>Export CSV</span>
          </a>

          <button
            onClick={() => setShowClearModal(true)}
            disabled={!data || data.total_records === 0}
            className="px-3 py-2 rounded bg-[#181010] hover:bg-[#251515] border border-[#FF525C]/30 hover:border-[#FF525C] text-xs text-[#FF525C] flex items-center gap-1.5 transition-colors disabled:opacity-40"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded bg-[#181010] border border-[#FF525C]/40 text-xs text-[#FF525C] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {actionMessage && (
        <div className="p-3 rounded bg-[#0E1A12] border border-[#39FF88]/40 text-xs text-[#39FF88] flex items-center gap-2">
          <span>{actionMessage}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="p-5 rounded bg-[#111111] border border-[#292929] space-y-4">
        <form onSubmit={handleSearchSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-grow">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search className="w-4 h-4 text-[#737373]" />
            </div>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by URL substring (e.g. paypal, apple, xyz)..."
              className="w-full pl-9 pr-4 py-2 rounded bg-[#0A0A0A] border border-[#292929] text-xs text-[#F5F5F5] placeholder-[#737373] focus:border-[#39FF88]"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded bg-[#181818] hover:bg-[#202020] border border-[#292929] hover:border-[#39FF88] text-xs text-[#F5F5F5] font-medium"
          >
            Search
          </button>
        </form>

        {/* Dropdown Filters */}
        <div className="flex flex-wrap items-center gap-4 text-xs text-[#A3A3A3] pt-2 border-t border-[#181818]">
          <div className="flex items-center gap-2">
            <span>Classification:</span>
            <select
              value={predictedClass}
              onChange={(e) => {
                setPredictedClass(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1 rounded bg-[#0A0A0A] border border-[#292929] text-xs text-[#F5F5F5] focus:border-[#39FF88]"
            >
              <option value="All">All Classes</option>
              <option value="Legitimate">Legitimate</option>
              <option value="Phishing">Phishing</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span>Risk Tier:</span>
            <select
              value={riskLevel}
              onChange={(e) => {
                setRiskLevel(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1 rounded bg-[#0A0A0A] border border-[#292929] text-xs text-[#F5F5F5] focus:border-[#39FF88]"
            >
              <option value="All">All Risk Tiers</option>
              <option value="Low Risk">Low Risk</option>
              <option value="Suspicious">Suspicious</option>
              <option value="High Risk">High Risk</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span>Threat Hits:</span>
            <select
              value={threatStatus}
              onChange={(e) => {
                setThreatStatus(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1 rounded bg-[#0A0A0A] border border-[#292929] text-xs text-[#F5F5F5] focus:border-[#39FF88]"
            >
              <option value="All">All Statuses</option>
              <option value="Threat Found">Threat Reported</option>
              <option value="No Match">No Match</option>
            </select>
          </div>

          {(search || predictedClass !== 'All' || riskLevel !== 'All' || threatStatus !== 'All') && (
            <button
              onClick={() => {
                setSearch('');
                setPredictedClass('All');
                setRiskLevel('All');
                setThreatStatus('All');
                setPage(1);
              }}
              className="text-[#39FF88] hover:underline text-xs flex items-center gap-1"
            >
              <RotateCcw className="w-3 h-3" />
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Table Section */}
      <div className="p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
        {loading ? (
          <div className="py-16 text-center space-y-3">
            <div className="inline-block w-6 h-6 border-2 border-[#39FF88] border-t-transparent rounded-full animate-spin" />
            <p className="text-xs text-[#A3A3A3]">Loading records...</p>
          </div>
        ) : !data || data.items.length === 0 ? (
          <div className="py-16 text-center space-y-4">
            <div className="w-10 h-10 rounded-full bg-[#181818] border border-[#292929] flex items-center justify-center mx-auto text-[#A3A3A3]">
              <History className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-[#F5F5F5]">No Scan Records Found</h3>
            <p className="text-xs text-[#A3A3A3] max-w-sm mx-auto">
              No matching records correspond to your query filters or the database is currently empty.
            </p>
            <Link
              to="/scanner"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#39FF88] text-[#050505] font-semibold text-xs"
            >
              <Terminal className="w-3.5 h-3.5" />
              Scan a URL Now
            </Link>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#181818] text-[#737373]">
                    <th className="py-2.5 px-3">Target URL</th>
                    <th className="py-2.5 px-3">ML Prediction</th>
                    <th className="py-2.5 px-3">Risk Tier</th>
                    <th className="py-2.5 px-3">Probability</th>
                    <th className="py-2.5 px-3">Threat Hit</th>
                    <th className="py-2.5 px-3">Timestamp (UTC)</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#181818]">
                  {data.items.map((scan) => (
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
                      <td className="py-3 px-3">
                        {scan.threat_intel_match ? (
                          <span className="text-[#FF525C] font-semibold">Matched</span>
                        ) : (
                          <span className="text-[#737373]">None</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-[#737373]">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-3 text-right space-x-2">
                        <Link
                          to={`/results/${scan.scan_id}`}
                          className="text-[#39FF88] hover:underline"
                        >
                          Report
                        </Link>
                        <button
                          onClick={() => setDeletingId(scan.scan_id)}
                          className="text-[#FF525C] hover:underline ml-2"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-[#181818] text-xs text-[#A3A3A3]">
              <span>
                Showing {((data.page - 1) * data.page_size) + 1} to {Math.min(data.page * data.page_size, data.total_records)} of {data.total_records} records
              </span>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(p - 1, 1))}
                  disabled={data.page <= 1}
                  className="px-2.5 py-1 rounded bg-[#0A0A0A] border border-[#292929] text-xs text-[#F5F5F5] disabled:opacity-40 flex items-center gap-1"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  Prev
                </button>
                <span className="px-2 text-xs font-mono text-[#F5F5F5]">
                  {data.page} / {data.total_pages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(p + 1, data.total_pages))}
                  disabled={data.page >= data.total_pages}
                  className="px-2.5 py-1 rounded bg-[#0A0A0A] border border-[#292929] text-xs text-[#F5F5F5] disabled:opacity-40 flex items-center gap-1"
                >
                  Next
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Delete Single Confirmation Modal */}
      {deletingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="max-w-md w-full p-6 rounded bg-[#111111] border border-[#292929] space-y-4">
            <div className="flex items-center gap-2 text-[#FF525C]">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="font-bold text-sm text-[#F5F5F5]">Confirm Record Deletion</h3>
            </div>
            <p className="text-xs text-[#A3A3A3]">
              Are you sure you want to delete scan record <span className="font-mono text-[#F5F5F5]">{deletingId}</span>? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setDeletingId(null)}
                className="px-3 py-1.5 rounded bg-[#181818] border border-[#292929] text-xs text-[#F5F5F5]"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteOne(deletingId)}
                className="px-3 py-1.5 rounded bg-[#FF525C] text-[#050505] font-bold text-xs"
              >
                Delete Record
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Clear All History Confirmation Modal */}
      {showClearModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="max-w-md w-full p-6 rounded bg-[#111111] border border-[#FF525C]/50 space-y-4">
            <div className="flex items-center gap-2 text-[#FF525C]">
              <Trash2 className="w-5 h-5" />
              <h3 className="font-bold text-sm text-[#F5F5F5]">Clear All Scan Records?</h3>
            </div>
            <p className="text-xs text-[#A3A3A3]">
              This will permanently delete all scan records and associated threat-intelligence logs from the SQLite database.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowClearModal(false)}
                className="px-3 py-1.5 rounded bg-[#181818] border border-[#292929] text-xs text-[#F5F5F5]"
              >
                Cancel
              </button>
              <button
                onClick={handleClearAll}
                className="px-3 py-1.5 rounded bg-[#FF525C] text-[#050505] font-bold text-xs"
              >
                Confirm &amp; Clear All
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
