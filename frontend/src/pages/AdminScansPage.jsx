import React, { useEffect, useState, useCallback } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import {
    Database, AlertTriangle, ArrowLeft, Activity,
    Search, Trash2, Download, ChevronLeft, ChevronRight, RefreshCw
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const SCAN_TYPES = ['web', 'network', 'network_ext', 'network_int', 'sast', 'dast', 'dependencies', 'apache', 'server_ext', 'server_int'];
const RISK_LEVELS = ['critical', 'high', 'medium', 'low'];

const AdminScansPage = () => {
    const { user } = useAuth();
    const [scans, setScans]         = useState([]);
    const [loading, setLoading]     = useState(true);
    const [error, setError]         = useState('');
    const [total, setTotal]         = useState(0);
    const [page, setPage]           = useState(1);
    const PER_PAGE = 25;

    // Filters
    const [search, setSearch]       = useState('');
    const [scanType, setScanType]   = useState('');
    const [riskLevel, setRiskLevel] = useState('');
    const [dateFrom, setDateFrom]   = useState('');
    const [dateTo, setDateTo]       = useState('');

    // Bulk selection
    const [selected, setSelected]   = useState(new Set());
    const [deleting, setDeleting]   = useState(false);

    const fetchScans = useCallback(async (p = page) => {
        setLoading(true);
        setSelected(new Set());
        try {
            const params = { page: p, per_page: PER_PAGE };
            if (scanType)  params.type       = scanType;
            if (riskLevel) params.risk_level  = riskLevel;
            if (dateFrom)  params.date_from   = dateFrom;
            if (dateTo)    params.date_to     = dateTo;
            const { data } = await axios.get('/api/admin/scans', { params, withCredentials: true });
            setScans(data.reports || []);
            setTotal(data.total  || 0);
            setError('');
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load scan records');
        } finally {
            setLoading(false);
        }
    }, [page, scanType, riskLevel, dateFrom, dateTo]);

    useEffect(() => {
        if (user?.role === 'admin') fetchScans(page);
    }, [user, page]);

    const applyFilters = () => { setPage(1); fetchScans(1); };

    const handleDeleteScan = async (token) => {
        if (!window.confirm('Delete this scan record permanently?')) return;
        try {
            await axios.delete(`/api/reports/${token}`, { withCredentials: true });
            fetchScans(page);
        } catch (err) {
            alert(err.response?.data?.error || 'Failed to delete scan');
        }
    };

    const handleBulkDelete = async () => {
        if (selected.size === 0) return;
        if (!window.confirm(`Delete ${selected.size} scan records permanently?`)) return;
        setDeleting(true);
        try {
            await Promise.all([...selected].map(token =>
                axios.delete(`/api/reports/${token}`, { withCredentials: true }).catch(() => {})
            ));
            fetchScans(page);
        } finally {
            setDeleting(false);
        }
    };

    const exportCsv = () => {
        if (!scans.length) return;
        const rows = [
            ['Token', 'Target', 'Scan Type', 'Operator', 'Findings', 'Risk Score', 'Date'],
            ...scans.map(s => [
                s.token, s.target, s.scan_type, s.username || s.user_id,
                s.vuln_count, s.risk_score, s.stored_at
            ])
        ];
        const csv = rows.map(r => r.map(v => `"${(v ?? '').toString().replace(/"/g, '""')}"`).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = 'scans_export.csv'; a.click();
        URL.revokeObjectURL(url);
    };

    const toggleSelect = (token) => {
        setSelected(prev => {
            const next = new Set(prev);
            next.has(token) ? next.delete(token) : next.add(token);
            return next;
        });
    };

    const toggleAll = () => {
        if (selected.size === scans.length) setSelected(new Set());
        else setSelected(new Set(scans.map(s => s.token)));
    };

    const filtered = scans.filter(s => {
        const q = search.toLowerCase();
        return !q || (s.target || '').toLowerCase().includes(q) || (s.token || '').toLowerCase().includes(q) || (s.username || '').toLowerCase().includes(q);
    });

    const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

    if (user?.role !== 'admin') return (
        <div className="h-64 flex items-center justify-center">
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-6 rounded-xl flex items-center gap-3">
                <AlertTriangle className="w-6 h-6" />
                <div><h3 className="font-bold">Access Denied</h3><p className="text-sm">Administrator privileges required.</p></div>
            </div>
        </div>
    );

    return (
        <div className="animate-in fade-in duration-500">
            <div className="mb-6">
                <Link to="/admin" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Admin Panel
                </Link>
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                            <Database className="w-8 h-8 text-primary-500" /> Global Scan Records
                        </h1>
                        <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">View all scans executed across the platform by any user.</p>
                    </div>
                    <div className="flex items-center gap-2">
                        <button onClick={exportCsv} className="px-3 py-2 text-xs font-semibold text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors flex items-center gap-1.5">
                            <Download className="w-3.5 h-3.5" /> Export CSV
                        </button>
                        {selected.size > 0 && (
                            <button onClick={handleBulkDelete} disabled={deleting} className="px-3 py-2 text-xs font-semibold text-red-600 dark:text-red-400 border border-red-300 dark:border-red-500/30 rounded-lg hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors flex items-center gap-1.5 disabled:opacity-50">
                                <Trash2 className="w-3.5 h-3.5" /> Delete ({selected.size})
                            </button>
                        )}
                    </div>
                </div>
            </div>

            {/* Filter bar */}
            <div className="mb-4 flex flex-wrap items-end gap-3 p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-sm">
                <div className="relative flex-1 min-w-[160px]">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input type="text" placeholder="Search target or token..." value={search} onChange={e => setSearch(e.target.value)}
                        className="pl-9 pr-4 py-2 border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 w-full" />
                </div>
                <select value={scanType} onChange={e => setScanType(e.target.value)}
                    className="px-3 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500">
                    <option value="">All Types</option>
                    {SCAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <select value={riskLevel} onChange={e => setRiskLevel(e.target.value)}
                    className="px-3 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500">
                    <option value="">All Risk Levels</option>
                    {RISK_LEVELS.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
                <div className="flex items-center gap-2">
                    <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
                        className="px-3 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500" />
                    <span className="text-xs text-slate-500">→</span>
                    <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
                        className="px-3 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500" />
                </div>
                <button onClick={applyFilters}
                    className="px-4 py-2 text-sm font-semibold text-white bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors flex items-center gap-1.5">
                    <RefreshCw className="w-3.5 h-3.5" /> Apply
                </button>
            </div>

            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                {loading ? (
                    <div className="p-12 flex justify-center"><Activity className="w-8 h-8 text-primary-500 animate-spin" /></div>
                ) : error ? (
                    <div className="p-6 text-red-500 text-sm">{error}</div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800">
                                    <th className="px-4 py-3">
                                        <input type="checkbox" checked={selected.size === scans.length && scans.length > 0} onChange={toggleAll}
                                            className="w-4 h-4 text-primary-600 rounded border-slate-300 focus:ring-primary-500" />
                                    </th>
                                    {['Token', 'Target', 'Type', 'Operator', 'Findings', 'Date', ''].map(h => (
                                        <th key={h} className="px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                {filtered.map(s => (
                                    <tr key={s.id} className={`hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors ${selected.has(s.token) ? 'bg-primary-50 dark:bg-primary-500/5' : ''}`}>
                                        <td className="px-4 py-3">
                                            <input type="checkbox" checked={selected.has(s.token)} onChange={() => toggleSelect(s.token)}
                                                className="w-4 h-4 text-primary-600 rounded border-slate-300 focus:ring-primary-500" />
                                        </td>
                                        <td className="px-4 py-3 text-xs font-mono text-primary-600 dark:text-primary-400">
                                            <Link to={`/reports/${s.token}`} className="hover:underline">{(s.token || '').substring(0, 8)}…</Link>
                                        </td>
                                        <td className="px-4 py-3 text-sm font-medium text-slate-900 dark:text-white truncate max-w-[180px]">{s.target}</td>
                                        <td className="px-4 py-3">
                                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                                                {s.scan_type}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-xs font-mono text-slate-500">{s.username || `#${s.user_id}`}</td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-1.5">
                                                <span className="text-sm font-bold text-slate-700 dark:text-slate-300">{s.vuln_count}</span>
                                                {(s.critical_count > 0 || s.high_count > 0) && (
                                                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border border-red-200 dark:border-red-500/20">
                                                        {s.critical_count > 0 ? `${s.critical_count} CRIT` : `${s.high_count} HIGH`}
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">{new Date(s.stored_at).toLocaleString()}</td>
                                        <td className="px-4 py-3">
                                            <button onClick={() => handleDeleteScan(s.token)}
                                                className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 dark:hover:text-red-400 rounded-lg transition-colors">
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                                {filtered.length === 0 && (
                                    <tr><td colSpan="8" className="px-6 py-12 text-center text-sm text-slate-500">No scan records match your criteria.</td></tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                        <span className="text-xs text-slate-500">Page {page} of {totalPages} · {total} total</span>
                        <div className="flex items-center gap-1">
                            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                                className="p-1.5 rounded-lg text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30 transition-colors">
                                <ChevronLeft className="w-4 h-4" />
                            </button>
                            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                                className="p-1.5 rounded-lg text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30 transition-colors">
                                <ChevronRight className="w-4 h-4" />
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AdminScansPage;
