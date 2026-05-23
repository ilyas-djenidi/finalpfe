import React, { useEffect, useState, useCallback, useRef } from 'react';
import axios from 'axios';
import { Link, useSearchParams } from 'react-router-dom';
import {
    FileText, AlertTriangle, ArrowLeft, Activity,
    Search, X, Download, RefreshCw, ChevronLeft, ChevronRight
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const ACTION_COLOR = {
    login_success: 'bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border-green-200 dark:border-green-500/20',
    login_failed:  'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20',
    scan_started:  'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
    scan_complete: 'bg-primary-100 text-primary-700 dark:bg-primary-500/10 dark:text-primary-400 border-primary-200 dark:border-primary-500/20',
    user_created:  'bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400 border-purple-200 dark:border-purple-500/20',
    user_deleted:  'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20',
    logout:        'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400 border-slate-200 dark:border-slate-700',
};

const CATEGORIES = ['auth', 'scan', 'admin', 'report', 'ai'];
const PER_PAGE = 50;

const AuditLogPage = () => {
    const { user } = useAuth();
    const [searchParams, setSearchParams] = useSearchParams();
    const filterUserId = searchParams.get('user_id');

    const [logs, setLogs]             = useState([]);
    const [loading, setLoading]       = useState(true);
    const [error, setError]           = useState('');
    const [total, setTotal]           = useState(0);
    const [page, setPage]             = useState(1);

    // Filters
    const [search, setSearch]         = useState('');
    const [category, setCategory]     = useState('');
    const [actionFilter, setAction]   = useState('');
    const [dateFrom, setDateFrom]     = useState('');
    const [dateTo, setDateTo]         = useState('');

    // Auto-refresh
    const [autoRefresh, setAutoRefresh] = useState(false);
    const intervalRef = useRef(null);

    const fetchLogs = useCallback(async (p = page) => {
        setLoading(true);
        setError('');
        try {
            const params = { page: p, per_page: PER_PAGE };
            if (filterUserId) params.user_id  = filterUserId;
            if (category)     params.category  = category;
            if (actionFilter) params.action    = actionFilter;
            if (dateFrom)     params.date_from = dateFrom;
            if (dateTo)       params.date_to   = dateTo;
            const { data } = await axios.get('/api/admin/audit', { params, withCredentials: true });
            setLogs(data.logs || []);
            setTotal(data.total || 0);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load audit logs');
        } finally {
            setLoading(false);
        }
    }, [filterUserId, category, actionFilter, dateFrom, dateTo, page]);

    useEffect(() => {
        if (user?.role === 'admin') fetchLogs(page);
    }, [user, page]);

    // Auto-refresh every 30 seconds
    useEffect(() => {
        if (autoRefresh) {
            intervalRef.current = setInterval(() => fetchLogs(page), 30000);
        } else {
            clearInterval(intervalRef.current);
        }
        return () => clearInterval(intervalRef.current);
    }, [autoRefresh, fetchLogs, page]);

    const applyFilters = () => { setPage(1); fetchLogs(1); };

    const exportCsv = () => {
        if (!logs.length) return;
        const rows = [
            ['Timestamp', 'User', 'Action', 'Category', 'Details', 'IP Address'],
            ...logs.map(l => [l.created_at, l.username || l.user_id, l.action, l.category || '', l.details || l.resource || '', l.ip_address || ''])
        ];
        const csv = rows.map(r => r.map(v => `"${(v ?? '').toString().replace(/"/g, '""')}"`).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = 'audit_log_export.csv'; a.click();
        URL.revokeObjectURL(url);
    };

    const filteredLogs = logs.filter(l => {
        const q = search.toLowerCase();
        return !q || (l.action || '').toLowerCase().includes(q) ||
            (l.details || '').toLowerCase().includes(q) ||
            (l.username || '').toLowerCase().includes(q) ||
            (l.ip_address || '').toLowerCase().includes(q);
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
                            <FileText className="w-8 h-8 text-primary-500" /> System Audit Logs
                        </h1>
                        <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">Immutable security and access event trail for compliance monitoring.</p>
                        {filterUserId && (
                            <div className="mt-2 inline-flex items-center gap-2 bg-primary-50 dark:bg-primary-500/10 border border-primary-200 dark:border-primary-500/20 text-primary-700 dark:text-primary-400 text-xs font-semibold px-3 py-1.5 rounded-lg">
                                Filtered: User #{filterUserId}
                                <button onClick={() => setSearchParams({})} className="hover:opacity-70 transition-opacity">
                                    <X className="w-3.5 h-3.5" />
                                </button>
                            </div>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        {/* Auto-refresh toggle */}
                        <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-500 dark:text-slate-400">
                            <div
                                onClick={() => setAutoRefresh(v => !v)}
                                className={`w-9 h-5 rounded-full transition-colors relative ${autoRefresh ? 'bg-primary-500' : 'bg-slate-300 dark:bg-slate-700'}`}
                            >
                                <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${autoRefresh ? 'translate-x-4' : 'translate-x-0.5'}`} />
                            </div>
                            Auto-refresh
                        </label>
                        <button onClick={exportCsv} className="px-3 py-2 text-xs font-semibold text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors flex items-center gap-1.5">
                            <Download className="w-3.5 h-3.5" /> Export CSV
                        </button>
                        <button onClick={() => fetchLogs(page)} className="p-2 text-slate-500 hover:text-primary-600 hover:bg-primary-50 dark:hover:bg-primary-500/10 rounded-lg transition-colors" title="Refresh">
                            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                        </button>
                    </div>
                </div>
            </div>

            {/* Filter bar */}
            <div className="mb-4 flex flex-wrap items-end gap-3 p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-sm">
                <div className="relative flex-1 min-w-[160px]">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input type="text" placeholder="Search logs..." value={search} onChange={e => setSearch(e.target.value)}
                        className="pl-9 pr-4 py-2 border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 w-full" />
                </div>
                <select value={category} onChange={e => setCategory(e.target.value)}
                    className="px-3 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500">
                    <option value="">All Categories</option>
                    {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
                <input type="text" placeholder="Action filter..." value={actionFilter} onChange={e => setAction(e.target.value)}
                    className="px-3 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 w-36" />
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
                                    {['Timestamp', 'User', 'Action', 'Details', 'IP Address'].map(h => (
                                        <th key={h} className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                {filteredLogs.map(l => (
                                    <tr key={l.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                        <td className="px-6 py-4 text-xs text-slate-500 whitespace-nowrap">
                                            {l.created_at ? new Date(l.created_at).toLocaleString() : '—'}
                                        </td>
                                        <td className="px-6 py-4 text-xs font-mono text-slate-900 dark:text-white whitespace-nowrap">
                                            {l.username || (l.user_id ? `#${l.user_id}` : 'SYSTEM')}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${ACTION_COLOR[l.action] || 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700'}`}>
                                                {l.action}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400 max-w-sm truncate">
                                            {l.details || l.resource || '—'}
                                        </td>
                                        <td className="px-6 py-4 text-xs font-mono text-slate-500 whitespace-nowrap">
                                            {l.ip_address || '—'}
                                        </td>
                                    </tr>
                                ))}
                                {filteredLogs.length === 0 && (
                                    <tr>
                                        <td colSpan="5" className="px-6 py-12 text-center text-sm text-slate-500">No audit logs match your criteria.</td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                        <span className="text-xs text-slate-500">Page {page} of {totalPages} · {total} events total</span>
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

            <div className="mt-4 text-xs text-slate-400 text-right flex items-center justify-end gap-2">
                {autoRefresh && <span className="text-primary-500">● auto-refreshing every 30s</span>}
                {filteredLogs.length} event{filteredLogs.length !== 1 ? 's' : ''} shown
            </div>
        </div>
    );
};

export default AuditLogPage;
