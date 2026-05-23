import React, { useEffect, useState, useCallback } from 'react';
import axios from 'axios';
import { Link, useSearchParams } from 'react-router-dom';
import { FileText, AlertTriangle, ArrowLeft, Activity, Search, X } from 'lucide-react';
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

const AuditLogPage = () => {
    const { user } = useAuth();
    const [searchParams, setSearchParams] = useSearchParams();
    const filterUserId = searchParams.get('user_id');

    const [logs, setLogs]           = useState([]);
    const [loading, setLoading]     = useState(true);
    const [error, setError]         = useState('');
    const [searchTerm, setSearchTerm] = useState('');

    const fetchLogs = useCallback(async () => {
        setLoading(true);
        setError('');
        try {
            const params = {};
            if (filterUserId) params.user_id = filterUserId;
            const { data } = await axios.get('/api/admin/audit', { params, withCredentials: true });
            setLogs(data.logs || []);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load audit logs');
        } finally {
            setLoading(false);
        }
    }, [filterUserId]);

    useEffect(() => {
        if (user?.role === 'admin') fetchLogs();
    }, [user, fetchLogs]);

    const clearFilter = () => {
        setSearchParams({});
    };

    if (user?.role !== 'admin') {
        return (
            <div className="h-64 flex items-center justify-center">
                <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-6 rounded-xl flex items-center gap-3">
                    <AlertTriangle className="w-6 h-6" />
                    <div>
                        <h3 className="font-bold">Access Denied</h3>
                        <p className="text-sm">Administrator privileges required.</p>
                    </div>
                </div>
            </div>
        );
    }

    const filteredLogs = logs.filter(l =>
        (l.action    || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (l.details   || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (l.username  || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (l.ip_address || '').toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="animate-in fade-in duration-500">
            <div className="mb-8">
                <Link to="/admin" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Admin Panel
                </Link>
                <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                            <FileText className="w-8 h-8 text-primary-500" />
                            System Audit Logs
                        </h1>
                        <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm max-w-2xl">
                            Immutable security and access event trail for compliance monitoring.
                        </p>
                        {filterUserId && (
                            <div className="mt-2 inline-flex items-center gap-2 bg-primary-50 dark:bg-primary-500/10 border border-primary-200 dark:border-primary-500/20 text-primary-700 dark:text-primary-400 text-xs font-semibold px-3 py-1.5 rounded-lg">
                                Filtered: User #{filterUserId}
                                <button onClick={clearFilter} className="hover:opacity-70 transition-opacity">
                                    <X className="w-3.5 h-3.5" />
                                </button>
                            </div>
                        )}
                    </div>
                    <div className="relative">
                        <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                            type="text"
                            placeholder="Search logs..."
                            value={searchTerm}
                            onChange={e => setSearchTerm(e.target.value)}
                            className="pl-9 pr-4 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 w-full md:w-64"
                        />
                    </div>
                </div>
            </div>

            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                {loading ? (
                    <div className="p-12 flex justify-center">
                        <Activity className="w-8 h-8 text-primary-500 animate-spin" />
                    </div>
                ) : error ? (
                    <div className="p-6 text-red-500 text-sm">{error}</div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800">
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Timestamp</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">User</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Action</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Details</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">IP Address</th>
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
                                            <span className={`inline-flex items-center px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider border ${ACTION_COLOR[l.action] || 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700'}`}>
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
                                        <td colSpan="5" className="px-6 py-12 text-center text-sm text-slate-500">
                                            No audit logs match your criteria.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            <div className="mt-4 text-xs text-slate-400 text-right">
                {filteredLogs.length} event{filteredLogs.length !== 1 ? 's' : ''} shown
            </div>
        </div>
    );
};

export default AuditLogPage;
