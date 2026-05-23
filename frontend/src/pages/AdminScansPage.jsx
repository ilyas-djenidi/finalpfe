import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { Database, AlertTriangle, ArrowLeft, Activity, Search, Trash2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const AdminScansPage = () => {
    const { user } = useAuth();
    const [scans, setScans]         = useState([]);
    const [loading, setLoading]     = useState(true);
    const [error, setError]         = useState('');
    const [searchTerm, setSearchTerm] = useState('');

    const fetchScans = async () => {
        setLoading(true);
        try {
            const { data } = await axios.get('/api/admin/scans', { withCredentials: true });
            setScans(data.reports || []);
            setError('');
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load scan records');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (user?.role === 'admin') fetchScans();
    }, [user]);

    const handleDeleteScan = async (token) => {
        if (!window.confirm('Delete this scan record permanently?')) return;
        try {
            await axios.delete(`/api/admin/scans/${token}`, { withCredentials: true });
            fetchScans();
        } catch (err) {
            alert(err.response?.data?.error || 'Failed to delete scan');
        }
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

    const filteredScans = scans.filter(s => {
        const q = searchTerm.toLowerCase();
        return (
            (s.target    || '').toLowerCase().includes(q) ||
            (s.scan_type || '').toLowerCase().includes(q) ||
            (s.username  || '').toLowerCase().includes(q) ||
            (s.token     || '').toLowerCase().includes(q)
        );
    });

    return (
        <div className="animate-in fade-in duration-500">
            <div className="mb-8">
                <Link to="/admin" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Admin Panel
                </Link>

                <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                            <Database className="w-8 h-8 text-primary-500" />
                            Global Scan Records
                        </h1>
                        <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm max-w-2xl">
                            View all scans executed across the platform by any user.
                        </p>
                    </div>
                    <div className="relative">
                        <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input 
                            type="text" 
                            placeholder="Search targets or tokens..." 
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="pl-9 pr-4 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 w-full md:w-64"
                        />
                    </div>
                </div>
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
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Token</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Target</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Type</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Operator</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Findings</th>
                                    <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Date</th>
                                    <th className="px-6 py-3"></th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                {filteredScans.map((s) => (
                                    <tr key={s.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                        <td className="px-6 py-4 text-xs font-mono text-primary-600 dark:text-primary-400">
                                            <Link to={`/reports/${s.token}`} className="hover:underline">{s.token.substring(0,8)}...</Link>
                                        </td>
                                        <td className="px-6 py-4 text-sm font-medium text-slate-900 dark:text-white truncate max-w-[200px]">
                                            {s.target}
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                                                {s.scan_type}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-xs font-mono text-slate-500">
                                            {s.username || `#${s.user_id}`}
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="flex items-center gap-2">
                                                <span className="text-sm font-bold text-slate-700 dark:text-slate-300">{s.vuln_count}</span>
                                                {(s.critical_count > 0 || s.high_count > 0) && (
                                                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border border-red-200 dark:border-red-500/20">
                                                        {s.critical_count > 0 ? `${s.critical_count} CRIT` : `${s.high_count} HIGH`}
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 text-sm text-slate-500 whitespace-nowrap">
                                            {new Date(s.stored_at).toLocaleString()}
                                        </td>
                                        <td className="px-6 py-4">
                                            <button
                                                onClick={() => handleDeleteScan(s.token)}
                                                className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 dark:hover:text-red-400 rounded-lg transition-colors"
                                                title="Delete scan"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                                {filteredScans.length === 0 && (
                                    <tr>
                                        <td colSpan="7" className="px-6 py-12 text-center text-sm text-slate-500">No scan records match your criteria.</td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AdminScansPage;
