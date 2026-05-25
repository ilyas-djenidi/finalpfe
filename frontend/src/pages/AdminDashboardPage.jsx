import React, { useEffect, useState, useCallback } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import {
    Users, Shield, Activity, BarChart2, AlertOctagon,
    ShieldAlert, RefreshCw, Calendar, Database, FileText,
    TrendingUp, Bug, Clock, UserCheck, Lock, ChevronRight,
    Radar, Globe, Network, Code, Package, Zap, Server,
    FileSearch, Layers,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const SEVERITY_STYLES = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20',
    high:     'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
    medium:   'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
    low:      'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
    info:     'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400 border-slate-200 dark:border-slate-700',
};

const SCAN_TYPE_LABELS = {
    web:          'Web App',
    network_ext:  'Net External',
    network_int:  'Net Internal',
    server_ext:   'Server Ext',
    server_int:   'Server Config',
    dependencies: 'Dependencies',
    sast:         'Code (SAST)',
    dast:         'DAST',
};

const ACTION_STYLES = {
    login_success: 'text-green-600 dark:text-green-400',
    login_failed:  'text-red-600 dark:text-red-400',
    scan_started:  'text-blue-600 dark:text-blue-400',
    scan_complete: 'text-primary-600 dark:text-primary-400',
    user_created:  'text-purple-600 dark:text-purple-400',
    user_deleted:  'text-red-600 dark:text-red-400',
    logout:        'text-slate-500 dark:text-slate-400',
};

const getLast7Days = () => {
    const days = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        days.push(d.toISOString().slice(0, 10));
    }
    return days;
};

const StatCard = ({ icon: Icon, label, value, sub, color }) => (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm flex flex-col gap-3">
        <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{label}</span>
            <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${color}`}>
                <Icon className="w-5 h-5" />
            </div>
        </div>
        <div>
            <div className="text-3xl font-bold text-slate-900 dark:text-white tabular-nums">{value ?? '—'}</div>
            {sub && <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{sub}</div>}
        </div>
    </div>
);

const AdminDashboardPage = () => {
    const { user } = useAuth();
    const [stats, setStats]             = useState(null);
    const [topVulns, setTopVulns]       = useState([]);
    const [reports, setReports]         = useState([]);
    const [loading, setLoading]         = useState(true);
    const [error, setError]             = useState('');
    const [lastRefresh, setLastRefresh] = useState(null);
    const [ariaStatus, setAriaStatus]   = useState(null);
    const [clearingAi, setClearingAi]   = useState(false);
    const [aiClearMsg, setAiClearMsg]   = useState('');

    const fetchAll = useCallback(async () => {
        setLoading(true);
        setError('');
        try {
            const [statsRes, scansRes] = await Promise.all([
                axios.get('/api/admin/stats', { withCredentials: true }),
                axios.get('/api/admin/scans',  { withCredentials: true }),
            ]);
            setStats(statsRes.data.stats);
            setTopVulns(statsRes.data.top_vulns || []);
            setReports(scansRes.data.reports || []);
            setLastRefresh(new Date());
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load dashboard data');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        if (user?.role === 'admin') fetchAll();
    }, [user, fetchAll]);

    useEffect(() => {
        axios.get('/api/ai/status', { withCredentials: true })
            .then(r => setAriaStatus(r.data))
            .catch(() => {});
    }, []);

    const handleClearAllAi = async () => {
        if (!window.confirm('Clear ALL users\' AI conversation histories? This cannot be undone.')) return;
        setClearingAi(true);
        setAiClearMsg('');
        try {
            const { data } = await axios.post('/api/admin/ai/clear-all', {}, { withCredentials: true });
            setAiClearMsg(data.message || 'Done.');
        } catch (err) {
            setAiClearMsg(err.response?.data?.error || 'Failed to clear AI histories.');
        } finally {
            setClearingAi(false);
        }
    };

    if (user?.role !== 'admin') {
        return (
            <div className="h-64 flex items-center justify-center">
                <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-6 rounded-xl flex items-center gap-3">
                    <AlertOctagon className="w-6 h-6" />
                    <div>
                        <h3 className="font-bold">Access Denied</h3>
                        <p className="text-sm">Administrator privileges required.</p>
                    </div>
                </div>
            </div>
        );
    }

    // ── 7-day chart data ────────────────────────────────────────────────────
    const days7 = getLast7Days();
    const dailyCounts = days7.map(day => {
        const count = reports.filter(r => (r.stored_at || '').startsWith(day)).length;
        const label = new Date(day + 'T12:00:00').toLocaleDateString('en', { weekday: 'short' });
        return { day, label, count };
    });
    const maxDay = Math.max(...dailyCounts.map(d => d.count), 1);

    // ── Scan type distribution ───────────────────────────────────────────────
    const byType = {};
    reports.forEach(r => {
        const t = r.scan_type || 'unknown';
        byType[t] = (byType[t] || 0) + 1;
    });
    const typeEntries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
    const maxTypeCount = Math.max(...typeEntries.map(([, c]) => c), 1);

    // ── Map username → user_id for audit log links ───────────────────────────
    const userIdByName = {};
    (stats?.users_list || []).forEach(u => { userIdByName[u.username] = u.id; });

    if (loading) return (
        <div className="flex items-center justify-center h-96">
            <div className="flex flex-col items-center gap-4">
                <div className="w-10 h-10 border-4 border-primary-600/30 border-t-primary-600 rounded-full animate-spin" />
                <span className="text-sm text-slate-500">Loading dashboard...</span>
            </div>
        </div>
    );

    if (error) return (
        <div className="flex items-center justify-center h-64">
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-6 rounded-xl text-sm flex items-center gap-3">
                <AlertOctagon className="w-5 h-5 flex-shrink-0" />
                {error}
                <button onClick={fetchAll} className="ml-4 underline text-xs">Retry</button>
            </div>
        </div>
    );

    return (
        <div className="animate-in fade-in duration-500 space-y-6">

            {/* ── Header ──────────────────────────────────────────────────── */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Shield className="w-8 h-8 text-primary-500" />
                        Admin Command Center
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 mt-1 text-sm">
                        Platform-wide security operations overview
                        {lastRefresh && (
                            <span className="ml-2 text-slate-400">
                                · Updated {lastRefresh.toLocaleTimeString()}
                            </span>
                        )}
                    </p>
                </div>
                <button
                    onClick={fetchAll}
                    className="self-start sm:self-auto flex items-center gap-2 px-4 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-sm"
                >
                    <RefreshCw className="w-4 h-4" /> Refresh
                </button>
            </div>

            {/* ── Authorization banner ────────────────────────────────────── */}
            <div className="bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark:border-blue-500/20 rounded-xl px-5 py-3 flex items-start gap-3">
                <Lock className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-blue-700 dark:text-blue-300">
                    <span className="font-semibold">Authorized Use Only.</span>{' '}
                    This platform is designed exclusively for legitimate security assessments conducted
                    with explicit written authorization from the asset owner. All activity is logged
                    and audited for compliance.
                </p>
            </div>

            {/* ── Stats row ───────────────────────────────────────────────── */}
            <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-4">
                <StatCard
                    icon={Users}
                    label="Total Users"
                    value={stats?.total_users}
                    sub={`${stats?.active_users ?? 0} active`}
                    color="bg-blue-100 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400"
                />
                <StatCard
                    icon={Radar}
                    label="Total Scans"
                    value={stats?.total_scans}
                    sub="all time"
                    color="bg-purple-100 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400"
                />
                <StatCard
                    icon={Calendar}
                    label="Today's Scans"
                    value={stats?.today_scans}
                    sub="last 24h"
                    color="bg-cyan-100 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400"
                />
                <StatCard
                    icon={Bug}
                    label="Total Vulns"
                    value={stats?.total_vulns}
                    sub="all scans"
                    color="bg-amber-100 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400"
                />
                <StatCard
                    icon={AlertOctagon}
                    label="Critical Vulns"
                    value={stats?.critical_vulns}
                    sub="across platform"
                    color="bg-red-100 dark:bg-red-500/10 text-red-600 dark:text-red-400"
                />
                <StatCard
                    icon={ShieldAlert}
                    label="Failed Logins"
                    value={stats?.failed_logins}
                    sub="today"
                    color="bg-orange-100 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400"
                />
            </div>

            {/* ── Charts row ──────────────────────────────────────────────── */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

                {/* 7-day bar chart */}
                <div className="lg:col-span-8 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                    <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-6 flex items-center gap-2">
                        <BarChart2 className="w-4 h-4 text-primary-500" /> 7-Day Scan Activity
                    </h2>
                    <div className="flex items-end justify-between gap-2" style={{ height: '144px' }}>
                        {dailyCounts.map(({ day, label, count }) => (
                            <div key={day} className="flex-1 flex flex-col items-center gap-1.5 group">
                                <span className="text-[10px] font-bold text-slate-600 dark:text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity tabular-nums min-h-[14px]">
                                    {count > 0 ? count : ''}
                                </span>
                                <div className="w-full flex items-end rounded-t-sm overflow-hidden" style={{ height: '96px' }}>
                                    <div
                                        className="w-full rounded-t-md bg-primary-500 dark:bg-primary-600 hover:bg-primary-400 dark:hover:bg-primary-500 transition-all duration-300"
                                        style={{
                                            height: count > 0
                                                ? `${Math.max(Math.round((count / maxDay) * 100), 8)}%`
                                                : '3px',
                                            opacity: count > 0 ? 1 : 0.25,
                                        }}
                                        title={`${count} scan${count !== 1 ? 's' : ''} on ${day}`}
                                    />
                                </div>
                                <span className="text-[10px] text-slate-500 dark:text-slate-400">{label}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Scan type breakdown */}
                <div className="lg:col-span-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                    <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-6 flex items-center gap-2">
                        <TrendingUp className="w-4 h-4 text-primary-500" /> Scan Types
                    </h2>
                    {typeEntries.length === 0 ? (
                        <p className="text-sm text-slate-500 text-center py-8">No scans recorded yet.</p>
                    ) : (
                        <div className="space-y-3.5">
                            {typeEntries.map(([type, count]) => (
                                <div key={type}>
                                    <div className="flex items-center justify-between mb-1">
                                        <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                                            {SCAN_TYPE_LABELS[type] || type}
                                        </span>
                                        <span className="text-xs font-bold text-slate-500 dark:text-slate-400 tabular-nums">{count}</span>
                                    </div>
                                    <div className="h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-primary-500 rounded-full transition-all duration-500"
                                            style={{ width: `${Math.round((count / maxTypeCount) * 100)}%` }}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* ── Data row ────────────────────────────────────────────────── */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

                {/* Top vulnerabilities */}
                <div className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                    <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/20 flex items-center gap-2">
                        <Bug className="w-4 h-4 text-primary-500" />
                        <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                            Top Vulnerabilities
                        </h2>
                    </div>
                    {topVulns.length === 0 ? (
                        <p className="p-8 text-center text-sm text-slate-500">No vulnerability data yet. Run some scans first.</p>
                    ) : (
                        <div className="divide-y divide-slate-100 dark:divide-slate-800">
                            {topVulns.slice(0, 8).map((v, i) => (
                                <div
                                    key={i}
                                    className="px-6 py-3 flex items-center justify-between gap-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                                >
                                    <div className="flex items-center gap-3 min-w-0">
                                        <span className="text-xs font-mono text-slate-400 w-5 flex-shrink-0">#{i + 1}</span>
                                        <span className="text-sm text-slate-700 dark:text-slate-300 truncate">{v.title}</span>
                                    </div>
                                    <div className="flex items-center gap-2 flex-shrink-0">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${SEVERITY_STYLES[v.severity] || SEVERITY_STYLES.info}`}>
                                            {v.severity}
                                        </span>
                                        <span className="text-xs font-bold text-slate-500 dark:text-slate-400 tabular-nums w-8 text-right">
                                            {v.count}×
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Right column: top scanners + recent events */}
                <div className="lg:col-span-5 flex flex-col gap-6">

                    {/* Top operators */}
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/20 flex items-center gap-2">
                            <UserCheck className="w-4 h-4 text-primary-500" />
                            <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                                Top Operators
                            </h2>
                        </div>
                        {!stats?.top_scanners?.length ? (
                            <p className="p-6 text-center text-sm text-slate-500">No scan history yet.</p>
                        ) : (
                            <div className="divide-y divide-slate-100 dark:divide-slate-800">
                                {stats.top_scanners.map((s, i) => {
                                    const uid = userIdByName[s.username];
                                    return (
                                        <div key={s.username} className="px-6 py-3 flex items-center justify-between hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                            <div className="flex items-center gap-3">
                                                <span className="text-xs font-mono text-slate-400 w-5">#{i + 1}</span>
                                                {uid != null ? (
                                                    <Link
                                                        to={`/audit?user_id=${uid}`}
                                                        className="text-sm font-medium text-slate-700 dark:text-slate-300 hover:text-primary-600 dark:hover:text-primary-400 transition-colors"
                                                    >
                                                        {s.username}
                                                    </Link>
                                                ) : (
                                                    <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{s.username}</span>
                                                )}
                                            </div>
                                            <span className="text-xs font-bold bg-primary-50 dark:bg-primary-500/10 text-primary-700 dark:text-primary-400 border border-primary-200 dark:border-primary-500/20 px-2.5 py-1 rounded-lg tabular-nums">
                                                {s.count} scan{s.count !== 1 ? 's' : ''}
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>

                    {/* Recent events */}
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden flex-1">
                        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/20 flex items-center gap-2">
                            <Clock className="w-4 h-4 text-primary-500" />
                            <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                                Recent Events
                            </h2>
                        </div>
                        {!stats?.recent_events?.length ? (
                            <p className="p-6 text-center text-sm text-slate-500">No recent events.</p>
                        ) : (
                            <div className="divide-y divide-slate-100 dark:divide-slate-800">
                                {stats.recent_events.slice(0, 8).map((ev, i) => (
                                    <div key={i} className="px-6 py-3 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2 flex-wrap">
                                                <span className={`text-xs font-bold ${ACTION_STYLES[ev.action] || 'text-slate-600 dark:text-slate-400'}`}>
                                                    {(ev.action || '').replace(/_/g, ' ')}
                                                </span>
                                                {ev.username && (
                                                    <span className="text-xs text-slate-500 dark:text-slate-400">
                                                        by {ev.username}
                                                    </span>
                                                )}
                                            </div>
                                            <span className="text-[10px] text-slate-400">
                                                {ev.created_at ? new Date(ev.created_at).toLocaleString() : ''}
                                            </span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* ── ARIA AI Management ──────────────────────────────────────── */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-xl bg-cyan-50 dark:bg-cyan-500/10 flex items-center justify-center text-cyan-600 dark:text-cyan-400 flex-shrink-0">
                            <Activity className="w-5 h-5" />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                ARIA AI Management
                                {ariaStatus && (
                                    <span className={`inline-flex items-center gap-1 text-[9px] px-2 py-0.5 rounded-full font-mono border ${
                                        ariaStatus.provider === 'gemini'
                                            ? 'bg-green-50 border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400'
                                            : ariaStatus.provider === 'ollama'
                                            ? 'bg-blue-50 border-blue-200 text-blue-700 dark:bg-blue-500/10 dark:border-blue-500/30 dark:text-blue-400'
                                            : 'bg-yellow-50 border-yellow-200 text-yellow-700 dark:bg-yellow-500/10 dark:border-yellow-500/30 dark:text-yellow-400'
                                    }`}>
                                        <span className={`w-1.5 h-1.5 rounded-full ${ariaStatus.provider === 'gemini' ? 'bg-green-500' : ariaStatus.provider === 'ollama' ? 'bg-blue-500' : 'bg-yellow-500'}`} />
                                        {ariaStatus.provider === 'gemini' ? 'Gemini Online' : ariaStatus.provider === 'ollama' ? 'Ollama Local' : 'Offline Mode'}
                                    </span>
                                )}
                            </h2>
                            <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 flex flex-wrap gap-3">
                                {ariaStatus?.model && <span>Model: <span className="font-mono text-slate-700 dark:text-slate-300">{ariaStatus.model}</span></span>}
                                <span>Per-user isolated conversation histories</span>
                            </div>
                            {aiClearMsg && (
                                <p className="text-xs mt-1 text-primary-600 dark:text-primary-400">{aiClearMsg}</p>
                            )}
                        </div>
                    </div>
                    <button
                        onClick={handleClearAllAi}
                        disabled={clearingAi}
                        className="self-start sm:self-auto flex items-center gap-2 px-4 py-2 text-sm font-semibold text-red-600 dark:text-red-400 border border-red-200 dark:border-red-500/30 rounded-xl hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors disabled:opacity-50"
                    >
                        <RefreshCw className={`w-4 h-4 ${clearingAi ? 'animate-spin' : ''}`} />
                        {clearingAi ? 'Clearing…' : 'Clear All AI Histories'}
                    </button>
                </div>
            </div>
        </div>

    );
};

export default AdminDashboardPage;
