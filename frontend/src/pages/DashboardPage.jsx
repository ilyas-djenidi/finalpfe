import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import {
    Activity, Shield, AlertTriangle, FileText,
    Globe, Server, Code, Settings, ChevronRight,
    Package, Zap, Network, Layers
} from 'lucide-react';

const SEVERITY_COLOR = {
    CRITICAL: 'text-red-700 bg-red-100 dark:text-red-400 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20',
    HIGH:     'text-orange-700 bg-orange-100 dark:text-orange-400 dark:bg-orange-500/10 border border-orange-200 dark:border-orange-500/20',
    MEDIUM:   'text-yellow-700 bg-yellow-100 dark:text-yellow-400 dark:bg-yellow-500/10 border border-yellow-200 dark:border-yellow-500/20',
    LOW:      'text-green-700 bg-green-100 dark:text-green-400 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20',
    INFO:     'text-blue-700 bg-blue-100 dark:text-blue-400 dark:bg-blue-500/10 border border-blue-200 dark:border-blue-500/20',
};

const SCAN_TYPE_BADGE = {
    web:          { label: 'Web',          icon: Globe,    color: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-500/10 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-500/20' },
    network:      { label: 'Network',      icon: Server,   color: 'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20' },
    network_ext:  { label: 'Net (Ext)',    icon: Network,  color: 'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20' },
    network_int:  { label: 'Net (Int)',    icon: Network,  color: 'bg-teal-100 text-teal-700 dark:bg-teal-500/10 dark:text-teal-400 border border-teal-200 dark:border-teal-500/20' },
    code:         { label: 'Code',         icon: Code,     color: 'bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400 border border-purple-200 dark:border-purple-500/20' },
    sast:         { label: 'SAST',         icon: Layers,   color: 'bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400 border border-purple-200 dark:border-purple-500/20' },
    dast:         { label: 'DAST',         icon: Zap,      color: 'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border border-orange-200 dark:border-orange-500/20' },
    dependencies: { label: 'Dependencies', icon: Package,  color: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-500/20' },
    apache:       { label: 'Config',       icon: Settings, color: 'bg-slate-100 text-slate-700 dark:bg-slate-500/10 dark:text-slate-400 border border-slate-200 dark:border-slate-500/20' },
    server_ext:   { label: 'Server (Ext)', icon: Server,   color: 'bg-slate-100 text-slate-700 dark:bg-slate-500/10 dark:text-slate-400 border border-slate-200 dark:border-slate-500/20' },
    server_int:   { label: 'Server (Int)', icon: Settings, color: 'bg-slate-100 text-slate-700 dark:bg-slate-500/10 dark:text-slate-400 border border-slate-200 dark:border-slate-500/20' },
};

const StatCard = ({ label, value, icon: Icon, colorClass, delay }) => (
    <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay }}
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm hover:shadow-md transition-shadow"
    >
        <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400">{label}</h3>
            <div className={`p-2 rounded-lg ${colorClass}`}>
                <Icon className="w-5 h-5" />
            </div>
        </div>
        <div className="text-3xl font-bold text-slate-900 dark:text-white font-mono">
            {value}
        </div>
    </motion.div>
);

const RiskProgressBar = ({ score }) => {
    const raw = parseFloat(score) || 0;
    const pct = Math.min(100, Math.max(0, raw * 10));
    const color = pct >= 75 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-500' : pct >= 25 ? 'bg-yellow-500' : 'bg-green-500';
    return (
        <div className="w-full flex items-center gap-3">
            <div className="flex-1 h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%`, transition: 'width 1s ease' }} />
            </div>
            <span className="text-xs font-bold font-mono w-8 text-right text-slate-700 dark:text-slate-300">
                {raw.toFixed(1)}
            </span>
        </div>
    );
};

const DashboardPage = () => {
    const { user } = useAuth();
    const navigate = useNavigate();
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        if (!user) { navigate('/login'); return; }
        axios.get('/api/dashboard', { withCredentials: true })
            .then(r => setData(r.data))
            .catch(() => setError('Failed to load dashboard data.'))
            .finally(() => setLoading(false));
    }, [user, navigate]);

    if (loading) return (
        <div className="h-64 flex flex-col items-center justify-center space-y-4">
            <Activity className="w-8 h-8 text-primary-500 animate-spin" />
            <p className="text-sm text-slate-500 dark:text-slate-400 font-medium">Loading Dashboard Data...</p>
        </div>
    );

    if (error) return (
        <div className="h-64 flex items-center justify-center">
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 px-6 py-4 rounded-xl flex items-center gap-3">
                <AlertTriangle className="w-5 h-5" />
                <p className="text-sm font-medium">{error}</p>
            </div>
        </div>
    );

    const stats   = data?.stats   || {};
    const reports = data?.reports || [];

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Header Area */}
            <div>
                <h1 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Overview</h1>
                <p className="text-slate-500 dark:text-slate-400 text-sm">
                    View your security posture and recent operations.
                </p>
            </div>

            {/* Stat Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard 
                    label="Total Scans" 
                    value={stats.total_scans || 0} 
                    icon={Activity} 
                    colorClass="bg-blue-100 text-blue-600 dark:bg-blue-500/20 dark:text-blue-400" 
                    delay={0} 
                />
                <StatCard 
                    label="Vulnerabilities Found" 
                    value={stats.total_vulns || 0} 
                    icon={AlertTriangle} 
                    colorClass="bg-orange-100 text-orange-600 dark:bg-orange-500/20 dark:text-orange-400" 
                    delay={0.1} 
                />
                <StatCard 
                    label="Critical Issues" 
                    value={stats.critical_vulns || 0} 
                    icon={Shield} 
                    colorClass="bg-red-100 text-red-600 dark:bg-red-500/20 dark:text-red-400" 
                    delay={0.2} 
                />
                <StatCard 
                    label="Average Risk Score" 
                    value={parseFloat(stats.avg_risk || 0).toFixed(1)} 
                    icon={FileText} 
                    colorClass="bg-purple-100 text-purple-600 dark:bg-purple-500/20 dark:text-purple-400" 
                    delay={0.3} 
                />
            </div>

            {/* Main Content Area */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Recent Scans Table */}
                <div className="lg:col-span-2 space-y-4">
                    <div className="flex items-center justify-between">
                        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Recent Operations</h2>
                        <Link to="/reports" className="text-sm font-medium text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 flex items-center gap-1">
                            View All <ChevronRight className="w-4 h-4" />
                        </Link>
                    </div>

                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
                        {reports.length === 0 ? (
                            <div className="p-12 text-center">
                                <FileText className="w-12 h-12 text-slate-300 dark:text-slate-600 mx-auto mb-4" />
                                <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-1">No scan records found</h3>
                                <p className="text-sm text-slate-500 dark:text-slate-400">Launch your first security scan to see results here.</p>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800">
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Target</th>
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Type</th>
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Risk Level</th>
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Findings</th>
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Date</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                        {reports.slice(0, 8).map((r, i) => {
                                            const badge = SCAN_TYPE_BADGE[r.scan_type] || SCAN_TYPE_BADGE.web;
                                            const BadgeIcon = badge.icon;
                                            
                                            return (
                                                <tr 
                                                    key={r.token}
                                                    onClick={() => navigate(`/reports/${r.token}`)}
                                                    className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer group"
                                                >
                                                    <td className="px-6 py-4">
                                                        <span className="text-sm font-medium text-slate-900 dark:text-slate-100 group-hover:text-primary-600 dark:group-hover:text-primary-400 transition-colors font-mono truncate max-w-[200px] block">
                                                            {r.target || 'N/A'}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium ${badge.color}`}>
                                                            <BadgeIcon className="w-3.5 h-3.5" />
                                                            {badge.label}
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 w-40">
                                                        <RiskProgressBar score={r.risk_score} />
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <div className="flex items-center gap-2">
                                                            <span className="text-sm font-bold text-slate-700 dark:text-slate-300 font-mono">{r.vuln_count || 0}</span>
                                                            {(r.critical_count > 0 || r.high_count > 0) && (
                                                                <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border border-red-200 dark:border-red-500/20">
                                                                    {r.critical_count > 0 ? `${r.critical_count} CRIT` : `${r.high_count} HIGH`}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 text-sm text-slate-500 dark:text-slate-400 whitespace-nowrap">
                                                        {r.stored_at ? new Date(r.stored_at).toLocaleDateString() : '—'}
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>

                {/* Quick Launch Panel */}
                <div className="space-y-4">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Quick Launch</h2>
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm flex flex-col gap-3">
                        {[
                            { label: 'Web Application Scan', desc: 'Automated vulnerability assessment', href: '/scan/web', icon: Globe, color: 'text-indigo-500 bg-indigo-50 dark:bg-indigo-500/10' },
                            { label: 'Network Scan', desc: 'Discover open ports and services', href: '/scan/network', icon: Network, color: 'text-blue-500 bg-blue-50 dark:bg-blue-500/10' },
                            { label: 'Dynamic Analysis', desc: 'Runtime behaviour and injection testing', href: '/scan/dast', icon: Zap, color: 'text-orange-500 bg-orange-50 dark:bg-orange-500/10' },
                            { label: 'Code Analysis', desc: 'Static source code security review', href: '/scan/code', icon: Code, color: 'text-purple-500 bg-purple-50 dark:bg-purple-500/10' },
                            { label: 'Server Config Audit', desc: 'Upload config for internal analysis', href: '/scan/apache', icon: Settings, color: 'text-teal-500 bg-teal-50 dark:bg-teal-500/10' },
                            { label: 'Dependencies', desc: 'Detect vulnerable packages', href: '/scan/dependencies', icon: Package, color: 'text-yellow-500 bg-yellow-50 dark:bg-yellow-500/10' },
                        ].map((item) => (
                            <Link 
                                key={item.href} 
                                to={item.href}
                                className="flex items-center gap-4 p-3 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors border border-transparent hover:border-slate-200 dark:hover:border-slate-700 group"
                            >
                                <div className={`p-2.5 rounded-lg ${item.color} group-hover:scale-105 transition-transform`}>
                                    <item.icon className="w-5 h-5" />
                                </div>
                                <div>
                                    <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{item.label}</h3>
                                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{item.desc}</p>
                                </div>
                            </Link>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default DashboardPage;
