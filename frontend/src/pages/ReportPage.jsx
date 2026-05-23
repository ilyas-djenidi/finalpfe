import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { FileText, Table, Code, ArrowLeft, Download } from 'lucide-react';

const REPORTS = [
    {
        label: 'Markdown Report',
        desc:  'Full vulnerability report with findings, severity, and recommendations',
        icon:  FileText,
        color: 'text-primary-600 bg-primary-100 dark:text-primary-400 dark:bg-primary-500/10 border-primary-200 dark:border-primary-500/20',
        endpoint: '/download_report',
        filename: 'vulnerability_report.md',
    },
    {
        label: 'CSV Export',
        desc:  'Spreadsheet-ready CSV with all findings for data analysis',
        icon:  Table,
        color: 'text-green-600 bg-green-100 dark:text-green-400 dark:bg-green-500/10 border-green-200 dark:border-green-500/20',
        endpoint: '/download_report_csv',
        filename: 'findings_summary.csv',
    },
    {
        label: 'JSON Export',
        desc:  'Raw JSON data export for integration with other security tools',
        icon:  Code,
        color: 'text-purple-600 bg-purple-100 dark:text-purple-400 dark:bg-purple-500/10 border-purple-200 dark:border-purple-500/20',
        endpoint: '/download_report_json',
        filename: 'findings.json',
    },
];

const ReportPage = () => {
    const [downloading, setDownloading] = useState({});

    const handleDownload = async (report) => {
        setDownloading(p => ({ ...p, [report.label]: true }));
        try {
            const res = await fetch(report.endpoint, { credentials: 'include' });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                alert(err.error || 'No report found. Run a scan first.');
                return;
            }
            const blob = await res.blob();
            const url  = URL.createObjectURL(blob);
            const a    = document.createElement('a');
            a.href     = url;
            a.download = report.filename;
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) {
            alert('Backend offline or no scan run yet.');
        } finally {
            setDownloading(p => ({ ...p, [report.label]: false }));
        }
    };

    return (
        <div className="animate-in fade-in duration-500 max-w-4xl mx-auto">
            {/* Header Section */}
            <div className="mb-8 text-center">
                <Link to="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Dashboard
                </Link>
                <div className="flex flex-col items-center">
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Download className="w-8 h-8 text-primary-500" />
                        Export Reports
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm max-w-xl text-center">
                        Download the results of your most recent security assessment in multiple formats.
                    </p>
                </div>
            </div>

            {/* Report Download Cards */}
            <div className="grid gap-4 mt-8">
                {REPORTS.map((report, i) => {
                    const Icon = report.icon;
                    return (
                        <div
                            key={report.label}
                            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-6 hover:shadow-md transition-shadow"
                        >
                            <div className="flex items-center gap-4">
                                <div className={`w-12 h-12 flex items-center justify-center rounded-xl border ${report.color}`}>
                                    <Icon className="w-6 h-6" />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-0.5">
                                        {report.label}
                                    </h3>
                                    <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md leading-relaxed">
                                        {report.desc}
                                    </p>
                                </div>
                            </div>
                            <button
                                onClick={() => handleDownload(report)}
                                disabled={downloading[report.label]}
                                className="w-full sm:w-auto px-6 py-2.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                            >
                                {downloading[report.label] ? (
                                    <>
                                        <div className="w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                                        Downloading...
                                    </>
                                ) : (
                                    <>
                                        <Download className="w-4 h-4" /> Download
                                    </>
                                )}
                            </button>
                        </div>
                    );
                })}
            </div>

            {/* Quick nav to scanners */}
            <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800 text-center">
                <p className="text-slate-500 dark:text-slate-400 text-sm mb-4">No recent reports? Run a new security assessment.</p>
                <div className="flex flex-wrap justify-center gap-3">
                    {[
                        { href: '/web-scan',     label: 'Web Scanner' },
                        { href: '/apache-scan',  label: 'Apache Audit' },
                        { href: '/code-scan',    label: 'Code Analyzer' },
                        { href: '/network-scan', label: 'Network Recon' },
                    ].map(link => (
                        <Link
                            key={link.href}
                            to={link.href}
                            className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 text-xs font-semibold uppercase tracking-wider rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                        >
                            {link.label}
                        </Link>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default ReportPage;
