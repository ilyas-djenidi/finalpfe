import React, { useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { Link } from 'react-router-dom';
import {
    Activity, ArrowLeft, Shield, AlertTriangle, Terminal,
    ChevronRight, Download, FileSearch, UploadCloud, FileText,
    X, CheckCircle, ToggleLeft, ToggleRight, FileDown, ClipboardList,
    ChevronDown, ChevronUp, Hash, Info
} from 'lucide-react';

const SEV_STYLES = {
    CRITICAL: { badge: 'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20', dot: 'bg-red-500' },
    HIGH:     { badge: 'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border-orange-200 dark:border-orange-500/20', dot: 'bg-orange-500' },
    MEDIUM:   { badge: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20', dot: 'bg-yellow-500' },
    LOW:      { badge: 'bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border-green-200 dark:border-green-500/20', dot: 'bg-green-500' },
    INFO:     { badge: 'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20', dot: 'bg-blue-500' },
};

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function downloadBlob(content, filename, mime = 'text/plain') {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

function buildJsonReport(results, scanMode, target, fileName) {
    return JSON.stringify({
        report: {
            tool: 'CyBrain Security Platform',
            scan_type: scanMode === 'file' ? 'Internal Config Audit (White-Box)' : scanMode === 'full' ? 'External Deep Audit' : 'Security Headers Audit',
            target: scanMode === 'file' ? fileName : target,
            generated_at: new Date().toISOString(),
        },
        summary: {
            total: results.findings?.length || 0,
            critical: results.findings?.filter(f => f.severity === 'CRITICAL').length || 0,
            high:     results.findings?.filter(f => f.severity === 'HIGH').length || 0,
            medium:   results.findings?.filter(f => f.severity === 'MEDIUM').length || 0,
            low:      results.findings?.filter(f => f.severity === 'LOW').length || 0,
            info:     results.findings?.filter(f => f.severity === 'INFO').length || 0,
        },
        findings: results.findings || [],
    }, null, 2);
}

/* Finding card with line number, state toggle, inline fix */
function FindingCard({ finding, index, isFixed, onToggleFix }) {
    const [expanded, setExpanded] = useState(false);
    const sev = (finding.severity || 'INFO').toUpperCase();
    const styles = SEV_STYLES[sev] || SEV_STYLES.INFO;
    const lineNum = finding.line_number || finding.line || null;
    const currentValue = finding.current_value || finding.evidence || null;

    return (
        <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.03 }}
            className={`bg-white dark:bg-slate-900 border rounded-xl shadow-sm overflow-hidden transition-all ${
                isFixed ? 'border-green-300 dark:border-green-500/30 opacity-70' : 'border-slate-200 dark:border-slate-800'
            }`}
        >
            {/* Card header */}
            <div
                className="flex items-start gap-4 p-4 cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                onClick={() => setExpanded(e => !e)}
            >
                <div className="flex-shrink-0 pt-0.5 flex flex-col items-center gap-1.5">
                    <div className={`w-2 h-2 rounded-full ${styles.dot}`} />
                    {lineNum != null && (
                        <div className="flex items-center gap-0.5 text-[9px] text-slate-400 font-mono">
                            <Hash className="w-2.5 h-2.5" />
                            {lineNum}
                        </div>
                    )}
                </div>

                <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1.5">
                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold tracking-wider border ${styles.badge}`}>
                            {sev}
                        </span>
                        <span className="text-sm font-bold text-slate-900 dark:text-white truncate">
                            {finding.code || finding.id || `Finding #${index + 1}`}
                        </span>
                        {isFixed && (
                            <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 px-2 py-0.5 rounded-full">
                                <CheckCircle className="w-3 h-3" /> Fixed
                            </span>
                        )}
                    </div>
                    <p className="text-sm text-slate-600 dark:text-slate-300 line-clamp-2">
                        {finding.message || finding.desc}
                    </p>
                </div>

                <div className="flex items-center gap-2 flex-shrink-0">
                    {/* Fix toggle */}
                    <button
                        onClick={(e) => { e.stopPropagation(); onToggleFix(); }}
                        title={isFixed ? 'Mark as unfixed' : 'Mark as fixed'}
                        className={`p-1.5 rounded-lg transition-colors ${
                            isFixed
                                ? 'text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-500/10'
                                : 'text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                        }`}
                    >
                        {isFixed ? <ToggleRight className="w-5 h-5" /> : <ToggleLeft className="w-5 h-5" />}
                    </button>
                    {expanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                </div>
            </div>

            {/* Expanded details */}
            <AnimatePresence>
                {expanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                    >
                        <div className="px-4 pb-4 space-y-3 border-t border-slate-100 dark:border-slate-800 pt-3">
                            {/* Line + current state */}
                            {(lineNum != null || currentValue) && (
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                    {lineNum != null && (
                                        <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2.5">
                                            <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1 flex items-center gap-1">
                                                <Hash className="w-3 h-3" /> Line Number
                                            </div>
                                            <code className="text-sm font-mono font-bold text-primary-600 dark:text-primary-400">
                                                Line {lineNum}
                                            </code>
                                        </div>
                                    )}
                                    {currentValue && (
                                        <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2.5">
                                            <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1 flex items-center gap-1">
                                                <Info className="w-3 h-3" /> Current State
                                            </div>
                                            <code className="text-xs font-mono text-red-600 dark:text-red-400 break-all">
                                                {currentValue}
                                            </code>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Recommended fix */}
                            {finding.fix && (
                                <div className="bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-500/20 rounded-lg px-3 py-2.5">
                                    <div className="text-[10px] font-semibold text-green-700 dark:text-green-400 uppercase tracking-wider mb-1.5">
                                        Recommended Fix
                                    </div>
                                    <code className="text-xs text-green-800 dark:text-green-300 break-all leading-relaxed font-mono">
                                        {finding.fix}
                                    </code>
                                </div>
                            )}

                            {/* Evidence */}
                            {finding.evidence && finding.evidence !== currentValue && (
                                <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2.5">
                                    <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">Evidence</div>
                                    <code className="text-xs text-slate-600 dark:text-slate-400 break-all font-mono">{finding.evidence}</code>
                                </div>
                            )}

                            {/* Remediation text */}
                            {finding.remediation && (
                                <p className="text-xs text-slate-500 dark:text-slate-400 italic leading-relaxed">
                                    {finding.remediation}
                                </p>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    );
}

const ApacheScanPage = () => {
    const [target, setTarget]                 = useState('');
    const [scanMode, setScanMode]             = useState('file');
    const [loading, setLoading]               = useState(false);
    const [results, setResults]               = useState(null);
    const [error, setError]                   = useState(null);
    const [permissionGranted, setPermissionGranted] = useState(false);
    const [ariaAnalysis, setAriaAnalysis]     = useState('');
    const [analyzing, setAnalyzing]           = useState(false);
    const [fixedSet, setFixedSet]             = useState(new Set());
    const [file, setFile]                     = useState(null);
    const [isDragging, setIsDragging]         = useState(false);
    const fileInputRef                        = useRef(null);

    const scanModes = [
        { id: 'file',    label: 'Internal Config Audit', desc: 'Upload your config file for deep white-box analysis', icon: FileSearch },
        { id: 'full',    label: 'External Deep Audit',   desc: 'Remotely probe server for misconfigurations',         icon: Shield },
        { id: 'headers', label: 'Headers Audit',         desc: 'Check for missing or weak security headers',          icon: Terminal },
    ];

    const handleDrag = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(e.type === 'dragenter' || e.type === 'dragover');
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);
        if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0]);
    };

    const removeFile = () => {
        setFile(null);
        if (fileInputRef.current) fileInputRef.current.value = '';
    };

    const toggleFix = useCallback((idx) => {
        setFixedSet(prev => {
            const next = new Set(prev);
            next.has(idx) ? next.delete(idx) : next.add(idx);
            return next;
        });
    }, []);

    const handleExecuteScan = async () => {
        if (!permissionGranted) return;
        if (scanMode === 'file' && !file) { setError('Please upload a configuration file first.'); return; }
        if (scanMode !== 'file' && !target.trim()) { setError('Please enter a target URL/IP.'); return; }

        setLoading(true);
        setResults(null);
        setError(null);
        setFixedSet(new Set());
        setAriaAnalysis('');

        try {
            if (scanMode === 'file') {
                const formData = new FormData();
                formData.append('file', file);
                const { data } = await axios.post('/fix_config', formData, {
                    headers: { 'Content-Type': 'multipart/form-data' },
                    withCredentials: true,
                    timeout: 480000,
                });
                if (data.findings || data.fixed_config) {
                    setResults(data);
                } else {
                    setError('No issues found in the uploaded configuration file.');
                }
            } else {
                const { data } = await axios.post(
                    '/scan_server',
                    { target: target.trim(), deep: scanMode === 'full' },
                    { headers: { 'Content-Type': 'application/json' }, withCredentials: true, timeout: 480000 },
                );
                if (data.findings?.length > 0) {
                    setResults(data);
                } else {
                    setError('No configuration vulnerabilities discovered on target.');
                }
            }
        } catch (e) {
            setError(`Scan error: ${e.response?.data?.error || e.message}`);
        } finally {
            setLoading(false);
        }
    };

    const analyzeWithAria = async () => {
        if (!results?.findings?.length) return;
        setAnalyzing(true);
        setAriaAnalysis('');
        try {
            const { data } = await axios.post('/api/ai/analyze', {
                findings: results.findings,
                scan_type: 'apache',
            }, { withCredentials: true });
            setAriaAnalysis(data.analysis || data.response || 'No analysis returned.');
        } catch (e) {
            setAriaAnalysis('ARIA analysis unavailable: ' + (e.response?.data?.error || e.message));
        } finally {
            setAnalyzing(false);
        }
    };

    const handleDownloadReport = () => {
        if (!results) return;
        const json = buildJsonReport(results, scanMode, target, file?.name);
        downloadBlob(json, 'cybrain-security-report.json', 'application/json');
    };

    const handleDownloadFixedConfig = () => {
        if (!results?.fixed_config) return;
        downloadBlob(results.fixed_config, 'fixed_config.conf');
    };

    const sortedFindings = [...(results?.findings || [])].sort(
        (a, b) => (SEV_ORDER[(a.severity || 'INFO').toUpperCase()] ?? 4) - (SEV_ORDER[(b.severity || 'INFO').toUpperCase()] ?? 4)
    );

    const getSevCount = (sev) => sortedFindings.filter(f => (f.severity || '').toUpperCase() === sev).length;
    const isScanDisabled = loading || !permissionGranted || (scanMode === 'file' ? !file : !target.trim());

    return (
        <div className="animate-in fade-in duration-500">
            {/* Header */}
            <div className="mb-8">
                <Link to="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Overview
                </Link>
                <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                            <FileSearch className="w-8 h-8 text-primary-500" />
                            Server Config Audit
                        </h1>
                        <p className="text-slate-500 dark:text-slate-400 mt-1 text-sm max-w-xl">
                            Upload your server configuration for internal white-box analysis, or probe a live server externally.
                        </p>
                    </div>
                    {results && (
                        <div className="flex items-center gap-2 flex-wrap">
                            <button
                                onClick={handleDownloadReport}
                                className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-primary-400 dark:hover:border-primary-500 rounded-xl text-sm font-semibold transition-all shadow-sm hover:shadow"
                            >
                                <ClipboardList className="w-4 h-4 text-primary-500" /> Download Report
                            </button>
                            {results.fixed_config && (
                                <button
                                    onClick={handleDownloadFixedConfig}
                                    className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-xl text-sm font-semibold transition-all shadow-md shadow-green-500/20"
                                >
                                    <FileDown className="w-4 h-4" /> Download Fixed Config
                                </button>
                            )}
                        </div>
                    )}
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                {/* Left: Controls */}
                <div className="lg:col-span-4 space-y-5">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm">

                        {/* Scan modes */}
                        <div className="space-y-2.5 mb-5">
                            <label className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Audit Mode</label>
                            {scanModes.map(mode => {
                                const Icon = mode.icon;
                                return (
                                    <button
                                        key={mode.id}
                                        onClick={() => setScanMode(mode.id)}
                                        className={`w-full p-3.5 rounded-xl border text-left transition-all flex items-start gap-3 ${
                                            scanMode === mode.id
                                                ? 'border-primary-500 bg-primary-50 dark:bg-primary-500/10 ring-1 ring-primary-500'
                                                : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                                        }`}
                                    >
                                        <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${scanMode === mode.id ? 'text-primary-600 dark:text-primary-400' : 'text-slate-400'}`} />
                                        <div>
                                            <div className={`text-sm font-semibold ${scanMode === mode.id ? 'text-primary-700 dark:text-primary-300' : 'text-slate-700 dark:text-slate-300'}`}>
                                                {mode.label}
                                            </div>
                                            <div className="text-xs text-slate-500 mt-0.5">{mode.desc}</div>
                                        </div>
                                    </button>
                                );
                            })}
                        </div>

                        {/* File upload or URL input */}
                        {scanMode === 'file' ? (
                            <div className="mb-5">
                                <label className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 block">
                                    Configuration File
                                </label>
                                {!file ? (
                                    <div
                                        onDragEnter={handleDrag} onDragLeave={handleDrag}
                                        onDragOver={handleDrag} onDrop={handleDrop}
                                        onClick={() => fileInputRef.current?.click()}
                                        className={`border-2 border-dashed rounded-xl p-7 text-center cursor-pointer transition-all ${
                                            isDragging
                                                ? 'border-primary-500 bg-primary-50 dark:bg-primary-500/10'
                                                : 'border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                                        }`}
                                    >
                                        <input ref={fileInputRef} type="file" className="hidden" accept=".conf,.txt,.cfg" onChange={e => e.target.files?.[0] && setFile(e.target.files[0])} />
                                        <UploadCloud className={`w-9 h-9 mx-auto mb-2.5 ${isDragging ? 'text-primary-500' : 'text-slate-400'}`} />
                                        <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">Drop config file here</p>
                                        <p className="text-xs text-slate-400 mt-1">.conf · .cfg · .txt</p>
                                    </div>
                                ) : (
                                    <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-3.5 border border-slate-200 dark:border-slate-700 flex items-center justify-between">
                                        <div className="flex items-center gap-3 overflow-hidden">
                                            <div className="w-9 h-9 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center flex-shrink-0">
                                                <FileText className="w-4 h-4 text-primary-600 dark:text-primary-400" />
                                            </div>
                                            <div className="overflow-hidden">
                                                <p className="text-sm font-semibold text-slate-900 dark:text-white truncate">{file.name}</p>
                                                <p className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB</p>
                                            </div>
                                        </div>
                                        <button onClick={e => { e.stopPropagation(); removeFile(); }} className="p-1.5 text-slate-400 hover:text-red-500 transition-colors">
                                            <X className="w-4 h-4" />
                                        </button>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <div className="space-y-1.5 mb-5">
                                <label className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Target Hostname / IP</label>
                                <input
                                    value={target}
                                    onChange={e => setTarget(e.target.value)}
                                    onKeyDown={e => e.key === 'Enter' && handleExecuteScan()}
                                    placeholder="http://example.com or 192.168.1.1"
                                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2.5 text-slate-900 dark:text-white placeholder-slate-400 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 transition-shadow"
                                />
                            </div>
                        )}

                        {/* Authorization checkbox */}
                        <div className="mb-5 p-3.5 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700/50">
                            <label className="flex items-start gap-3 cursor-pointer select-none">
                                <input
                                    type="checkbox"
                                    checked={permissionGranted}
                                    onChange={e => setPermissionGranted(e.target.checked)}
                                    className="mt-0.5 w-4 h-4 text-primary-600 rounded border-slate-300 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-900"
                                />
                                <span className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                                    I confirm I am authorized to audit this system or own the configuration file being uploaded.
                                </span>
                            </label>
                        </div>

                        <button
                            onClick={handleExecuteScan}
                            disabled={isScanDisabled}
                            className={`w-full py-3 px-4 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 ${
                                isScanDisabled
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-400 cursor-not-allowed'
                                    : 'bg-primary-600 hover:bg-primary-700 text-white shadow-lg shadow-primary-500/20'
                            }`}
                        >
                            {loading ? (
                                <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Auditing…</>
                            ) : (
                                <> Start Audit <ChevronRight className="w-4 h-4" /></>
                            )}
                        </button>
                    </div>

                    {/* Quick legend */}
                    {results && (
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 shadow-sm">
                            <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-3">Severity Breakdown</p>
                            <div className="space-y-2">
                                {['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(sev => {
                                    const cnt = getSevCount(sev);
                                    const styles = SEV_STYLES[sev];
                                    return (
                                        <div key={sev} className="flex items-center justify-between">
                                            <div className="flex items-center gap-2">
                                                <div className={`w-2 h-2 rounded-full ${styles.dot}`} />
                                                <span className="text-xs font-medium text-slate-600 dark:text-slate-400">{sev}</span>
                                            </div>
                                            <span className={`text-xs font-bold px-2 py-0.5 rounded border ${styles.badge}`}>{cnt}</span>
                                        </div>
                                    );
                                })}
                            </div>
                            <div className="mt-3 pt-3 border-t border-slate-100 dark:border-slate-800 flex justify-between items-center text-xs text-slate-500">
                                <span>{fixedSet.size} of {sortedFindings.length} marked fixed</span>
                                {fixedSet.size > 0 && (
                                    <button onClick={() => setFixedSet(new Set())} className="text-primary-500 hover:underline">Clear all</button>
                                )}
                            </div>
                        </div>
                    )}
                </div>

                {/* Right: Results */}
                <div className="lg:col-span-8">
                    {error && (
                        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-4 rounded-xl text-sm font-medium flex items-center gap-3 mb-6">
                            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    <AnimatePresence mode="wait">
                        {results ? (
                            <motion.div key="results" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-5">

                                {/* ARIA analysis */}
                                <div className="bg-purple-50 dark:bg-purple-500/5 border border-purple-200 dark:border-purple-500/20 rounded-xl p-5 shadow-sm">
                                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
                                        <div>
                                            <h3 className="text-sm font-bold text-purple-700 dark:text-purple-400 flex items-center gap-2">
                                                <span className="text-base">✦</span> ARIA AI Analysis
                                            </h3>
                                            <p className="text-xs text-purple-600/70 dark:text-purple-400/70 mt-0.5">AI-powered configuration risk assessment.</p>
                                        </div>
                                        <button
                                            onClick={analyzeWithAria}
                                            disabled={analyzing}
                                            className="px-4 py-2 bg-purple-100 dark:bg-purple-500/20 text-purple-700 dark:text-purple-300 rounded-lg text-xs font-semibold hover:bg-purple-200 dark:hover:bg-purple-500/30 transition-colors disabled:opacity-50 whitespace-nowrap"
                                        >
                                            {analyzing ? 'Analyzing…' : 'Analyze with ARIA'}
                                        </button>
                                    </div>
                                    {ariaAnalysis && (
                                        <div className="bg-white dark:bg-slate-950 border border-purple-100 dark:border-purple-500/10 rounded-lg p-4">
                                            <pre className="text-xs text-slate-700 dark:text-slate-300 font-mono leading-relaxed whitespace-pre-wrap max-h-52 overflow-y-auto custom-scrollbar">
                                                {ariaAnalysis}
                                            </pre>
                                        </div>
                                    )}
                                </div>

                                {/* Findings list */}
                                {sortedFindings.length > 0 && (
                                    <div className="space-y-2.5">
                                        <div className="flex items-center justify-between px-1">
                                            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
                                                {sortedFindings.length} Finding{sortedFindings.length !== 1 ? 's' : ''} — click to expand
                                            </h3>
                                            <div className="flex items-center gap-1.5 text-xs text-slate-400">
                                                <ToggleRight className="w-3.5 h-3.5" />
                                                Toggle to mark fixed
                                            </div>
                                        </div>
                                        {sortedFindings.map((finding, idx) => (
                                            <FindingCard
                                                key={idx}
                                                finding={finding}
                                                index={idx}
                                                isFixed={fixedSet.has(idx)}
                                                onToggleFix={() => toggleFix(idx)}
                                            />
                                        ))}
                                    </div>
                                )}

                                {/* Fixed config preview */}
                                {results.fixed_config && (
                                    <div className="space-y-2 mt-4">
                                        <div className="flex items-center justify-between px-1">
                                            <h3 className="text-xs font-semibold text-green-600 dark:text-green-400 uppercase tracking-wider flex items-center gap-1.5">
                                                <CheckCircle className="w-3.5 h-3.5" /> Remediated Configuration
                                            </h3>
                                            <button
                                                onClick={handleDownloadFixedConfig}
                                                className="flex items-center gap-1.5 text-xs font-semibold text-green-600 dark:text-green-400 hover:underline"
                                            >
                                                <Download className="w-3.5 h-3.5" /> Download
                                            </button>
                                        </div>
                                        <div className="bg-slate-900 rounded-xl overflow-hidden border border-slate-700">
                                            <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-800/50">
                                                <span className="text-xs font-mono text-slate-400">fixed_config.conf</span>
                                                <span className="text-[10px] text-green-400 font-mono">0 vulnerabilities</span>
                                            </div>
                                            <pre className="text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-72 p-4 custom-scrollbar">
                                                {results.fixed_config}
                                            </pre>
                                        </div>
                                    </div>
                                )}

                                {/* Bottom download bar */}
                                <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex flex-wrap gap-3 justify-end">
                                    <button
                                        onClick={handleDownloadReport}
                                        className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-primary-400 rounded-lg text-sm font-medium transition-all"
                                    >
                                        <ClipboardList className="w-4 h-4" /> Download Report
                                    </button>
                                    {results.fixed_config && (
                                        <button
                                            onClick={handleDownloadFixedConfig}
                                            className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg text-sm font-medium transition-all"
                                        >
                                            <FileDown className="w-4 h-4" /> Download Fixed Config
                                        </button>
                                    )}
                                </div>
                            </motion.div>
                        ) : loading ? (
                            <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white/50 dark:bg-slate-900/50">
                                <Activity className="w-12 h-12 text-primary-500 animate-pulse mb-5" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Auditing Configuration</h3>
                                <p className="text-sm text-slate-500 text-center max-w-sm">Analysing directives and identifying security weaknesses…</p>
                            </motion.div>
                        ) : (
                            <div className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white dark:bg-slate-900">
                                <FileSearch className="w-16 h-16 text-slate-200 dark:text-slate-700 mb-5" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Ready to Audit</h3>
                                <p className="text-sm text-slate-500 text-center max-w-xs">
                                    Upload a configuration file or enter a target URL and confirm authorization to begin.
                                </p>
                            </div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
};

export default ApacheScanPage;
