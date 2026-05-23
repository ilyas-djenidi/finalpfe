import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { 
    Activity, ArrowLeft, Settings, Shield, 
    AlertTriangle, Terminal, ChevronRight, Download,
    FileSearch, UploadCloud, FileText, X
} from 'lucide-react';

const SEVERITY_COLORS = {
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20',
    HIGH:     'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
    MEDIUM:   'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
    LOW:      'bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border-green-200 dark:border-green-500/20',
    INFO:     'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
};

const ApacheScanPage = () => {
    const [target, setTarget] = useState('');
    const [scanMode, setScanMode] = useState('full');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const [permissionGranted, setPermissionGranted] = useState(false);

    // File Upload State
    const [file, setFile] = useState(null);
    const [isDragging, setIsDragging] = useState(false);
    const fileInputRef = useRef(null);

    const scanModes = [
        { id: 'full', label: 'Deep Audit', desc: 'Complete external config vulnerability check', icon: Shield },
        { id: 'headers', label: 'Headers Audit', desc: 'Check missing security headers externally', icon: Terminal },
        { id: 'file', label: 'File Analysis (White-Box)', desc: 'Upload httpd.conf to find misconfigurations and get fixed config', icon: FileSearch }
    ];

    const handleDrag = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === "dragenter" || e.type === "dragover") setIsDragging(true);
        else if (e.type === "dragleave") setIsDragging(false);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setFile(e.dataTransfer.files[0]);
        }
    };

    const handleFileSelect = (e) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
        }
    };

    const removeFile = () => {
        setFile(null);
        if (fileInputRef.current) fileInputRef.current.value = "";
    };

    const handleExecuteScan = async () => {
        if (!permissionGranted) return;
        
        if (scanMode === 'file' && !file) {
            setError("Please upload a configuration file first.");
            return;
        } else if (scanMode !== 'file' && !target.trim()) {
            setError("Please enter a target URL/IP.");
            return;
        }

        setLoading(true);
        setResults(null);
        setError(null);

        try {
            if (scanMode === 'file') {
                const formData = new FormData();
                formData.append('file', file);
                
                const { data } = await axios.post('/fix_config', formData, {
                    headers: { 'Content-Type': 'multipart/form-data' },
                    withCredentials: true,
                    timeout: 480000
                });
                
                if (data.findings || data.fixed_config) {
                    setResults(data);
                } else {
                    setError('No issues found in the uploaded configuration file.');
                }
            } else {
                const scanTarget = target.trim();
                const { data } = await axios.post(
                    '/scan_server',
                    { target: scanTarget, deep: scanMode === 'full' },
                    { headers: { 'Content-Type': 'application/json' }, withCredentials: true, timeout: 480000 }
                );
                
                if (data.findings && data.findings.length > 0) {
                    setResults(data);
                } else {
                    setError('No configuration vulnerabilities discovered on target.');
                }
            }
        } catch (e) {
            setError(`Error: ${e.response?.data?.error || e.message}`);
        } finally {
            setLoading(false);
        }
    };

    const getSeverityCount = (sev) => results?.findings?.filter(f => f.severity === sev).length || 0;
    
    // Determine if button should be disabled
    const isScanDisabled = loading || !permissionGranted || (scanMode === 'file' ? !file : !target.trim());

    return (
        <div className="animate-in fade-in duration-500">
            {/* Header Section */}
            <div className="mb-8">
                <Link to="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Dashboard
                </Link>
                <div>
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Settings className="w-8 h-8 text-primary-500" />
                        Config Scanner
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm max-w-2xl">
                        Audit server configurations externally or upload your httpd.conf for an internal white-box review.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                
                {/* Left Column: Input & Modes */}
                <div className="lg:col-span-4 space-y-6">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                        
                        <div className="space-y-3 mb-6">
                            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Operational Mode</label>
                            {scanModes.map(mode => {
                                const Icon = mode.icon;
                                return (
                                    <button
                                        key={mode.id}
                                        onClick={() => setScanMode(mode.id)}
                                        className={`w-full p-4 rounded-xl border text-left transition-all duration-200 flex items-start gap-4 ${
                                            scanMode === mode.id
                                                ? 'border-primary-500 bg-primary-50 dark:bg-primary-500/10 ring-1 ring-primary-500'
                                                : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                                        }`}
                                    >
                                        <Icon className={`w-5 h-5 mt-0.5 flex-shrink-0 ${scanMode === mode.id ? 'text-primary-600 dark:text-primary-400' : 'text-slate-400'}`} />
                                        <div>
                                            <div className={`text-sm font-semibold mb-0.5 ${scanMode === mode.id ? 'text-primary-700 dark:text-primary-300' : 'text-slate-700 dark:text-slate-300'}`}>
                                                {mode.label}
                                            </div>
                                            <div className="text-xs text-slate-500 dark:text-slate-400">{mode.desc}</div>
                                        </div>
                                    </button>
                                );
                            })}
                        </div>

                        {scanMode === 'file' ? (
                            <div className="mb-6">
                                <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3 block">Upload Config File</label>
                                
                                {!file ? (
                                    <div
                                        onDragEnter={handleDrag}
                                        onDragLeave={handleDrag}
                                        onDragOver={handleDrag}
                                        onDrop={handleDrop}
                                        onClick={() => fileInputRef.current?.click()}
                                        className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
                                            isDragging 
                                                ? 'border-primary-500 bg-primary-50 dark:bg-primary-500/10' 
                                                : 'border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                                        }`}
                                    >
                                        <input
                                            ref={fileInputRef}
                                            type="file"
                                            className="hidden"
                                            accept=".conf,.txt"
                                            onChange={handleFileSelect}
                                        />
                                        <UploadCloud className={`w-10 h-10 mx-auto mb-3 ${isDragging ? 'text-primary-500' : 'text-slate-400'}`} />
                                        <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                                            Drop httpd.conf or .txt here
                                        </p>
                                    </div>
                                ) : (
                                    <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-4 border border-slate-200 dark:border-slate-700 flex items-center justify-between">
                                        <div className="flex items-center gap-3 overflow-hidden">
                                            <div className="w-10 h-10 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center flex-shrink-0">
                                                <FileText className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                                            </div>
                                            <div className="overflow-hidden">
                                                <p className="text-sm font-semibold text-slate-900 dark:text-white truncate">
                                                    {file.name}
                                                </p>
                                                <p className="text-xs text-slate-500">
                                                    {(file.size / 1024).toFixed(1)} KB
                                                </p>
                                            </div>
                                        </div>
                                        <button 
                                            onClick={(e) => { e.stopPropagation(); removeFile(); }}
                                            className="p-2 text-slate-400 hover:text-red-500 transition-colors"
                                        >
                                            <X className="w-5 h-5" />
                                        </button>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <div className="space-y-1.5 mb-6">
                                <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Target Hostname / IP</label>
                                <input 
                                    value={target}
                                    onChange={e => setTarget(e.target.value)}
                                    onKeyDown={e => e.key === 'Enter' && handleExecuteScan()}
                                    placeholder="http://example.com"
                                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white placeholder-slate-400 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 transition-shadow"
                                />
                            </div>
                        )}

                        <div className="mb-6 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700/50">
                            <label className="flex items-start gap-3 cursor-pointer select-none">
                                <input 
                                    type="checkbox" 
                                    checked={permissionGranted}
                                    onChange={e => setPermissionGranted(e.target.checked)}
                                    className="mt-0.5 w-4 h-4 text-primary-600 rounded border-slate-300 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-900"
                                />
                                <span className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                                    I authorize Cybrain to perform a configuration audit on the specified target.
                                </span>
                            </label>
                        </div>

                        <button
                            onClick={handleExecuteScan}
                            disabled={isScanDisabled}
                            className={`w-full py-3.5 px-4 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 ${
                                isScanDisabled
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-400 cursor-not-allowed'
                                    : 'bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20'
                            }`}
                        >
                            {loading ? (
                                <>
                                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                    Auditing Config...
                                </>
                            ) : (
                                <>Start Config Audit <ChevronRight className="w-4 h-4" /></>
                            )}
                        </button>
                    </div>
                </div>

                {/* Right Column: Results */}
                <div className="lg:col-span-8">
                    {error && (
                        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-4 rounded-xl text-sm font-medium flex items-center gap-3 mb-6">
                            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    <AnimatePresence mode="wait">
                        {results ? (
                            <motion.div initial={{ opacity:0, y:10 }} animate={{ opacity:1, y:0 }} className="space-y-6">
                                
                                {/* Severity Counters */}
                                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                    {[
                                        { l: 'CRITICAL', c: 'red', v: getSeverityCount('CRITICAL') },
                                        { l: 'HIGH', c: 'orange', v: getSeverityCount('HIGH') },
                                        { l: 'MEDIUM', c: 'yellow', v: getSeverityCount('MEDIUM') },
                                        { l: 'LOW', c: 'green', v: getSeverityCount('LOW') },
                                        { l: 'INFO', c: 'blue', v: getSeverityCount('INFO') },
                                    ].map(s => (
                                        <div key={s.l} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-center shadow-sm">
                                            <div className={`text-2xl font-bold font-mono text-${s.c}-600 dark:text-${s.c}-400 mb-1`}>{s.v}</div>
                                            <div className="text-[10px] font-semibold text-slate-500 tracking-wider uppercase">{s.l}</div>
                                        </div>
                                    ))}
                                </div>

                                {/* Findings */}
                                {(results.findings || []).length > 0 && (
                                    <div className="space-y-3">
                                        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider px-1">Findings Log</h3>
                                        {results.findings.map((finding, idx) => (
                                            <div key={idx} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm hover:shadow-md transition-shadow">
                                                <div className="flex flex-wrap items-start justify-between gap-4 mb-3">
                                                    <div className="flex items-center gap-3">
                                                        <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold tracking-wider border ${SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.INFO}`}>
                                                            {finding.severity}
                                                        </span>
                                                        <h4 className="text-sm font-bold text-slate-900 dark:text-white">{finding.code || finding.id}</h4>
                                                    </div>
                                                </div>
                                                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed mb-3">
                                                    {finding.message || finding.desc}
                                                </p>
                                                {finding.fix && (
                                                    <div className="mt-3 p-3 bg-green-50 dark:bg-green-900/10 rounded border border-green-200 dark:border-green-800/30">
                                                        <div className="text-xs font-semibold text-green-700 dark:text-green-500 mb-1">Recommended Fix:</div>
                                                        <code className="text-xs text-green-800 dark:text-green-400 break-all">{finding.fix}</code>
                                                    </div>
                                                )}
                                                {finding.evidence && (
                                                    <div className="mt-2 p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                                                        <div className="text-xs font-semibold text-slate-500 mb-1">Evidence:</div>
                                                        <code className="text-xs text-slate-700 dark:text-slate-400 break-all">{finding.evidence}</code>
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {/* Fixed Config Block (Only for File mode) */}
                                {results.fixed_config && (
                                    <div className="space-y-3 mt-8">
                                        <h3 className="text-xs font-semibold text-primary-600 dark:text-primary-400 uppercase tracking-wider px-1">Remediated Configuration File</h3>
                                        <div className="bg-slate-900 rounded-xl p-5 shadow-sm overflow-hidden">
                                            <div className="flex justify-between items-center mb-3 border-b border-slate-800 pb-2">
                                                <span className="text-xs font-mono text-slate-400">fixed_httpd.conf</span>
                                                <button 
                                                    onClick={() => {
                                                        const blob = new Blob([results.fixed_config], { type: 'text/plain' });
                                                        const url = URL.createObjectURL(blob);
                                                        const a = document.createElement('a');
                                                        a.href = url;
                                                        a.download = 'fixed_httpd.conf';
                                                        a.click();
                                                        URL.revokeObjectURL(url);
                                                    }}
                                                    className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1 transition-colors"
                                                >
                                                    <Download className="w-3 h-3" /> Download Fix
                                                </button>
                                            </div>
                                            <pre className="text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-96 custom-scrollbar">
                                                {results.fixed_config}
                                            </pre>
                                        </div>
                                    </div>
                                )}
                                
                                <div className="pt-6 border-t border-slate-200 dark:border-slate-800 flex justify-end">
                                    <button className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
                                        <Download className="w-4 h-4" /> Export Report
                                    </button>
                                </div>
                            </motion.div>
                        ) : loading ? (
                            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white/50 dark:bg-slate-900/50">
                                <Activity className="w-12 h-12 text-primary-500 animate-pulse mb-6" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Auditing Configuration</h3>
                                <p className="text-sm text-slate-500 text-center max-w-sm px-4">Analyzing configurations and identifying security weaknesses.</p>
                            </motion.div>
                        ) : (
                            <div className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white dark:bg-slate-900">
                                <Settings className="w-16 h-16 text-slate-200 dark:text-slate-700 mb-6" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Awaiting Target</h3>
                                <p className="text-sm text-slate-500 text-center max-w-xs">Input a target URL or upload a config file to begin automated audit.</p>
                            </div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
};

export default ApacheScanPage;
