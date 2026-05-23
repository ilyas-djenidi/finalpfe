import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { Link } from 'react-router-dom';
import {
    Activity, ArrowLeft, Code, Shield,
    AlertTriangle, Terminal, ChevronRight, Download, Upload, FileArchive

} from 'lucide-react';

const SEVERITY_COLORS = {
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20',
    HIGH:     'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
    MEDIUM:   'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
    LOW:      'bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border-green-200 dark:border-green-500/20',
    INFO:     'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
};

const CodeScanPage = () => {
    const [file,            setFile]            = useState(null);
    const [loading,         setLoading]         = useState(false);
    const [results,         setResults]         = useState(null);
    const [error,           setError]           = useState(null);
    const [permissionGranted, setPermissionGranted] = useState(false);
    const [dragOver,        setDragOver]        = useState(false);
    const [ariaAnalysis,    setAriaAnalysis]    = useState('');
    const [analyzing,       setAnalyzing]       = useState(false);
    const fileRef = useRef();

    const handleFile = (f) => {
        if (!f) return;
        if (!f.name.endsWith('.zip')) { setError('Only .zip archives are supported.'); return; }
        if (f.size > 10 * 1024 * 1024) { setError('File must be ≤ 10 MB.'); return; }
        setFile(f); setError(null);
    };

    const handleDrop = (e) => {
        e.preventDefault(); setDragOver(false);
        handleFile(e.dataTransfer.files?.[0]);
    };

    const handleExecuteScan = async () => {
        if (!file || !permissionGranted) return;
        setLoading(true); setResults(null); setError(null);
        try {
            const form = new FormData();
            form.append('file', file);
            const { data } = await axios.post('/analyze_code', form, {
                withCredentials: true,
                timeout: 480000,
            });
            if (data.findings?.length > 0) setResults(data);
            else setError('No vulnerabilities discovered in the uploaded archive.');
        } catch (e) {
            setError(`Error: ${e.response?.data?.error || e.message}`);
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
                scan_type: 'sast',
            }, { withCredentials: true });
            setAriaAnalysis(data.analysis || data.response || 'No analysis returned.');
        } catch (e) {
            setAriaAnalysis('ARIA analysis unavailable: ' + (e.response?.data?.error || e.message));
        } finally {
            setAnalyzing(false);
        }
    };

    const getSeverityCount = (sev) => results?.findings?.filter(f => f.severity === sev).length || 0;

    return (
        <div className="animate-in fade-in duration-500">
            <div className="mb-8">
                <Link to="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Dashboard
                </Link>
                <div>
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Code className="w-8 h-8 text-primary-500" />
                        Code Analyzer (SAST)
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm max-w-2xl">
                        Upload a .zip of your source code. Bandit + Semgrep + Gitleaks run in parallel to find vulnerabilities, secrets, and misconfigurations.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <div className="lg:col-span-4 space-y-6">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">

                        {/* Drop zone */}
                        <div
                            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                            onDragLeave={() => setDragOver(false)}
                            onDrop={handleDrop}
                            onClick={() => fileRef.current?.click()}
                            className={`mb-6 border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200 ${
                                dragOver
                                    ? 'border-primary-500 bg-primary-50 dark:bg-primary-500/10'
                                    : file
                                        ? 'border-green-400 bg-green-50 dark:bg-green-500/10'
                                        : 'border-slate-300 dark:border-slate-700 hover:border-primary-400 dark:hover:border-primary-600'
                            }`}
                        >
                            <input
                                ref={fileRef}
                                type="file"
                                accept=".zip"
                                className="hidden"
                                onChange={e => handleFile(e.target.files?.[0])}
                            />
                            {file ? (
                                <>
                                    <FileArchive className="w-10 h-10 mx-auto mb-3 text-green-500" />
                                    <p className="text-sm font-semibold text-green-700 dark:text-green-400 truncate">{file.name}</p>
                                    <p className="text-xs text-slate-500 mt-1">{(file.size / 1024).toFixed(0)} KB — click to change</p>
                                </>
                            ) : (
                                <>
                                    <Upload className="w-10 h-10 mx-auto mb-3 text-slate-400" />
                                    <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">Drop .zip archive here</p>
                                    <p className="text-xs text-slate-500 mt-1">or click to browse · max 10 MB</p>
                                </>
                            )}
                        </div>

                        <div className="mb-6 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700/50 rounded-xl p-4 text-xs text-slate-500 dark:text-slate-400 space-y-1">
                            <p className="font-semibold text-slate-600 dark:text-slate-300 mb-2">Supported languages</p>
                            <p>Python · JavaScript/TypeScript · Go · Ruby · Java · C/C++ · PHP · C#</p>
                            <p className="mt-2 font-semibold text-slate-600 dark:text-slate-300">Engines</p>
                            <p>Bandit · Semgrep (OWASP Top 10) · Gitleaks (secrets)</p>
                        </div>

                        <div className="mb-6 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700/50">
                            <label className="flex items-start gap-3 cursor-pointer select-none">
                                <input
                                    type="checkbox"
                                    checked={permissionGranted}
                                    onChange={e => setPermissionGranted(e.target.checked)}
                                    className="mt-0.5 w-4 h-4 text-primary-600 rounded border-slate-300 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-900"
                                />
                                <span className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                                    I authorize Cybrain to perform a static security analysis on the uploaded source code.
                                </span>
                            </label>
                        </div>

                        <button
                            onClick={handleExecuteScan}
                            disabled={loading || !file || !permissionGranted}
                            className={`w-full py-3.5 px-4 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 ${
                                loading || !file || !permissionGranted
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-400 cursor-not-allowed'
                                    : 'bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20'
                            }`}
                        >
                            {loading ? (
                                <>
                                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                    Analyzing Code…
                                </>
                            ) : (
                                <>Start SAST Scan <ChevronRight className="w-4 h-4" /></>
                            )}
                        </button>
                    </div>
                </div>

                {/* Results column */}
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
                                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                    {['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map((sev, i) => (
                                        <div key={sev} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-center shadow-sm">
                                            <div className={`text-2xl font-bold font-mono mb-1 ${['text-red-600 dark:text-red-400','text-orange-600 dark:text-orange-400','text-yellow-600 dark:text-yellow-400','text-green-600 dark:text-green-400','text-blue-600 dark:text-blue-400'][i]}`}>
                                                {getSeverityCount(sev)}
                                            </div>
                                            <div className="text-[10px] font-semibold text-slate-500 tracking-wider uppercase">{sev}</div>
                                        </div>
                                    ))}
                                </div>

                                {/* ARIA Analysis Card */}
                                <div className="bg-purple-50 dark:bg-purple-500/5 border border-purple-200 dark:border-purple-500/20 rounded-xl p-6 shadow-sm">
                                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
                                        <div>
                                            <h3 className="text-sm font-bold text-purple-700 dark:text-purple-400 flex items-center gap-2">
                                                <Terminal className="w-4 h-4" /> Analyze with ARIA
                                            </h3>
                                            <p className="text-xs text-purple-600/80 dark:text-purple-400/80 mt-1">AI-powered code vulnerability interpretation.</p>
                                        </div>
                                        <button
                                            onClick={analyzeWithAria}
                                            disabled={analyzing}
                                            className="px-4 py-2 bg-purple-100 dark:bg-purple-500/20 text-purple-700 dark:text-purple-300 rounded-lg text-xs font-semibold hover:bg-purple-200 dark:hover:bg-purple-500/30 transition-colors disabled:opacity-50 whitespace-nowrap"
                                        >
                                            {analyzing ? 'Analyzing...' : 'Analyze with ARIA'}
                                        </button>
                                    </div>
                                    {ariaAnalysis && (
                                        <div className="bg-white dark:bg-slate-950 border border-purple-100 dark:border-purple-500/10 rounded-lg p-4">
                                            <pre className="text-xs text-slate-700 dark:text-slate-300 font-mono leading-relaxed whitespace-pre-wrap max-h-64 overflow-y-auto">
                                                {ariaAnalysis}
                                            </pre>
                                        </div>
                                    )}
                                </div>

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
                                                <div className="text-xs font-mono text-slate-500 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded">
                                                    {finding.file}{finding.line ? `:${finding.line}` : ''}
                                                </div>
                                            </div>
                                            <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">{finding.message || finding.desc}</p>
                                        </div>
                                    ))}
                                </div>

                                <div className="pt-6 border-t border-slate-200 dark:border-slate-800 flex justify-end">
                                    <button className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
                                        <Download className="w-4 h-4" /> Export Report
                                    </button>
                                </div>
                            </motion.div>
                        ) : loading ? (
                            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white/50 dark:bg-slate-900/50">
                                <Activity className="w-12 h-12 text-primary-500 animate-pulse mb-6" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Analyzing Source Code</h3>
                                <p className="text-sm text-slate-500 text-center max-w-sm px-4">Running Bandit, Semgrep, and Gitleaks in parallel. This may take 30–60 seconds.</p>
                            </motion.div>
                        ) : (
                            <div className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white dark:bg-slate-900">
                                <Code className="w-16 h-16 text-slate-200 dark:text-slate-700 mb-6" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Awaiting Archive</h3>
                                <p className="text-sm text-slate-500 text-center max-w-xs">Upload a .zip of your source code to begin static analysis.</p>
                            </div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
};

export default CodeScanPage;
