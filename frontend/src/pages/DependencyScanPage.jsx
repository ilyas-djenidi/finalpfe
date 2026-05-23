import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { 
    Activity, ArrowLeft, PackageSearch, UploadCloud, 
    FileText, X, AlertTriangle, ChevronRight, Download
} from 'lucide-react';

const SEVERITY_COLORS = {
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20',
    HIGH:     'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
    MEDIUM:   'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
    LOW:      'bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border-green-200 dark:border-green-500/20',
    INFO:     'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
};

const DependencyScanPage = () => {
    const [file, setFile] = useState(null);
    const [isDragging, setIsDragging] = useState(false);
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const fileInputRef = useRef(null);

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
        if (!file) return;

        setLoading(true);
        setResults(null);
        setError(null);

        const formData = new FormData();
        formData.append('file', file);

        try {
            const { data } = await axios.post(
                '/scan_dependencies',
                formData,
                { 
                    headers: { 'Content-Type': 'multipart/form-data' }, 
                    withCredentials: true, 
                    timeout: 480000 
                }
            );
            if (data.findings && data.findings.length > 0) setResults(data);
            else setError('No vulnerable dependencies found.');
        } catch (e) {
            setError(`Error: ${e.response?.data?.error || e.message}`);
        } finally {
            setLoading(false);
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
                        <PackageSearch className="w-8 h-8 text-primary-500" />
                        Dependency Scanner
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm max-w-2xl">
                        Audit project dependencies (package.json, requirements.txt, etc.) for known CVEs.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <div className="lg:col-span-4 space-y-6">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                        
                        <div className="mb-6">
                            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3 block">Upload Manifest File</label>
                            
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
                                        accept=".json,.txt,.toml"
                                        onChange={handleFileSelect}
                                    />
                                    <UploadCloud className={`w-10 h-10 mx-auto mb-3 ${isDragging ? 'text-primary-500' : 'text-slate-400'}`} />
                                    <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                                        Drop your package.json or requirements.txt here
                                    </p>
                                    <p className="text-xs text-slate-500 mt-1">or click to browse files</p>
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

                        <button
                            onClick={handleExecuteScan}
                            disabled={loading || !file}
                            className={`w-full py-3.5 px-4 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 ${
                                loading || !file
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-400 cursor-not-allowed'
                                    : 'bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20'
                            }`}
                        >
                            {loading ? (
                                <>
                                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                    Analyzing...
                                </>
                            ) : (
                                <>Audit Dependencies <ChevronRight className="w-4 h-4" /></>
                            )}
                        </button>
                    </div>
                </div>

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
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Analyzing Dependencies</h3>
                                <p className="text-sm text-slate-500 text-center max-w-sm px-4">Cross-referencing package versions against CVE databases.</p>
                            </motion.div>
                        ) : (
                            <div className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white dark:bg-slate-900">
                                <PackageSearch className="w-16 h-16 text-slate-200 dark:text-slate-700 mb-6" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Awaiting File Upload</h3>
                                <p className="text-sm text-slate-500 text-center max-w-xs">Upload a manifest file to detect known vulnerabilities in project dependencies.</p>
                            </div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
};

export default DependencyScanPage;
