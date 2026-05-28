import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import securaxLogo from '../assets/securax_logo.png';
import {
    ShieldAlert, Shield, Globe, Server, Code, Network,
    Package, Zap, ChevronRight, CheckCircle, Lock, Eye,
    FileSearch, Activity, ArrowRight, Star, Users
} from 'lucide-react';

const SERVICES = [
    {
        icon: Network,
        title: 'Network Reconnaissance',
        desc: 'Discover open ports, active services, and network topology across your internal and external infrastructure.',
        color: 'from-blue-500/10 to-blue-600/5 border-blue-500/20',
        accent: 'text-blue-400',
        badge: 'Internal · External',
    },
    {
        icon: Globe,
        title: 'Web Application Security',
        desc: 'Identify injection flaws, broken authentication, and sensitive data exposure in your web applications.',
        color: 'from-indigo-500/10 to-indigo-600/5 border-indigo-500/20',
        accent: 'text-indigo-400',
        badge: 'OWASP Top 10',
    },
    {
        icon: Zap,
        title: 'Dynamic Analysis',
        desc: 'Runtime testing that simulates real attacker behaviour — revealing vulnerabilities invisible to static scans.',
        color: 'from-orange-500/10 to-orange-600/5 border-orange-500/20',
        accent: 'text-orange-400',
        badge: 'DAST',
    },
    {
        icon: Code,
        title: 'Code Security Review',
        desc: 'Scan source code for dangerous patterns, hardcoded secrets, insecure dependencies, and logic flaws.',
        color: 'from-purple-500/10 to-purple-600/5 border-purple-500/20',
        accent: 'text-purple-400',
        badge: 'SAST',
    },
    {
        icon: FileSearch,
        title: 'Server Configuration Audit',
        desc: 'Upload your server config file or probe externally — get a clean, patched config file to deploy instantly.',
        color: 'from-teal-500/10 to-teal-600/5 border-teal-500/20',
        accent: 'text-teal-400',
        badge: 'Config · Hardening',
    },
    {
        icon: Package,
        title: 'Dependency Analysis',
        desc: 'Detect outdated or vulnerable third-party packages with CVE references and upgrade paths.',
        color: 'from-yellow-500/10 to-yellow-600/5 border-yellow-500/20',
        accent: 'text-yellow-400',
        badge: 'SCA',
    },
];

const FEATURES = [
    { icon: Shield, text: 'AI-powered ARIA security advisor' },
    { icon: Lock, text: 'Role-based access control' },
    { icon: Eye, text: 'Full audit log trail' },
    { icon: Activity, text: 'Real-time scan progress' },
    { icon: FileSearch, text: 'Auto-generated fix config files' },
    { icon: CheckCircle, text: 'CVE enrichment via NVD' },
];

const STATS = [
    { value: '6+', label: 'Scan Types' },
    { value: 'ARIA', label: 'AI Security Advisor' },
];

function FloatingOrb({ style, className }) {
    return (
        <div
            className={`absolute rounded-full blur-3xl pointer-events-none ${className}`}
            style={style}
        />
    );
}

const LandingPage = () => {
    const [year] = useState(new Date().getFullYear());
    const [scrolled, setScrolled] = useState(false);

    useEffect(() => {
        const handleScroll = () => setScrolled(window.scrollY > 20);
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    return (
        <div className="min-h-screen bg-slate-950 text-white overflow-x-hidden">

            {/* ── Navbar ────────────────────────────────────────────────── */}
            <header className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
                scrolled ? 'bg-slate-950/90 backdrop-blur-md border-b border-white/5 shadow-lg' : ''
            }`}>
                <div className="max-w-7xl mx-auto px-6 lg:px-8 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                        <img src={securaxLogo} alt="securAX Logo" className="w-8 h-8 object-contain" />
                        <span className="font-bold text-lg tracking-tight text-white">securAX</span>
                    </div>
                    <div className="flex items-center gap-3">
                        <Link
                            to="/login"
                            className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
                        >
                            Sign In
                        </Link>
                        <Link
                            to="/register"
                            className="px-5 py-2 text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white rounded-xl transition-all shadow-lg shadow-primary-600/20 hover:shadow-primary-500/30"
                        >
                            Get Started
                        </Link>
                    </div>
                </div>
            </header>

            {/* ── Hero ──────────────────────────────────────────────────── */}
            <section className="relative min-h-screen flex items-center justify-center px-6 pt-16">
                <FloatingOrb className="w-[600px] h-[600px] bg-primary-600/10" style={{ top: '-10%', left: '-15%' }} />
                <FloatingOrb className="w-[400px] h-[400px] bg-cyan-500/8" style={{ top: '20%', right: '-10%' }} />
                <FloatingOrb className="w-[300px] h-[300px] bg-purple-600/8" style={{ bottom: '0', left: '30%' }} />

                <div className="relative z-10 max-w-4xl mx-auto text-center">
                    {/* Badge removed as requested */}

                    <h1 className="text-5xl md:text-7xl font-bold mb-6 leading-tight tracking-tight">
                        <span className="text-white">Secure Your</span>
                        <br />
                        <span className="bg-gradient-to-r from-primary-400 via-cyan-400 to-purple-400 bg-clip-text text-transparent">
                            Infrastructure
                        </span>
                    </h1>

                    <p className="text-lg md:text-xl text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
                        securAX is an AI-powered security assessment platform. Scan networks, web apps,
                        server configs, and code — then let ARIA AI guide you through every fix.
                    </p>

                    <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                        <Link
                            to="/register"
                            className="group flex items-center gap-2 px-8 py-4 bg-primary-600 hover:bg-primary-500 text-white font-semibold rounded-2xl transition-all shadow-2xl shadow-primary-600/30 hover:shadow-primary-500/40 text-sm"
                        >
                            Start Free Assessment
                            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                        </Link>
                        <Link
                            to="/login"
                            className="flex items-center gap-2 px-8 py-4 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 text-white font-semibold rounded-2xl transition-all text-sm backdrop-blur-sm"
                        >
                            Sign In
                            <ChevronRight className="w-4 h-4" />
                        </Link>
                    </div>

                    {/* Stats row */}
                    <div className="mt-16 grid grid-cols-2 gap-4 max-w-md mx-auto">
                        {STATS.map((s, i) => (
                            <div key={i} className="bg-white/[0.03] border border-white/8 rounded-2xl py-4 px-3 backdrop-blur-sm">
                                <div className="text-2xl font-bold text-white mb-1">{s.value}</div>
                                <div className="text-xs text-slate-500">{s.label}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Scroll indicator */}
                <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 text-slate-600 animate-bounce">
                    <div className="w-px h-8 bg-gradient-to-b from-transparent to-slate-700" />
                </div>
            </section>

            {/* ── Services ──────────────────────────────────────────────── */}
            <section className="py-24 px-6">
                <div className="max-w-7xl mx-auto">
                    <div className="text-center mb-16">
                        <p className="text-xs font-semibold text-primary-400 uppercase tracking-widest mb-3">Platform Capabilities</p>
                        <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">Six Layers of Defence</h2>
                        <p className="text-slate-400 max-w-xl mx-auto text-sm leading-relaxed">
                            Every attack vector covered — from perimeter scanning to source code analysis,
                            all in one unified security workspace.
                        </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                        {SERVICES.map((svc, i) => {
                            const Icon = svc.icon;
                            return (
                                <div
                                    key={i}
                                    className={`relative bg-gradient-to-br ${svc.color} border rounded-2xl p-6 group hover:scale-[1.02] transition-all duration-300 hover:shadow-xl hover:shadow-black/20`}
                                >
                                    <div className={`inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest px-2.5 py-1 rounded-full bg-white/5 border border-white/10 mb-4 ${svc.accent}`}>
                                        {svc.badge}
                                    </div>
                                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center mb-4 bg-white/5 border border-white/10 ${svc.accent}`}>
                                        <Icon className="w-5 h-5" />
                                    </div>
                                    <h3 className="text-base font-bold text-white mb-2">{svc.title}</h3>
                                    <p className="text-sm text-slate-400 leading-relaxed">{svc.desc}</p>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </section>

            {/* ── ARIA AI Highlight ─────────────────────────────────────── */}
            <section className="py-20 px-6">
                <div className="max-w-7xl mx-auto">
                    <div className="relative bg-gradient-to-br from-cyan-500/8 to-purple-500/8 border border-white/8 rounded-3xl p-10 md:p-14 overflow-hidden">
                        <FloatingOrb className="w-72 h-72 bg-cyan-500/8" style={{ top: '-30%', right: '-10%' }} />
                        <FloatingOrb className="w-56 h-56 bg-purple-500/8" style={{ bottom: '-20%', left: '-5%' }} />

                        <div className="relative z-10 grid md:grid-cols-2 gap-10 items-center">
                            <div>
                                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold mb-6">
                                    <span className="text-sm">✦</span> ARIA — AI Security Expert
                                </div>
                                <h2 className="text-3xl md:text-4xl font-bold text-white mb-4 leading-tight">
                                    Your AI security<br />
                                    <span className="text-cyan-400">advisor on-demand</span>
                                </h2>
                                <p className="text-slate-400 leading-relaxed mb-8 text-sm">
                                    ARIA understands your scan results and explains every vulnerability in plain English.
                                    Get targeted fix recommendations, code samples, and threat context — instantly.
                                </p>
                                <Link
                                    to="/register"
                                    className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 font-semibold rounded-xl transition-all text-sm"
                                >
                                    Try ARIA Free <ArrowRight className="w-4 h-4" />
                                </Link>
                            </div>

                            {/* Mock chat preview */}
                            <div className="bg-black/40 border border-white/8 rounded-2xl overflow-hidden backdrop-blur-sm">
                                <div className="flex items-center gap-3 px-4 py-3 border-b border-white/5">
                                    <div className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500/30 to-purple-500/30 border border-cyan-500/30 flex items-center justify-center">
                                        <span className="text-cyan-400 text-xs">✦</span>
                                    </div>
                                    <div>
                                        <p className="text-xs font-bold text-white">ARIA</p>
                                        <p className="text-[10px] text-slate-500">securAX AI</p>
                                    </div>
                                    <span className="ml-auto flex items-center gap-1 text-[9px] text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-0.5 rounded-full">
                                        <span className="w-1 h-1 rounded-full bg-green-400" />
                                        Online
                                    </span>
                                </div>
                                <div className="px-4 py-4 space-y-3">
                                    <div className="flex justify-end">
                                        <div className="bg-cyan-500/10 border border-cyan-500/20 text-cyan-100 rounded-2xl rounded-br-sm px-3 py-2 text-xs max-w-[80%]">
                                            What does SQL Injection mean for my app?
                                        </div>
                                    </div>
                                    <div className="flex gap-2">
                                        <div className="w-6 h-6 rounded-full bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 flex items-center justify-center flex-shrink-0 mt-1">
                                            <span className="text-cyan-400 text-[10px]">✦</span>
                                        </div>
                                        <div className="bg-white/[0.04] border border-white/8 rounded-2xl rounded-bl-sm px-3 py-2 text-xs text-slate-300 max-w-[85%] leading-relaxed">
                                            SQL Injection lets an attacker manipulate database queries by inserting malicious SQL code. In your case, the <span className="text-cyan-400 font-mono">login</span> endpoint is vulnerable. Use parameterised queries to fix it.
                                        </div>
                                    </div>
                                </div>
                                <div className="px-4 pb-4">
                                    <div className="bg-black/30 border border-white/8 rounded-xl px-3 py-2.5 flex items-center gap-2">
                                        <span className="text-slate-600 text-xs flex-1">Ask ARIA anything…</span>
                                        <span className="text-cyan-500 text-sm">➤</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── Features grid ─────────────────────────────────────────── */}
            <section className="py-16 px-6">
                <div className="max-w-5xl mx-auto">
                    <div className="text-center mb-12">
                        <h2 className="text-2xl md:text-3xl font-bold text-white mb-3">Everything you need</h2>
                        <p className="text-slate-400 text-sm">Built for security teams that move fast and fix faster.</p>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                        {FEATURES.map((f, i) => {
                            const Icon = f.icon;
                            return (
                                <div key={i} className="flex items-center gap-3 bg-white/[0.03] border border-white/8 rounded-xl px-4 py-3.5 hover:bg-white/[0.06] transition-colors">
                                    <div className="w-8 h-8 rounded-lg bg-primary-500/10 border border-primary-500/20 flex items-center justify-center flex-shrink-0">
                                        <Icon className="w-4 h-4 text-primary-400" />
                                    </div>
                                    <span className="text-sm text-slate-300">{f.text}</span>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </section>

            {/* ── CTA ───────────────────────────────────────────────────── */}
            <section className="py-24 px-6">
                <div className="max-w-3xl mx-auto text-center">
                    <div className="relative bg-gradient-to-br from-primary-600/10 to-primary-700/5 border border-primary-500/20 rounded-3xl p-12 overflow-hidden">
                        <FloatingOrb className="w-64 h-64 bg-primary-500/10" style={{ top: '-30%', left: '-15%' }} />
                        <div className="relative z-10">
                            <img src={securaxLogo} alt="securAX Logo" className="w-16 h-16 mx-auto mb-6 object-contain" />
                            <h2 className="text-3xl font-bold text-white mb-4">Ready to find your risks?</h2>
                            <p className="text-slate-400 mb-8 text-sm leading-relaxed max-w-lg mx-auto">
                                Create your free account and run your first security scan in minutes.
                                Only use on systems you own or have written permission to test.
                            </p>
                            <div className="flex flex-col sm:flex-row gap-3 justify-center">
                                <Link
                                    to="/register"
                                    className="flex items-center justify-center gap-2 px-8 py-3.5 bg-primary-600 hover:bg-primary-500 text-white font-semibold rounded-xl transition-all shadow-xl shadow-primary-600/30 text-sm"
                                >
                                    Create Free Account <ArrowRight className="w-4 h-4" />
                                </Link>
                                <Link
                                    to="/login"
                                    className="flex items-center justify-center gap-2 px-8 py-3.5 bg-white/5 hover:bg-white/10 border border-white/10 text-white font-semibold rounded-xl transition-all text-sm"
                                >
                                    Already have an account
                                </Link>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── Footer ────────────────────────────────────────────────── */}
            <footer className="border-t border-white/5 py-8 px-6">
                <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
                    <div className="flex items-center gap-2">
                        <img src={securaxLogo} alt="securAX Logo" className="w-6 h-6 object-contain" />
                        <span className="text-sm font-bold text-slate-400">securAX</span>
                    </div>
                    <p className="text-xs text-slate-600 text-center">
                        © {year} securAX — For authorized security testing only. All activity is logged and audited.
                    </p>
                    <div className="flex gap-4">
                        <Link to="/login" className="text-xs text-slate-500 hover:text-slate-300 transition-colors">Sign In</Link>
                        <Link to="/register" className="text-xs text-slate-500 hover:text-slate-300 transition-colors">Register</Link>
                    </div>
                </div>
            </footer>
        </div>
    );
};

export default LandingPage;
