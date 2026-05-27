import React, { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
    Moon, Sun, User, LogOut, Menu, X,
    ChevronDown, Network, Globe, Server, Package,
    Shield, FileSearch, Layers, Zap
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import securaxLogo from '../assets/securax_logo.png';

const NAV_GROUPS = [
    {
        label: 'Scan Web',
        icon: Globe,
        items: [
            { label: 'Web Application Scan', desc: 'Automated vulnerability assessment', to: '/scan/web', icon: Globe },
            { label: 'Dynamic Analysis', desc: 'Runtime behavior and injection testing', to: '/scan/dast', icon: Zap },
            { label: 'Code Analysis', desc: 'Static source code security review', to: '/scan/code', icon: Layers },
        ],
    },
    {
        label: 'Scan Server',
        icon: Server,
        items: [
            { label: 'Internal Config Audit', desc: 'Analyse uploaded config file for issues', to: '/scan/apache', icon: FileSearch },
            { label: 'External Server Audit', desc: 'Probe server externally for misconfigs', to: '/scan/server-ext', icon: Shield },
        ],
    },
];

function DropdownMenu({ group, pathname, onClose }) {
    const Icon = group.icon;
    const isActive = group.items.some(i => pathname.startsWith(i.to));
    const [open, setOpen] = useState(false);
    const ref = useRef(null);

    useEffect(() => {
        const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
        document.addEventListener('mousedown', handler);
        return () => document.removeEventListener('mousedown', handler);
    }, []);

    return (
        <div ref={ref} className="relative">
            <button
                onClick={() => setOpen(o => !o)}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                    isActive
                        ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-white'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 dark:text-slate-300 dark:hover:text-white dark:hover:bg-slate-800/50'
                }`}
            >
                <Icon className="w-3.5 h-3.5" />
                {group.label}
                <ChevronDown className={`w-3 h-3 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
            </button>

            {open && (
                <>
                    <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
                    <div className="absolute left-0 mt-2 w-64 bg-white dark:bg-slate-900 rounded-xl shadow-xl border border-slate-200 dark:border-slate-800 py-1.5 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                        {group.items.map(item => {
                            const ItemIcon = item.icon;
                            const active = pathname === item.to;
                            return (
                                <Link
                                    key={item.to}
                                    to={item.to}
                                    onClick={() => { setOpen(false); onClose?.(); }}
                                    className={`flex items-start gap-3 px-4 py-3 mx-1.5 rounded-lg transition-colors ${
                                        active
                                            ? 'bg-primary-50 dark:bg-primary-500/10 text-primary-700 dark:text-primary-300'
                                            : 'hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                                    }`}
                                >
                                    <div className={`mt-0.5 p-1.5 rounded-md flex-shrink-0 ${active ? 'bg-primary-100 dark:bg-primary-500/20 text-primary-600 dark:text-primary-400' : 'bg-slate-100 dark:bg-slate-800 text-slate-500'}`}>
                                        <ItemIcon className="w-3.5 h-3.5" />
                                    </div>
                                    <div>
                                        <div className="text-sm font-semibold leading-tight">{item.label}</div>
                                        <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 leading-tight">{item.desc}</div>
                                    </div>
                                </Link>
                            );
                        })}
                    </div>
                </>
            )}
        </div>
    );
}

const Navbar = () => {
    const { user, logout } = useAuth();
    const { pathname } = useLocation();
    const [darkMode, setDarkMode]         = useState(false);
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
    const [userMenuOpen, setUserMenuOpen] = useState(false);
    const [lang, setLang]                 = useState('en');

    useEffect(() => {
        if (localStorage.theme === 'light') {
            setDarkMode(false);
            document.documentElement.classList.remove('dark');
        } else {
            setDarkMode(true);
            document.documentElement.classList.add('dark');
        }
        const savedLang = localStorage.getItem('cybrain_lang') || 'en';
        setLang(savedLang);
        document.dir = savedLang === 'ar' ? 'rtl' : 'ltr';
        document.documentElement.lang = savedLang;
    }, []);

    const toggleTheme = () => {
        const newTheme = !darkMode;
        setDarkMode(newTheme);
        if (newTheme) {
            document.documentElement.classList.add('dark');
            localStorage.theme = 'dark';
        } else {
            document.documentElement.classList.remove('dark');
            localStorage.theme = 'light';
        }
    };

    const toggleLang = () => {
        const newLang = lang === 'en' ? 'ar' : 'en';
        setLang(newLang);
        localStorage.setItem('cybrain_lang', newLang);
        document.dir = newLang === 'ar' ? 'rtl' : 'ltr';
        document.documentElement.lang = newLang;
    };

    if (!user) return null;

    return (
        <nav className="sticky top-0 z-50 bg-white/80 dark:bg-slate-950/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 transition-colors duration-300">
            <div className="px-4 sm:px-6">
                <div className="flex items-center h-16">

                    {/* Left Brand Area */}
                    <div className="flex-1 flex items-center gap-2">
                        <Link to="/dashboard" className="flex items-center gap-2">
                            <img 
                                src={securaxLogo} 
                                alt="securAX Logo" 
                                className="w-8 h-8 object-contain rounded-md" 
                            />
                            <span className="font-bold text-lg tracking-tight text-slate-900 dark:text-white">securAX</span>
                        </Link>
                    </div>

                    {/* Center: nav items */}
                    <div className="hidden lg:flex items-center gap-2">
                        {/* Scan Network — direct link, no dropdown */}
                        <Link
                            to="/scan/network"
                            className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                                pathname.startsWith('/scan/network')
                                    ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-white'
                                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 dark:text-slate-300 dark:hover:text-white dark:hover:bg-slate-800/50'
                            }`}
                        >
                            <Network className="w-3.5 h-3.5" />
                            Scan Network
                        </Link>

                        {NAV_GROUPS.map(group => (
                            <DropdownMenu key={group.label} group={group} pathname={pathname} />
                        ))}

                        <Link
                            to="/scan/dependencies"
                            className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                                pathname === '/scan/dependencies'
                                    ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-white'
                                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 dark:text-slate-300 dark:hover:text-white dark:hover:bg-slate-800/50'
                            }`}
                        >
                            <Package className="w-3.5 h-3.5" />
                            Dependencies
                        </Link>

                        <Link
                            to="/chat"
                            className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md transition-all ${
                                pathname === '/chat'
                                    ? 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                                    : 'text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/10 border border-transparent hover:border-cyan-500/20'
                            }`}
                        >
                            <span className="text-[11px]">✦</span> ARIA AI
                        </Link>
                    </div>

                    {/* Right: actions */}
                    <div className="flex-1 flex items-center justify-end gap-2">
                        <button
                            onClick={toggleTheme}
                            className="hidden md:flex p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors rounded-full hover:bg-slate-100 dark:hover:bg-slate-800"
                        >
                            {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                        </button>

                        {/* Mobile menu button */}
                        <button
                            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                            className="lg:hidden p-2 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800 rounded-md"
                        >
                            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
                        </button>
                    </div>

                </div>
            </div>

            {/* Mobile Menu */}
            {mobileMenuOpen && (
                <div className="md:hidden border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-4 pt-2 pb-4 space-y-1">
                    <Link to="/scan/network" onClick={() => setMobileMenuOpen(false)} className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium ${pathname.startsWith('/scan/network') ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-white' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800'}`}>
                        <Network className="w-4 h-4" /> Scan Network
                    </Link>

                    <p className="px-3 pt-2 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Scan Web</p>
                    <Link to="/scan/web" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">Web Application Scan</Link>
                    <Link to="/scan/dast" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">Dynamic Analysis</Link>
                    <Link to="/scan/code" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">Code Analysis</Link>

                    <p className="px-3 pt-2 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Scan Server</p>
                    <Link to="/scan/apache" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">Internal Config Audit</Link>
                    <Link to="/scan/server-ext" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">External Server Audit</Link>

                    <Link to="/scan/dependencies" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">Dependencies</Link>
                    <Link to="/chat" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm font-medium text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/10">✦ ARIA AI</Link>

                    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800 flex justify-between items-center">
                        <div className="flex items-center gap-3 px-3">
                            <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                                <User className="w-4 h-4" />
                            </div>
                            <div>
                                <div className="text-sm font-medium text-slate-900 dark:text-white">{user.username}</div>
                                <div className="text-xs text-slate-500 dark:text-slate-400 capitalize">{user.role}</div>
                            </div>
                        </div>
                        <div className="flex gap-2">
                            <button onClick={toggleLang} className="px-2 py-1 text-xs font-semibold text-slate-500 border border-slate-200 dark:border-slate-700 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
                                {lang === 'en' ? 'AR' : 'EN'}
                            </button>
                            <button onClick={toggleTheme} className="p-2 text-slate-500 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800">
                                {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                            </button>
                            <button onClick={() => { setMobileMenuOpen(false); logout(); }} className="p-2 text-red-500 rounded-full hover:bg-red-50 dark:hover:bg-red-500/10">
                                <LogOut className="w-5 h-5" />
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </nav>
    );
};

export default Navbar;
