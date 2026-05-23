import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
    ShieldAlert, 
    Moon, 
    Sun, 
    User,
    LogOut,
    Menu,
    X,
    ChevronDown
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const NavLink = ({ to, label, active }) => (
    <Link
        to={to}
        className={`px-3 py-2 text-sm font-medium rounded-md transition-colors ${
            active 
                ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-white' 
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 dark:text-slate-300 dark:hover:text-white dark:hover:bg-slate-800/50'
        }`}
    >
        {label}
    </Link>
);

const Navbar = () => {
    const { user, logout } = useAuth();
    const { pathname } = useLocation();
    const [darkMode, setDarkMode] = useState(false);
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
    const [userMenuOpen, setUserMenuOpen] = useState(false);

    useEffect(() => {
        if (localStorage.theme === 'light') {
            setDarkMode(false);
            document.documentElement.classList.remove('dark');
        } else {
            // Default to dark mode if no preference or explicitly dark
            setDarkMode(true);
            document.documentElement.classList.add('dark');
        }
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

    if (!user) return null;

    return (
        <nav className="sticky top-0 z-50 bg-white/80 dark:bg-slate-950/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 transition-colors duration-300">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between h-16">
                    {/* Left: Brand & Desktop Nav */}
                    <div className="flex items-center gap-8">
                        <Link to="/dashboard" className="flex items-center gap-2">
                            <div className="w-8 h-8 rounded bg-primary-600 flex items-center justify-center shadow-sm">
                                <ShieldAlert className="w-4 h-4 text-white" />
                            </div>
                            <span className="font-bold text-lg tracking-tight text-slate-900 dark:text-white">CyBrain</span>
                        </Link>

                        <div className="hidden md:flex items-center gap-1">
                            <NavLink to="/dashboard" label="Overview" active={pathname === '/dashboard'} />
                            <NavLink to="/web-scan" label="Web Scan" active={pathname === '/web-scan'} />
                            <NavLink to="/network-scan" label="Network" active={pathname === '/network-scan'} />
                            <NavLink to="/code-scan" label="Code" active={pathname === '/code-scan'} />
                            <NavLink to="/dependency-scan" label="Dependencies" active={pathname === '/dependency-scan'} />
                            <NavLink to="/dast-scan" label="DAST" active={pathname === '/dast-scan'} />
                            <NavLink to="/apache-scan" label="Config" active={pathname === '/apache-scan'} />
                            {user.role === 'admin' && (
                                <NavLink to="/admin" label="Admin" active={pathname.startsWith('/admin')} />
                            )}
                        </div>
                    </div>

                    {/* Right: Actions */}
                    <div className="hidden md:flex items-center gap-4">
                        <button 
                            onClick={toggleTheme}
                            className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors rounded-full hover:bg-slate-100 dark:hover:bg-slate-800"
                        >
                            {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                        </button>

                        <div className="relative">
                            <button 
                                onClick={() => setUserMenuOpen(!userMenuOpen)}
                                className="flex items-center gap-2 p-1 pl-3 pr-2 rounded-full border border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 bg-white dark:bg-slate-900 transition-colors"
                            >
                                <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{user.username}</span>
                                <div className="w-6 h-6 rounded-full bg-primary-100 dark:bg-primary-900/50 flex items-center justify-center text-primary-600 dark:text-primary-400">
                                    <User className="w-3.5 h-3.5" />
                                </div>
                                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                            </button>

                            {/* Dropdown Menu */}
                            {userMenuOpen && (
                                <>
                                    <div 
                                        className="fixed inset-0 z-40" 
                                        onClick={() => setUserMenuOpen(false)}
                                    />
                                    <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-slate-900 rounded-lg shadow-lg border border-slate-200 dark:border-slate-800 py-1 z-50 animate-in fade-in slide-in-from-top-2 duration-200">
                                        <div className="px-4 py-2 border-b border-slate-100 dark:border-slate-800 mb-1">
                                            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">Signed in as</p>
                                            <p className="text-sm font-semibold text-slate-900 dark:text-white truncate">{user.username}</p>
                                            <p className="text-xs text-primary-600 dark:text-primary-400 capitalize mt-0.5">{user.role}</p>
                                        </div>
                                        {user.role === 'admin' && (
                                            <>
                                                <Link onClick={() => setUserMenuOpen(false)} to="/admin/users" className="block px-4 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800">User Management</Link>
                                                <Link onClick={() => setUserMenuOpen(false)} to="/audit" className="block px-4 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800">Audit Logs</Link>
                                            </>
                                        )}
                                        <button 
                                            onClick={() => { setUserMenuOpen(false); logout(); }}
                                            className="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 flex items-center gap-2 mt-1 border-t border-slate-100 dark:border-slate-800"
                                        >
                                            <LogOut className="w-4 h-4" /> Sign Out
                                        </button>
                                    </div>
                                </>
                            )}
                        </div>
                    </div>

                    {/* Mobile Menu Button */}
                    <div className="flex items-center md:hidden">
                        <button 
                            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                            className="p-2 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800 rounded-md"
                        >
                            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
                        </button>
                    </div>
                </div>
            </div>

            {/* Mobile Menu */}
            {mobileMenuOpen && (
                <div className="md:hidden border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-4 pt-2 pb-4 space-y-1">
                    <Link to="/dashboard" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-base font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">Overview</Link>
                    <Link to="/web-scan" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-base font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">Web Scan</Link>
                    <Link to="/network-scan" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-base font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">Network</Link>
                    <Link to="/code-scan" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-base font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">Code</Link>
                    <Link to="/dependency-scan" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-base font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">Dependencies</Link>
                    <Link to="/dast-scan" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-base font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">DAST</Link>
                    <Link to="/apache-scan" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-base font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">Config</Link>
                    {user.role === 'admin' && (
                        <Link to="/admin" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-base font-medium text-primary-600 dark:text-primary-400 hover:bg-slate-50 dark:hover:bg-slate-800">Admin Panel</Link>
                    )}
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
