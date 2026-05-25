import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Lock, User, ArrowRight, AlertCircle, ShieldAlert, Moon, Sun, KeyRound, CheckCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const LoginPage = () => {
    const [username,   setUsername]   = useState('');
    const [password,   setPassword]   = useState('');
    const [totpToken,  setTotpToken]  = useState('');
    const [totpStep,   setTotpStep]   = useState(false);
    const [error,      setError]      = useState('');
    const [fieldErrors, setFieldErrors] = useState({});
    const [loading,    setLoading]    = useState(false);
    const [lockSecs,   setLockSecs]   = useState(0);
    const lockIntervalRef = useRef(null);

    const { login, verifyTotp } = useAuth();
    const navigate = useNavigate();
    const location = useLocation();

    // Success message from RegisterPage redirect
    const registeredMsg = location.state?.registered
        ? 'Account created successfully — please log in'
        : '';

    // Theme
    const [darkMode, setDarkMode] = useState(false);
    useEffect(() => {
        if (localStorage.theme === 'light') {
            setDarkMode(false);
            document.documentElement.classList.remove('dark');
        } else {
            setDarkMode(true);
            document.documentElement.classList.add('dark');
        }
    }, []);

    const toggleTheme = () => {
        const newTheme = !darkMode;
        setDarkMode(newTheme);
        document.documentElement.classList.toggle('dark', newTheme);
        localStorage.theme = newTheme ? 'dark' : 'light';
    };

    // Lockout countdown
    useEffect(() => {
        if (lockSecs <= 0) {
            if (lockIntervalRef.current) {
                clearInterval(lockIntervalRef.current);
                lockIntervalRef.current = null;
            }
            return;
        }
        lockIntervalRef.current = setInterval(() => {
            setLockSecs(s => {
                if (s <= 1) {
                    clearInterval(lockIntervalRef.current);
                    lockIntervalRef.current = null;
                    setError('');
                    return 0;
                }
                return s - 1;
            });
        }, 1000);
        return () => { if (lockIntervalRef.current) clearInterval(lockIntervalRef.current); };
    }, [lockSecs]);

    const fmtLock = (secs) => {
        const m = Math.floor(secs / 60);
        const s = secs % 60;
        return `${m}:${String(s).padStart(2, '0')}`;
    };

    // TOTP auto-submit on 6 digits
    const handleTotpChange = (e) => {
        const val = e.target.value.replace(/\D/g, '');
        setTotpToken(val);
        if (val.length === 6) {
            // small delay so user sees the digit before auto-submit
            setTimeout(() => submitTotp(val), 80);
        }
    };

    const submitTotp = async (code) => {
        setLoading(true);
        setError('');
        try {
            const data = await verifyTotp((code ?? totpToken).trim());
            if (data.ok) {
                navigate(data.user?.role === 'admin' ? '/admin' : '/dashboard');
            } else {
                setError(data.error || 'Invalid 2FA code.');
                setTotpToken('');
            }
        } catch (err) {
            setError(err.response?.data?.error || 'Cannot reach server — make sure the backend is running on port 5000');
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (totpStep) { submitTotp(); return; }
        if (lockSecs > 0) return;
        setLoading(true);
        setError('');
        setFieldErrors({});
        try {
            if (!username.trim() || !password) { setLoading(false); return; }
            const data = await login(username.trim(), password);
            if (data.ok) {
                navigate(data.user?.role === 'admin' ? '/admin' : '/dashboard');
            } else if (data.totp_required) {
                setTotpStep(true);
                setError('');
            } else if (data.lock_seconds_remaining) {
                setLockSecs(data.lock_seconds_remaining);
                setError(`Account locked — try again in ${fmtLock(data.lock_seconds_remaining)}`);
            } else if (data.field) {
                setFieldErrors({ [data.field]: data.message || data.error });
            } else {
                setError(data.error || 'Invalid credentials.');
            }
        } catch (err) {
            if (!err.response) {
                setError('Cannot reach server — make sure the backend is running on port 5000');
            } else {
                const d = err.response?.data || {};
                if (d.lock_seconds_remaining) {
                    setLockSecs(d.lock_seconds_remaining);
                    setError(`Account locked — try again in ${fmtLock(d.lock_seconds_remaining)}`);
                } else if (d.field) {
                    setFieldErrors({ [d.field]: d.message || d.error });
                } else {
                    setError(d.error || 'Invalid credentials.');
                }
            }
        } finally {
            setLoading(false);
        }
    };

    const isLocked = lockSecs > 0;

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 transition-colors duration-300">
            <div className="absolute top-6 right-6">
                <button
                    onClick={toggleTheme}
                    className="p-2 rounded-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 shadow-sm transition-all"
                >
                    {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                </button>
            </div>

            <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
                <div className="mx-auto w-12 h-12 bg-primary-600 rounded-xl flex items-center justify-center shadow-lg shadow-primary-500/30 mb-4">
                    <ShieldAlert className="w-7 h-7 text-white" />
                </div>
                <h2 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
                    securAX Security
                </h2>
                <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                    Sign in to your enterprise account
                </p>
            </div>

            <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
                <div className="bg-white dark:bg-slate-900 py-8 px-4 shadow-xl shadow-slate-200/50 dark:shadow-black/50 sm:rounded-2xl sm:px-10 border border-slate-200 dark:border-slate-800">

                    {registeredMsg && (
                        <div className="mb-6 flex items-start gap-3 bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 rounded-xl px-4 py-3">
                            <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0" />
                            <p className="text-green-700 dark:text-green-400 text-sm font-medium">{registeredMsg}</p>
                        </div>
                    )}

                    {error && (
                        <div className="mb-6 flex items-start gap-3 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-xl px-4 py-3">
                            <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0" />
                            <div className="flex-1">
                                <p className="text-red-700 dark:text-red-400 text-sm font-medium">{error}</p>
                                {isLocked && (
                                    <p className="text-red-600 dark:text-red-500 text-sm font-mono mt-1">
                                        {fmtLock(lockSecs)} remaining
                                    </p>
                                )}
                            </div>
                        </div>
                    )}

                    <form className="space-y-6" onSubmit={handleSubmit}>
                        {totpStep ? (
                            <div>
                                <div className="mb-4 flex items-center gap-3 bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark:border-blue-500/20 rounded-xl px-4 py-3">
                                    <KeyRound className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0" />
                                    <p className="text-blue-700 dark:text-blue-300 text-sm font-medium">Enter the 6-digit code from your authenticator app. It will submit automatically.</p>
                                </div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                    Authenticator Code
                                </label>
                                <div className="mt-1 relative">
                                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                        <KeyRound className="h-5 w-5 text-slate-400" />
                                    </div>
                                    <input
                                        type="text"
                                        inputMode="numeric"
                                        pattern="[0-9]{6}"
                                        maxLength={6}
                                        value={totpToken}
                                        onChange={handleTotpChange}
                                        className="block w-full pl-10 pr-3 py-2.5 border border-slate-300 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 font-mono tracking-widest text-center text-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 sm:text-sm transition-shadow"
                                        placeholder="000000"
                                        autoFocus
                                    />
                                </div>
                                <button
                                    type="button"
                                    onClick={() => { setTotpStep(false); setTotpToken(''); setError(''); }}
                                    className="mt-3 text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 underline"
                                >
                                    Back to login
                                </button>
                            </div>
                        ) : (
                            <>
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Username</label>
                                    <div className="mt-1 relative">
                                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                            <User className="h-5 w-5 text-slate-400" />
                                        </div>
                                        <input
                                            type="text"
                                            value={username}
                                            onChange={e => setUsername(e.target.value)}
                                            disabled={isLocked}
                                            className={`block w-full pl-10 pr-3 py-2.5 border rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 sm:text-sm transition-shadow disabled:opacity-50 ${fieldErrors.username ? 'border-red-400 dark:border-red-500' : 'border-slate-300 dark:border-slate-700'}`}
                                            placeholder="Enter username"
                                            autoComplete="username"
                                        />
                                    </div>
                                    {fieldErrors.username && (
                                        <p className="mt-1 text-xs text-red-600 dark:text-red-400">{fieldErrors.username}</p>
                                    )}
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Password</label>
                                    <div className="mt-1 relative">
                                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                            <Lock className="h-5 w-5 text-slate-400" />
                                        </div>
                                        <input
                                            type="password"
                                            value={password}
                                            onChange={e => setPassword(e.target.value)}
                                            disabled={isLocked}
                                            className={`block w-full pl-10 pr-3 py-2.5 border rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 sm:text-sm transition-shadow disabled:opacity-50 ${fieldErrors.password ? 'border-red-400 dark:border-red-500' : 'border-slate-300 dark:border-slate-700'}`}
                                            placeholder="••••••••"
                                            autoComplete="current-password"
                                        />
                                    </div>
                                    {fieldErrors.password && (
                                        <p className="mt-1 text-xs text-red-600 dark:text-red-400">{fieldErrors.password}</p>
                                    )}
                                </div>
                            </>
                        )}

                        <button
                            type="submit"
                            disabled={loading || isLocked}
                            className="w-full flex justify-center items-center gap-2 py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 transition-colors"
                        >
                            {loading ? (
                                <>
                                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                    Authenticating...
                                </>
                            ) : isLocked ? (
                                `Locked — ${fmtLock(lockSecs)}`
                            ) : totpStep ? (
                                <>Verify Code <ArrowRight className="w-4 h-4" /></>
                            ) : (
                                <>Sign In <ArrowRight className="w-4 h-4" /></>
                            )}
                        </button>
                    </form>

                    <div className="mt-6 text-center">
                        <p className="text-xs text-gray-500 font-inter">securAX Security Intelligence</p>
                        <p className="text-sm text-slate-500 dark:text-slate-400 mt-2">
                            Don't have an account?{' '}
                            <Link to="/register" className="font-medium text-primary-600 hover:text-primary-500 dark:text-primary-400">
                                Register here
                            </Link>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
