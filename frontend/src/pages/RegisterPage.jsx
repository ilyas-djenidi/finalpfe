import { useState, useMemo, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Lock, User, Mail, ArrowRight, AlertCircle, Moon, Sun, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import securaxLogo from '../assets/securax_logo.png';

// ── Password strength ─────────────────────────────────────────────────────────
// Password must match backend check_password_complexity():
//   ≥10 chars, uppercase, lowercase, digit, special char
const getStrength = (pw) => {
    if (!pw) return { level: 0, label: '', color: '', hint: '' };
    const hasLower  = /[a-z]/.test(pw);
    const hasUpper  = /[A-Z]/.test(pw);
    const hasDigit  = /\d/.test(pw);
    const hasSymbol = /[!@#$%^&*()\-_=+[\]{};:'",.<>?/\\|`~]/.test(pw);
    const types = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
    if (pw.length >= 10 && types >= 4) return { level: 3, label: 'Strong',  color: 'bg-green-500',  hint: '' };
    if (pw.length >= 10 && types >= 2) return { level: 2, label: 'Medium',  color: 'bg-yellow-400', hint: 'Add uppercase, digit & symbol' };
    if (pw.length >= 6)                return { level: 1, label: 'Weak',    color: 'bg-red-500',    hint: 'Min 10 chars with A-Z, 0-9, symbol' };
    return { level: 1, label: 'Too short', color: 'bg-red-500', hint: 'Minimum 10 characters required' };
};

const meetsRequirements = (pw) => {
    return (
        pw.length >= 10 &&
        /[A-Z]/.test(pw) &&
        /[a-z]/.test(pw) &&
        /\d/.test(pw) &&
        /[!@#$%^&*()\-_=+[\]{};:'",.<>?/\\|`~]/.test(pw)
    );
};

const RegisterPage = () => {
    const { register } = useAuth();
    const navigate     = useNavigate();

    const [username,     setUsername]     = useState('');
    const [email,        setEmail]        = useState('');
    const [password,     setPassword]     = useState('');
    const [confirm,      setConfirm]      = useState('');
    const [showPass,     setShowPass]     = useState(false);
    const [showConfirm,  setShowConfirm]  = useState(false);
    const [loading,      setLoading]      = useState(false);
    const [error,        setError]        = useState('');
    const [darkMode,     setDarkMode]     = useState(false);

    useEffect(() => {
        const isDark = localStorage.theme !== 'light';
        setDarkMode(isDark);
        document.documentElement.classList.toggle('dark', isDark);
    }, []);

    const toggleTheme = () => {
        const next = !darkMode;
        setDarkMode(next);
        document.documentElement.classList.toggle('dark', next);
        localStorage.theme = next ? 'dark' : 'light';
    };

    const strength    = useMemo(() => getStrength(password), [password]);
    const mismatch    = confirm.length > 0 && confirm !== password;
    const matchOk     = confirm.length > 0 && confirm === password;
    const pwOk        = meetsRequirements(password);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (password !== confirm)  { setError('Passwords do not match.');                   return; }
        if (!pwOk) { setError('Password must be ≥10 chars with uppercase, lowercase, digit and symbol.'); return; }
        setLoading(true);
        try {
            const data = await register(username.trim(), email.trim(), password);
            if (data.ok) {
                navigate('/login', { state: { registered: true } });
            } else {
                setError(data.error || 'Registration failed.');
            }
        } catch (err) {
            setError(err.response?.data?.error || 'Server error. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const strengthColors = ['bg-slate-200 dark:bg-slate-700', 'bg-red-500', 'bg-yellow-400', 'bg-green-500'];
    const strengthTextColors = ['', 'text-red-500', 'text-yellow-500', 'text-green-500'];

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 transition-colors duration-300">

            {/* Theme toggle */}
            <div className="absolute top-6 right-6">
                <button
                    onClick={toggleTheme}
                    className="p-2 rounded-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 shadow-sm transition-all"
                >
                    {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                </button>
            </div>

            {/* Logo + title */}
            <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
                <img src={securaxLogo} alt="securAX Logo" className="mx-auto h-16 w-auto mb-4" />
                <h2 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
                    Create Account
                </h2>
                <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                    Register for securAX Security
                </p>
            </div>

            {/* Card */}
            <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
                <div className="bg-white dark:bg-slate-900 py-8 px-4 shadow-xl shadow-slate-200/50 dark:shadow-black/50 sm:rounded-2xl sm:px-10 border border-slate-200 dark:border-slate-800">

                    {error && (
                        <div className="mb-6 flex items-start gap-3 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-xl px-4 py-3">
                            <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                            <p className="text-red-700 dark:text-red-400 text-sm font-medium">{error}</p>
                        </div>
                    )}

                    <form className="space-y-5" onSubmit={handleSubmit}>

                        {/* Username */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Username
                            </label>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <User className="h-5 w-5 text-slate-400" />
                                </div>
                                <input
                                    type="text"
                                    value={username}
                                    onChange={e => setUsername(e.target.value)}
                                    required
                                    minLength={3}
                                    maxLength={32}
                                    pattern="[a-zA-Z0-9_\-]+"
                                    placeholder="e.g. analyst01"
                                    className="block w-full pl-10 pr-3 py-2.5 border border-slate-300 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 sm:text-sm transition-shadow"
                                />
                            </div>
                        </div>

                        {/* Email */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Email <span className="text-slate-400 font-normal">(optional)</span>
                            </label>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <Mail className="h-5 w-5 text-slate-400" />
                                </div>
                                <input
                                    type="email"
                                    value={email}
                                    onChange={e => setEmail(e.target.value)}
                                    placeholder="you@example.com"
                                    className="block w-full pl-10 pr-3 py-2.5 border border-slate-300 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 sm:text-sm transition-shadow"
                                />
                            </div>
                        </div>

                        {/* Password */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Password
                            </label>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <Lock className="h-5 w-5 text-slate-400" />
                                </div>
                                <input
                                    type={showPass ? 'text' : 'password'}
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    required
                                    minLength={8}
                                    placeholder="••••••••"
                                    className="block w-full pl-10 pr-10 py-2.5 border border-slate-300 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 sm:text-sm transition-shadow"
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPass(v => !v)}
                                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                                >
                                    {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>

                            {/* Strength bar */}
                            {password.length > 0 && (
                                <div className="mt-2">
                                    <div className="flex gap-1 h-1.5">
                                        {[1, 2, 3].map(lvl => (
                                            <div
                                                key={lvl}
                                                className={`flex-1 rounded-full transition-all duration-300 ${
                                                    strength.level >= lvl ? strengthColors[strength.level] : 'bg-slate-200 dark:bg-slate-700'
                                                }`}
                                            />
                                        ))}
                                    </div>
                                    <p className={`text-xs mt-1 font-medium ${strengthTextColors[strength.level]}`}>
                                        {strength.label}{strength.hint ? ` — ${strength.hint}` : ''}
                                    </p>
                                </div>
                            )}
                        </div>

                        {/* Confirm password */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Confirm Password
                            </label>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <Lock className="h-5 w-5 text-slate-400" />
                                </div>
                                <input
                                    type={showConfirm ? 'text' : 'password'}
                                    value={confirm}
                                    onChange={e => setConfirm(e.target.value)}
                                    required
                                    placeholder="••••••••"
                                    className={`block w-full pl-10 pr-10 py-2.5 border rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 sm:text-sm transition-shadow ${
                                        mismatch  ? 'border-red-400 dark:border-red-500 focus:ring-red-500 focus:border-red-500'
                                        : matchOk ? 'border-green-400 dark:border-green-500 focus:ring-green-500 focus:border-green-500'
                                        :           'border-slate-300 dark:border-slate-700 focus:ring-primary-500 focus:border-primary-500'
                                    }`}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowConfirm(v => !v)}
                                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                                >
                                    {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>
                            {mismatch && (
                                <p className="mt-1 text-xs text-red-500 font-medium">Passwords do not match</p>
                            )}
                            {matchOk && (
                                <p className="mt-1 text-xs text-green-500 font-medium">✓ Passwords match</p>
                            )}
                        </div>

                        {/* Requirements checklist */}
                        {password.length > 0 && !pwOk && (
                            <ul className="text-[11px] text-slate-500 dark:text-slate-400 space-y-0.5 pl-1">
                                {[
                                    [password.length >= 10,          '≥ 10 characters'],
                                    [/[A-Z]/.test(password),         'Uppercase letter (A-Z)'],
                                    [/[a-z]/.test(password),         'Lowercase letter (a-z)'],
                                    [/\d/.test(password),            'A number (0-9)'],
                                    [/[!@#$%^&*]/.test(password),    'A symbol (!@#$%^&*)'],
                                ].map(([ok, label]) => (
                                    <li key={label} className={`flex items-center gap-1.5 ${ok ? 'text-green-500' : 'text-slate-400'}`}>
                                        <span>{ok ? '✓' : '○'}</span> {label}
                                    </li>
                                ))}
                            </ul>
                        )}

                        <div className="pt-2">
                            <button
                                type="submit"
                                disabled={loading || mismatch || !pwOk}
                                className="w-full flex justify-center items-center gap-2 py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 transition-colors"
                            >
                                {loading ? (
                                    <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Creating Account…</>
                                ) : (
                                    <>Create Account <ArrowRight className="w-4 h-4" /></>
                                )}
                            </button>
                        </div>
                    </form>

                    <div className="mt-6 text-center">
                        <p className="text-xs text-gray-500 font-inter">securAX Security Intelligence</p>
                        <p className="text-sm text-slate-500 dark:text-slate-400 mt-2">
                            Already have an account?{' '}
                            <Link to="/login" className="font-medium text-primary-600 hover:text-primary-500 dark:text-primary-400">
                                Sign in here
                            </Link>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default RegisterPage;
