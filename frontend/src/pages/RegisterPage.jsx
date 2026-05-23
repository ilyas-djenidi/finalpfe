import React, { useState, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Lock, User, ArrowRight, ShieldCheck, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const getStrength = (pw) => {
    if (!pw) return { level: 0, label: '', color: '' };
    const hasLower  = /[a-z]/.test(pw);
    const hasUpper  = /[A-Z]/.test(pw);
    const hasDigit  = /\d/.test(pw);
    const hasSymbol = /[^a-zA-Z0-9]/.test(pw);
    const types = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
    if (pw.length >= 10 && types >= 4) return { level: 3, label: 'Strong',  color: 'bg-green-500' };
    if (pw.length >= 8  && types >= 2) return { level: 2, label: 'Medium',  color: 'bg-yellow-400' };
    return { level: 1, label: 'Weak', color: 'bg-red-500' };
};

const RegisterPage = () => {
    const { register } = useAuth();
    const navigate     = useNavigate();

    const [username,  setUsername]  = useState('');
    const [password,  setPassword]  = useState('');
    const [confirm,   setConfirm]   = useState('');
    const [loading,   setLoading]   = useState(false);
    const [error,     setError]     = useState('');

    const strength     = useMemo(() => getStrength(password), [password]);
    const mismatch     = confirm.length > 0 && confirm !== password;
    const confirmMatch = confirm.length > 0 && confirm === password;

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (password !== confirm) { setError('Passwords do not match.'); return; }
        if (password.length < 8)  { setError('Password must be at least 8 characters.'); return; }
        setLoading(true);
        try {
            const data = await register(username.trim(), password);
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

    return (
        <div className="min-h-screen bg-black flex items-center justify-center p-6 relative overflow-hidden">
            <div className="absolute top-1/4 -right-24 w-96 h-96 bg-purple-500/10 rounded-full blur-[120px]" />
            <div className="absolute bottom-1/4 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-[120px]" />

            <motion.div
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                className="w-full max-w-md relative z-10"
            >
                <div className="bg-white/[0.03] backdrop-blur-2xl border border-white/10 p-8 md:p-10 rounded-3xl shadow-2xl">
                    <div className="text-center mb-10">
                        <div className="w-16 h-16 bg-cyan-500/10 border border-cyan-500/20 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-[0_0_30px_rgba(0,245,212,0.1)]">
                            <ShieldCheck className="w-8 h-8 text-cyan-400" />
                        </div>
                        <h1 className="font-orbitron font-black text-2xl text-white tracking-widest mb-2 uppercase">
                            Register Operative
                        </h1>
                        <p className="text-gray-500 font-inter text-sm tracking-wide">
                            Join the next generation of security auditing.
                        </p>
                    </div>

                    {error && (
                        <div className="mb-5 flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-red-400 text-sm font-inter">
                            <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    <form className="space-y-5" onSubmit={handleSubmit}>
                        {/* Username */}
                        <div className="space-y-2">
                            <label className="text-[10px] font-orbitron text-gray-500 tracking-[0.2em] uppercase ml-1">Username</label>
                            <div className="relative group">
                                <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 group-focus-within:text-cyan-400 transition-colors" />
                                <input
                                    type="text"
                                    placeholder="agent42"
                                    value={username}
                                    onChange={e => setUsername(e.target.value)}
                                    required
                                    minLength={3}
                                    maxLength={32}
                                    pattern="[a-zA-Z0-9_\-]+"
                                    className="w-full bg-black/40 border border-white/5 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-gray-700 focus:outline-none focus:border-cyan-500/50 focus:bg-black/60 transition-all font-inter text-sm"
                                />
                            </div>
                        </div>

                        {/* Password + strength bar */}
                        <div className="space-y-2">
                            <label className="text-[10px] font-orbitron text-gray-500 tracking-[0.2em] uppercase ml-1">Password</label>
                            <div className="relative group">
                                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 group-focus-within:text-cyan-400 transition-colors" />
                                <input
                                    type="password"
                                    placeholder="••••••••••••"
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    required
                                    minLength={8}
                                    className="w-full bg-black/40 border border-white/5 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-gray-700 focus:outline-none focus:border-cyan-500/50 focus:bg-black/60 transition-all font-inter text-sm"
                                />
                            </div>
                            {/* Strength bar */}
                            {password.length > 0 && (
                                <div className="px-1">
                                    <div className="flex gap-1 h-1">
                                        {[1, 2, 3].map(lvl => (
                                            <div
                                                key={lvl}
                                                className={`flex-1 rounded-full transition-all duration-300 ${strength.level >= lvl ? strength.color : 'bg-white/10'}`}
                                            />
                                        ))}
                                    </div>
                                    <p className={`text-[10px] font-inter mt-1 ${strength.level === 3 ? 'text-green-400' : strength.level === 2 ? 'text-yellow-400' : 'text-red-400'}`}>
                                        {strength.label}
                                    </p>
                                </div>
                            )}
                        </div>

                        {/* Confirm password */}
                        <div className="space-y-2">
                            <label className="text-[10px] font-orbitron text-gray-500 tracking-[0.2em] uppercase ml-1">Confirm Password</label>
                            <div className="relative group">
                                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 group-focus-within:text-cyan-400 transition-colors" />
                                <input
                                    type="password"
                                    placeholder="••••••••••••"
                                    value={confirm}
                                    onChange={e => setConfirm(e.target.value)}
                                    required
                                    className={`w-full bg-black/40 border rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-gray-700 focus:outline-none focus:bg-black/60 transition-all font-inter text-sm ${mismatch ? 'border-red-500/50 focus:border-red-500/70' : confirmMatch ? 'border-green-500/40 focus:border-green-500/60' : 'border-white/5 focus:border-cyan-500/50'}`}
                                />
                            </div>
                            {mismatch && (
                                <p className="text-[11px] text-red-400 font-inter ml-1">Passwords do not match</p>
                            )}
                        </div>

                        <div className="pt-4">
                            <button
                                type="submit"
                                disabled={loading || mismatch}
                                className="w-full py-4 bg-gradient-to-r from-cyan-600 to-purple-600 text-white font-orbitron font-bold text-xs tracking-[0.2em] uppercase rounded-xl hover:from-cyan-500 hover:to-purple-500 transition-all duration-300 shadow-[0_0_20px_rgba(0,245,212,0.2)] flex items-center justify-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed"
                            >
                                {loading ? 'Creating Account…' : 'Create Account'}
                                {!loading && <ArrowRight className="w-4 h-4" />}
                            </button>
                        </div>
                    </form>

                    <div className="mt-8 pt-8 border-t border-white/5 text-center">
                        <p className="text-gray-600 font-inter text-xs tracking-wide">
                            Already registered?{' '}
                            <Link to="/login" className="text-cyan-400 hover:underline">Log In Here</Link>
                        </p>
                    </div>
                </div>

                <div className="mt-8 text-center">
                    <Link to="/" className="text-gray-600 text-[10px] font-orbitron tracking-widest hover:text-gray-400 transition-colors">
                        ← BACK TO HOME
                    </Link>
                </div>
            </motion.div>
        </div>
    );
};

export default RegisterPage;
