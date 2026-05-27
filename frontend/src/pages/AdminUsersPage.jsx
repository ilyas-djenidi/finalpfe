import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link, useNavigate } from 'react-router-dom';
import {
    Users, AlertTriangle, ShieldCheck, UserPlus, Trash2,
    ArrowLeft, Activity, FileText,
    Search, ChevronLeft, ChevronRight, RefreshCw, KeyRound, Globe, Unlock,
    Ban, ShieldOff, MapPin
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const AdminUsersPage = () => {
    const { user } = useAuth();
    const navigate = useNavigate();
    const [usersList, setUsersList]         = useState([]);
    const [loading, setLoading]             = useState(true);
    const [fetchError, setFetchError]       = useState('');
    const [newUsername, setNewUsername]         = useState('');
    const [newPassword, setNewPassword]         = useState('');
    const [confirmPw, setConfirmPw]             = useState('');
    const [newRole, setNewRole]                 = useState('analyst');
    const [newAllowedTarget, setNewAllowedTarget] = useState('');
    const [adding, setAdding]                   = useState(false);
    const [createError, setCreateError]     = useState('');
    const [createSuccess, setCreateSuccess] = useState('');
    const [showModal, setShowModal]         = useState(false);

    // Filters & pagination
    const [search, setSearch]   = useState('');
    const [roleFilter, setRoleFilter] = useState('');
    const [page, setPage]       = useState(1);
    const [total, setTotal]     = useState(0);
    const PER_PAGE = 20;

    const fetchUsers = async (p = page) => {
        setLoading(true);
        try {
            const { data } = await axios.get('/api/admin/users', {
                params: { page: p, per_page: PER_PAGE },
                withCredentials: true,
            });
            setUsersList(data.users || []);
            setTotal(data.total || 0);
            setFetchError('');
        } catch (err) {
            setFetchError(err.response?.data?.error || 'Failed to load users');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchUsers(); }, [page]);

    const handleCreateUser = async (e) => {
        e.preventDefault();
        setCreateError('');
        setCreateSuccess('');
        if (newPassword !== confirmPw) { setCreateError('Passwords do not match.'); return; }
        setAdding(true);
        try {
            const { data } = await axios.post('/api/admin/users', {
                username: newUsername, password: newPassword,
                confirm_password: confirmPw, role: newRole,
                allowed_target: newRole === 'analyst' ? newAllowedTarget.trim() : '',
            }, { withCredentials: true });
            if (data.ok) {
                setCreateSuccess(`Account "${newUsername}" created.`);
                setNewUsername(''); setNewPassword(''); setConfirmPw(''); setNewAllowedTarget('');
                fetchUsers(1); setPage(1);
                setTimeout(() => { setShowModal(false); setCreateSuccess(''); }, 1500);
            } else {
                setCreateError(data.error || 'Failed to create user.');
            }
        } catch (err) {
            setCreateError(err.response?.data?.error || 'Failed to create user.');
        } finally {
            setAdding(false);
        }
    };

    const handleDelete = async (uid, targetUsername) => {
        if (!window.confirm(`Permanently delete account "${targetUsername}"?`)) return;
        try {
            await axios.delete(`/api/admin/users/${uid}`, { withCredentials: true });
            fetchUsers();
        } catch (err) {
            alert(err.response?.data?.error || 'Failed to delete user');
        }
    };

    const handlePatch = async (uid, patch) => {
        try {
            await axios.patch(`/api/admin/users/${uid}`, patch, { withCredentials: true });
            fetchUsers();
        } catch (err) {
            alert(err.response?.data?.error || 'Failed to update user');
        }
    };

    const filtered = usersList.filter(u => {
        const q = search.toLowerCase();
        const matchSearch = !q || (u.username || '').toLowerCase().includes(q);
        const matchRole   = !roleFilter || u.role === roleFilter;
        return matchSearch && matchRole;
    });

    const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

    if (user?.role !== 'admin') return (
        <div className="h-64 flex items-center justify-center">
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-6 rounded-xl flex items-center gap-3">
                <AlertTriangle className="w-6 h-6" />
                <div><h3 className="font-bold">Access Denied</h3><p className="text-sm">Administrator privileges required.</p></div>
            </div>
        </div>
    );

    const closeModal = () => {
        setShowModal(false);
        setCreateError('');
        setCreateSuccess('');
        setNewUsername(''); setNewPassword(''); setConfirmPw(''); setNewAllowedTarget('');
    };

    return (
        <div className="animate-in fade-in duration-500">
            {/* ── Header ── */}
            <div className="mb-8 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <button
                        onClick={() => navigate('/admin')}
                        className="inline-flex items-center gap-2 px-3 py-1.5 mb-4 text-sm font-medium text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 rounded-lg transition-all hover:scale-[1.02] active:scale-[0.98]"
                    >
                        <ArrowLeft className="w-4 h-4" /> Back to Admin Panel
                    </button>
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Users className="w-8 h-8 text-primary-500" /> User Management
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">Provision, modify, and revoke access for platform operators.</p>
                </div>
                <button
                    onClick={() => setShowModal(true)}
                    className="self-start sm:self-auto flex items-center gap-2 px-5 py-2.5 bg-primary-600 hover:bg-primary-700 text-white text-sm font-bold rounded-xl shadow-md shadow-primary-500/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                >
                    <UserPlus className="w-4 h-4" /> Provision New Account
                </button>
            </div>

            {/* ── Modal ── */}
            {showModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
                    {/* Backdrop */}
                    <div
                        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
                        onClick={closeModal}
                    />
                    {/* Dialog */}
                    <div className="relative w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl animate-in fade-in zoom-in-95 duration-200">
                        {/* Modal header */}
                        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
                            <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                                <UserPlus className="w-4 h-4 text-primary-500" /> Provision New Account
                            </h2>
                            <button
                                onClick={closeModal}
                                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                            >
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                            </button>
                        </div>

                        {/* Modal body */}
                        <div className="px-6 py-5">
                            {createError && (
                                <div className="mb-4 flex items-start gap-2 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-lg px-3 py-2.5">
                                    <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                                    <p className="text-red-700 dark:text-red-400 text-xs font-medium">{createError}</p>
                                </div>
                            )}
                            {createSuccess && (
                                <div className="mb-4 bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 rounded-lg px-3 py-2.5 flex items-center gap-2">
                                    <svg className="w-4 h-4 text-green-600 dark:text-green-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                                    <p className="text-green-700 dark:text-green-400 text-xs font-medium">{createSuccess}</p>
                                </div>
                            )}

                            <form onSubmit={handleCreateUser} className="space-y-4">
                                {[
                                    { label: 'Username', type: 'text', val: newUsername, set: setNewUsername, ph: 'operator1' },
                                    { label: 'Password', type: 'password', val: newPassword, set: setNewPassword, ph: 'Min 10 chars…' },
                                    { label: 'Confirm Password', type: 'password', val: confirmPw, set: setConfirmPw, ph: 'Repeat password' },
                                ].map(f => (
                                    <div key={f.label}>
                                        <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">{f.label}</label>
                                        <input
                                            type={f.type}
                                            value={f.val}
                                            onChange={e => f.set(e.target.value)}
                                            placeholder={f.ph}
                                            required
                                            className={`w-full bg-slate-50 dark:bg-slate-950 border rounded-lg px-4 py-2.5 text-slate-900 dark:text-white placeholder-slate-400 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 transition-shadow ${
                                                f.label === 'Confirm Password' && confirmPw && confirmPw !== newPassword
                                                    ? 'border-red-400 dark:border-red-500'
                                                    : 'border-slate-300 dark:border-slate-700'
                                            }`}
                                        />
                                        {f.label === 'Confirm Password' && confirmPw && confirmPw !== newPassword && (
                                            <p className="mt-1 text-xs text-red-600 dark:text-red-400">Passwords do not match.</p>
                                        )}
                                    </div>
                                ))}

                                <div>
                                    <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Role</label>
                                    <select
                                        value={newRole}
                                        onChange={e => { setNewRole(e.target.value); setNewAllowedTarget(''); }}
                                        className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm"
                                    >
                                        <option value="analyst">Analyst</option>
                                        <option value="admin">Administrator (Full Access)</option>
                                    </select>
                                </div>

                                {/* Allowed Target — only relevant for analysts */}
                                {newRole === 'analyst' && (
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">
                                            Allowed Target <span className="normal-case font-normal text-slate-400">(optional — leave blank for unrestricted)</span>
                                        </label>
                                        <div className="relative">
                                            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                            <input
                                                type="text"
                                                value={newAllowedTarget}
                                                onChange={e => setNewAllowedTarget(e.target.value)}
                                                placeholder="example.com"
                                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg pl-9 pr-4 py-2.5 text-slate-900 dark:text-white placeholder-slate-400 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 transition-shadow"
                                            />
                                        </div>
                                        <p className="mt-1 text-[10px] text-slate-400">
                                            The analyst will only be able to scan this domain/IP. You can change it later.
                                        </p>
                                    </div>
                                )}

                                <p className="text-[10px] text-slate-400">Password must be ≥10 chars with upper, lower, digit, and symbol.</p>

                                <div className="flex gap-3 pt-1">
                                    <button
                                        type="button"
                                        onClick={closeModal}
                                        className="flex-1 py-2.5 px-4 rounded-xl text-sm font-semibold border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        disabled={adding || !newUsername || !newPassword || newPassword !== confirmPw}
                                        className="flex-1 py-2.5 px-4 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        {adding ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Provisioning...</> : 'Create Account'}
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Users List (full width now) ── */}
            <div className="space-y-4">
                    {/* Filter bar */}
                    <div className="flex flex-wrap items-center gap-3">
                        <div className="relative flex-1 min-w-[180px]">
                            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                            <input
                                type="text"
                                placeholder="Search username..."
                                value={search}
                                onChange={e => setSearch(e.target.value)}
                                className="pl-9 pr-4 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 w-full"
                            />
                        </div>
                        <select
                            value={roleFilter}
                            onChange={e => setRoleFilter(e.target.value)}
                            className="px-3 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                        >
                            <option value="">All Roles</option>
                            <option value="admin">Admin</option>
                            <option value="analyst">Analyst</option>
                        </select>
                        <button
                            onClick={() => fetchUsers(page)}
                            className="p-2 text-slate-500 hover:text-primary-600 hover:bg-primary-50 dark:hover:bg-primary-500/10 rounded-lg transition-colors"
                            title="Refresh"
                        >
                            <RefreshCw className="w-4 h-4" />
                        </button>
                    </div>

                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-800/20">
                            <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">Active Directory</h2>
                            <span className="text-xs text-slate-500">{total} account{total !== 1 ? 's' : ''}</span>
                        </div>

                        {fetchError && <div className="p-6 text-red-500 text-sm flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> {fetchError}</div>}

                        {loading ? (
                            <div className="p-12 flex justify-center"><Activity className="w-8 h-8 text-primary-500 animate-spin" /></div>
                        ) : !fetchError && (
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800">
                                            {['ID', 'Username', 'Role', 'Status', 'Actions'].map(h => (
                                                <th key={h} className="px-4 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{h}</th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                        {filtered.map(u => (
                                            <tr key={u.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                                <td className="px-4 py-3 text-xs font-mono text-slate-500">#{u.id}</td>
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-2 flex-wrap">
                                                        <span className="text-sm font-medium text-slate-900 dark:text-white">{u.username}</span>
                                                        {u.username === user.username && (
                                                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-primary-100 text-primary-700 dark:bg-primary-500/10 dark:text-primary-400 border border-primary-200 dark:border-primary-500/20">YOU</span>
                                                        )}
                                                        {u.totp_enabled && (
                                                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border border-green-200 dark:border-green-500/20">2FA</span>
                                                        )}
                                                        {u.locked_target && (
                                                            <span className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20" title={`Authorized target: ${u.locked_target}`}>
                                                                <MapPin className="w-2.5 h-2.5" />
                                                                {u.locked_target}
                                                            </span>
                                                        )}
                                                    </div>
                                                    {u.last_login && (
                                                        <div className="text-[10px] text-slate-400 mt-0.5">
                                                            Last login: {new Date(u.last_login).toLocaleDateString()}
                                                        </div>
                                                    )}
                                                </td>
                                                <td className="px-4 py-3">
                                                    {u.role === 'admin' ? (
                                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400 border border-purple-200 dark:border-purple-500/20">
                                                            <ShieldCheck className="w-3 h-3" /> Admin
                                                        </span>
                                                    ) : (
                                                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20">Analyst</span>
                                                    )}
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div className="flex flex-col gap-1.5">
                                                        {/* Status badge */}
                                                        {u.is_active ? (
                                                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border border-green-200 dark:border-green-500/20 w-fit">
                                                                <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block" />
                                                                Active
                                                            </span>
                                                        ) : (
                                                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border border-red-200 dark:border-red-500/20 w-fit">
                                                                <Ban className="w-2.5 h-2.5" />
                                                                Blocked
                                                            </span>
                                                        )}

                                                        {/* Block / Unblock button */}
                                                        {u.username !== user.username && (
                                                            <button
                                                                onClick={() => {
                                                                    if (u.is_active) {
                                                                        if (window.confirm(`Block "${u.username}"?\nThey will not be able to log in until unblocked.`))
                                                                            handlePatch(u.id, { is_active: false });
                                                                    } else {
                                                                        handlePatch(u.id, { is_active: true });
                                                                    }
                                                                }}
                                                                className={`inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-semibold transition-all hover:scale-[1.03] active:scale-[0.97] w-fit ${
                                                                    u.is_active
                                                                        ? 'bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-500/20 border border-red-200 dark:border-red-500/20'
                                                                        : 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-500/20 border border-green-200 dark:border-green-500/20'
                                                                }`}
                                                            >
                                                                {u.is_active
                                                                    ? <><ShieldOff className="w-2.5 h-2.5" /> Block</>
                                                                    : <><ShieldCheck className="w-2.5 h-2.5" /> Unblock</>
                                                                }
                                                            </button>
                                                        )}
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-1">
                                                        <Link
                                                            to={`/audit?user_id=${u.id}`}
                                                            className="p-1.5 text-slate-400 hover:text-primary-600 hover:bg-primary-50 dark:hover:bg-primary-500/10 dark:hover:text-primary-400 rounded-lg transition-colors"
                                                            title="View Audit Logs"
                                                        >
                                                            <FileText className="w-3.5 h-3.5" />
                                                        </Link>
                                                        <button
                                                            onClick={() => handlePatch(u.id, { reset_failed_attempts: true })}
                                                            disabled={u.username === user.username}
                                                            className="p-1.5 text-slate-400 hover:text-yellow-600 hover:bg-yellow-50 dark:hover:bg-yellow-500/10 dark:hover:text-yellow-400 rounded-lg transition-colors disabled:opacity-30"
                                                            title="Reset failed login attempts"
                                                        >
                                                            <RefreshCw className="w-3.5 h-3.5" />
                                                        </button>
                                                        {u.totp_enabled && (
                                                            <button
                                                                onClick={() => handlePatch(u.id, { totp_enabled: false })}
                                                                disabled={u.username === user.username}
                                                                className="p-1.5 text-slate-400 hover:text-orange-600 hover:bg-orange-50 dark:hover:bg-orange-500/10 dark:hover:text-orange-400 rounded-lg transition-colors disabled:opacity-30"
                                                                title="Disable 2FA"
                                                            >
                                                                <KeyRound className="w-3.5 h-3.5" />
                                                            </button>
                                                        )}
                                                        {/* Set / Edit allowed target — analysts only */}
                                                        {u.role === 'analyst' && u.username !== user.username && (
                                                            <button
                                                                onClick={() => {
                                                                    const current = u.locked_target || '';
                                                                    const input = window.prompt(
                                                                        `Set allowed target for "${u.username}"\n\nEnter a domain or IP (e.g. example.com).\nLeave blank to remove the restriction.`,
                                                                        current
                                                                    );
                                                                    if (input === null) return; // cancelled
                                                                    handlePatch(u.id, { set_allowed_target: input.trim() });
                                                                }}
                                                                className="p-1.5 text-slate-400 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-500/10 dark:hover:text-blue-400 rounded-lg transition-colors"
                                                                title={u.locked_target ? `Edit allowed target (current: ${u.locked_target})` : 'Set allowed target'}
                                                            >
                                                                <Globe className="w-3.5 h-3.5" />
                                                            </button>
                                                        )}
                                                        {/* Clear allowed target */}
                                                        {u.locked_target && u.username !== user.username && (
                                                            <button
                                                                onClick={() => {
                                                                    if (window.confirm(`Remove target restriction for "${u.username}"?\nThey will be able to scan any target.`))
                                                                        handlePatch(u.id, { reset_locked_target: true });
                                                                }}
                                                                className="p-1.5 text-slate-400 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-500/10 dark:hover:text-amber-400 rounded-lg transition-colors"
                                                                title={`Remove target restriction (current: ${u.locked_target})`}
                                                            >
                                                                <Unlock className="w-3.5 h-3.5" />
                                                            </button>
                                                        )}
                                                        <button
                                                            onClick={() => handleDelete(u.id, u.username)}
                                                            disabled={u.username === user.username}
                                                            className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 dark:hover:text-red-400 rounded-lg transition-colors disabled:opacity-30 disabled:cursor-default"
                                                            title="Revoke Access"
                                                        >
                                                            <Trash2 className="w-3.5 h-3.5" />
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                        {filtered.length === 0 && (
                                            <tr>
                                                <td colSpan="5" className="px-6 py-12 text-center text-sm text-slate-500">No users found.</td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {/* Pagination */}
                        {totalPages > 1 && (
                            <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                                <span className="text-xs text-slate-500">Page {page} of {totalPages}</span>
                                <div className="flex items-center gap-1">
                                    <button
                                        onClick={() => setPage(p => Math.max(1, p - 1))}
                                        disabled={page === 1}
                                        className="p-1.5 rounded-lg text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30 transition-colors"
                                    >
                                        <ChevronLeft className="w-4 h-4" />
                                    </button>
                                    <button
                                        onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                                        disabled={page === totalPages}
                                        className="p-1.5 rounded-lg text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30 transition-colors"
                                    >
                                        <ChevronRight className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
            </div>
        </div>
    );
};

export default AdminUsersPage;
