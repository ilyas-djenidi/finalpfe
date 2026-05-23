import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import {
    Users, AlertTriangle, ShieldCheck, UserPlus, Trash2,
    ArrowLeft, Activity, FileText, ToggleLeft, ToggleRight,
    Search, ChevronLeft, ChevronRight, RefreshCw, KeyRound
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const AdminUsersPage = () => {
    const { user } = useAuth();
    const [usersList, setUsersList]         = useState([]);
    const [loading, setLoading]             = useState(true);
    const [fetchError, setFetchError]       = useState('');
    const [newUsername, setNewUsername]     = useState('');
    const [newPassword, setNewPassword]     = useState('');
    const [confirmPw, setConfirmPw]         = useState('');
    const [newRole, setNewRole]             = useState('operator');
    const [adding, setAdding]               = useState(false);
    const [createError, setCreateError]     = useState('');
    const [createSuccess, setCreateSuccess] = useState('');

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
            }, { withCredentials: true });
            if (data.ok) {
                setCreateSuccess(`Account "${newUsername}" created.`);
                setNewUsername(''); setNewPassword(''); setConfirmPw('');
                fetchUsers(1); setPage(1);
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

    return (
        <div className="animate-in fade-in duration-500">
            <div className="mb-8">
                <Link to="/admin" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Admin Panel
                </Link>
                <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                    <Users className="w-8 h-8 text-primary-500" /> User Management
                </h1>
                <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">Provision, modify, and revoke access for platform operators.</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                {/* Create User Form */}
                <div className="lg:col-span-4 space-y-6">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                        <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-6 flex items-center gap-2">
                            <UserPlus className="w-4 h-4" /> Provision New Account
                        </h2>

                        {createError && (
                            <div className="mb-4 flex items-start gap-2 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-lg px-3 py-2.5">
                                <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                                <p className="text-red-700 dark:text-red-400 text-xs font-medium">{createError}</p>
                            </div>
                        )}
                        {createSuccess && (
                            <div className="mb-4 bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 rounded-lg px-3 py-2.5">
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
                                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Clearance Level</label>
                                <select
                                    value={newRole}
                                    onChange={e => setNewRole(e.target.value)}
                                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm"
                                >
                                    <option value="operator">Operator (Standard)</option>
                                    <option value="analyst">Analyst (Read-only)</option>
                                    <option value="admin">Administrator (Full Access)</option>
                                </select>
                            </div>
                            <p className="text-[10px] text-slate-400">Password must be ≥10 chars with upper, lower, digit, and symbol.</p>
                            <button
                                type="submit"
                                disabled={adding || !newUsername || !newPassword || newPassword !== confirmPw}
                                className="w-full mt-2 py-3 px-4 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {adding ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Provisioning...</> : 'Create Account'}
                            </button>
                        </form>
                    </div>
                </div>

                {/* Users List */}
                <div className="lg:col-span-8 space-y-4">
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
                            <option value="operator">Operator</option>
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
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-sm font-medium text-slate-900 dark:text-white">{u.username}</span>
                                                        {u.username === user.username && (
                                                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-primary-100 text-primary-700 dark:bg-primary-500/10 dark:text-primary-400 border border-primary-200 dark:border-primary-500/20">YOU</span>
                                                        )}
                                                        {u.totp_enabled && (
                                                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border border-green-200 dark:border-green-500/20">2FA</span>
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
                                                    ) : u.role === 'analyst' ? (
                                                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20">Analyst</span>
                                                    ) : (
                                                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400 border border-slate-200 dark:border-slate-700">Operator</span>
                                                    )}
                                                </td>
                                                <td className="px-4 py-3">
                                                    <button
                                                        onClick={() => handlePatch(u.id, { is_active: !u.is_active })}
                                                        disabled={u.username === user.username}
                                                        className="flex items-center gap-1 text-xs font-medium transition-colors disabled:opacity-40 disabled:cursor-default"
                                                        title={u.is_active ? 'Click to deactivate' : 'Click to activate'}
                                                    >
                                                        {u.is_active ? (
                                                            <><ToggleRight className="w-5 h-5 text-green-500" /><span className="text-green-600 dark:text-green-400">Active</span></>
                                                        ) : (
                                                            <><ToggleLeft className="w-5 h-5 text-slate-400" /><span className="text-slate-500">Inactive</span></>
                                                        )}
                                                    </button>
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
        </div>
    );
};

export default AdminUsersPage;
