import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { Users, AlertTriangle, ShieldCheck, UserPlus, Trash2, ArrowLeft, Activity } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const AdminUsersPage = () => {
    const { user } = useAuth();
    const [usersList, setUsersList] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [newUsername, setNewUsername] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [newRole, setNewRole] = useState('operator');
    const [adding, setAdding] = useState(false);

    const fetchUsers = async () => {
        try {
            const { data } = await axios.get('/api/admin/users', { withCredentials: true });
            setUsersList(data.users);
            setError('');
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load users');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchUsers();
    }, []);

    const handleCreateUser = async (e) => {
        e.preventDefault();
        setAdding(true);
        try {
            await axios.post('/api/admin/users', {
                username: newUsername,
                password: newPassword,
                role: newRole
            }, { withCredentials: true });
            setNewUsername('');
            setNewPassword('');
            fetchUsers();
        } catch (err) {
            alert(err.response?.data?.error || 'Failed to create user');
        } finally {
            setAdding(false);
        }
    };

    const handleDelete = async (uid, targetUsername) => {
        if (!window.confirm(`Delete user ${targetUsername}?`)) return;
        try {
            await axios.delete(`/api/admin/users/${uid}`, { withCredentials: true });
            fetchUsers();
        } catch (err) {
            alert(err.response?.data?.error || 'Failed to delete user');
        }
    };

    if (user?.role !== 'admin') {
        return (
            <div className="h-64 flex items-center justify-center">
                <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-6 rounded-xl flex items-center gap-3">
                    <AlertTriangle className="w-6 h-6" />
                    <div>
                        <h3 className="font-bold">Access Denied</h3>
                        <p className="text-sm">Administrator privileges required.</p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="animate-in fade-in duration-500">
            <div className="mb-8">
                <Link to="/admin" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Admin Panel
                </Link>
                <div>
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Users className="w-8 h-8 text-primary-500" />
                        User Management
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm max-w-2xl">
                        Create, modify, and revoke access for platform operators.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                
                {/* Create User Form */}
                <div className="lg:col-span-4 space-y-6">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                        <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-6 flex items-center gap-2">
                            <UserPlus className="w-4 h-4" /> Provision New Account
                        </h2>
                        <form onSubmit={handleCreateUser} className="space-y-4">
                            <div>
                                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Username</label>
                                <input 
                                    value={newUsername}
                                    onChange={e => setNewUsername(e.target.value)}
                                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white placeholder-slate-400 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 transition-shadow"
                                    placeholder="operator1"
                                    required
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Access Token</label>
                                <input 
                                    type="password"
                                    value={newPassword}
                                    onChange={e => setNewPassword(e.target.value)}
                                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white placeholder-slate-400 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 transition-shadow"
                                    placeholder="••••••••"
                                    required
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Clearance Level</label>
                                <select 
                                    value={newRole}
                                    onChange={e => setNewRole(e.target.value)}
                                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 transition-shadow text-sm"
                                >
                                    <option value="operator">Operator (Standard)</option>
                                    <option value="admin">Administrator (Full Access)</option>
                                </select>
                            </div>
                            <button 
                                type="submit" 
                                disabled={adding || !newUsername || !newPassword}
                                className="w-full mt-2 py-3 px-4 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20 disabled:opacity-50"
                            >
                                {adding ? 'Provisioning...' : 'Create Account'}
                            </button>
                        </form>
                    </div>
                </div>

                {/* Users List */}
                <div className="lg:col-span-8">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-800/20">
                            <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">Active Directory</h2>
                        </div>
                        
                        {loading ? (
                            <div className="p-12 flex justify-center"><Activity className="w-8 h-8 text-primary-500 animate-spin" /></div>
                        ) : error ? (
                            <div className="p-6 text-red-500 text-sm">{error}</div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-left border-collapse">
                                    <thead>
                                        <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800">
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">ID</th>
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Username</th>
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Role</th>
                                            <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                        {usersList.map((u) => (
                                            <tr key={u.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                                <td className="px-6 py-4 text-xs font-mono text-slate-500 dark:text-slate-400">#{u.id}</td>
                                                <td className="px-6 py-4">
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-sm font-medium text-slate-900 dark:text-white">{u.username}</span>
                                                        {u.username === user.username && (
                                                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-primary-100 text-primary-700 dark:bg-primary-500/10 dark:text-primary-400 border border-primary-200 dark:border-primary-500/20">YOU</span>
                                                        )}
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4">
                                                    {u.role === 'admin' ? (
                                                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400 border border-purple-200 dark:border-purple-500/20">
                                                            <ShieldCheck className="w-3.5 h-3.5" /> Admin
                                                        </span>
                                                    ) : (
                                                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                                                            Operator
                                                        </span>
                                                    )}
                                                </td>
                                                <td className="px-6 py-4 text-right">
                                                    <button
                                                        onClick={() => handleDelete(u.id, u.username)}
                                                        disabled={u.username === user.username}
                                                        className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 dark:hover:text-red-400 rounded-lg transition-colors disabled:opacity-30 disabled:hover:bg-transparent"
                                                        title="Revoke Access"
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                        {usersList.length === 0 && (
                                            <tr>
                                                <td colSpan="4" className="px-6 py-12 text-center text-sm text-slate-500">No users found.</td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AdminUsersPage;
