import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';

// ── Global axios defaults ──────────────────────────────────────────────────
// All requests send session cookie automatically.
axios.defaults.withCredentials = true;

// ── CSRF token management ──────────────────────────────────────────────────
// Flask-WTF stores the CSRF token in a cookie named "csrftoken" (or reads it
// from the meta tag). We fetch it once and attach it as a request header so
// every non-exempt POST/PATCH/DELETE succeeds without 400 CSRF errors.
const _fetchCsrfToken = async () => {
    try {
        // /api/auth/me is a safe GET — its response cookie carries the CSRF token
        const resp = await axios.get('/api/auth/me');
        // Flask-WTF sets X-CSRFToken header on responses; fall back to cookie
        const fromHeader = resp.headers?.['x-csrftoken'];
        const fromCookie = document.cookie
            .split('; ')
            .find(r => r.startsWith('csrftoken='))
            ?.split('=')[1];
        const token = fromHeader || fromCookie || '';
        if (token) {
            axios.defaults.headers.common['X-CSRFToken'] = token;
        }
        return resp.data;
    } catch {
        return null;
    }
};

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user,    setUser]    = useState(null);   // null = loading
    const [loading, setLoading] = useState(true);

    const fetchMe = useCallback(async () => {
        try {
            const data = await _fetchCsrfToken();
            setUser(data?.authenticated ? data.user : false);
        } catch {
            setUser(false);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchMe(); }, [fetchMe]);

    // Refresh auth state + CSRF token every 25 minutes (session lifetime is 30 min)
    useEffect(() => {
        const interval = setInterval(fetchMe, 25 * 60 * 1000);
        return () => clearInterval(interval);
    }, [fetchMe]);

    const login = async (username, password) => {
        const { data } = await axios.post('/api/auth/login', { username, password });
        if (data.ok) {
            setUser(data.user);
            // Refresh CSRF token after successful login
            await _fetchCsrfToken();
        }
        // Caller checks data.totp_required to show TOTP step
        return data;
    };

    const verifyTotp = async (token) => {
        const { data } = await axios.post('/api/auth/totp-verify', { token });
        if (data.ok) {
            setUser(data.user);
            await _fetchCsrfToken();
        }
        return data;
    };

    const logout = async () => {
        try {
            await axios.post('/api/auth/logout', {});
        } catch { /* swallow */ }
        setUser(false);
        delete axios.defaults.headers.common['X-CSRFToken'];
    };

    const register = async (username, password) => {
        const { data } = await axios.post('/api/auth/register', { username, password });
        return data;
    };

    return (
        <AuthContext.Provider value={{ user, loading, login, logout, register, verifyTotp, refetch: fetchMe }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const ctx = useContext(AuthContext);
    if (!ctx) throw new Error('useAuth must be inside AuthProvider');
    return ctx;
};
