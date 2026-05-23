import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

// ── Toast system (no external library) ────────────────────────────────────────
export const showToast = (message, type = 'error') => {
    window.dispatchEvent(new CustomEvent('cybrain-toast', { detail: { message, type, id: Date.now() + Math.random() } }));
};

export const ToastContainer = () => {
    const [toasts, setToasts] = useState([]);

    useEffect(() => {
        const handle = (e) => {
            const t = e.detail;
            setToasts(prev => [...prev.slice(-4), t]);
            setTimeout(() => setToasts(prev => prev.filter(x => x.id !== t.id)), 4000);
        };
        window.addEventListener('cybrain-toast', handle);
        return () => window.removeEventListener('cybrain-toast', handle);
    }, []);

    if (!toasts.length) return null;
    return (
        <div className="fixed top-4 right-4 z-[9999] flex flex-col gap-2 pointer-events-none">
            {toasts.map(t => (
                <div
                    key={t.id}
                    className={`px-4 py-3 rounded-xl text-sm font-medium shadow-lg border max-w-sm backdrop-blur-sm animate-in slide-in-from-right-2 duration-300 ${
                        t.type === 'warning'
                            ? 'bg-orange-50 dark:bg-orange-900/80 border-orange-200 dark:border-orange-700 text-orange-700 dark:text-orange-300'
                            : t.type === 'success'
                            ? 'bg-green-50 dark:bg-green-900/80 border-green-200 dark:border-green-700 text-green-700 dark:text-green-300'
                            : 'bg-red-50 dark:bg-red-900/80 border-red-200 dark:border-red-700 text-red-700 dark:text-red-300'
                    }`}
                >
                    {t.message}
                </div>
            ))}
        </div>
    );
};

// ── Global axios defaults ──────────────────────────────────────────────────────
axios.defaults.withCredentials = true;

// ── CSRF token management ──────────────────────────────────────────────────────
const _fetchCsrfToken = async () => {
    try {
        const resp = await axios.get('/api/auth/me');
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

// Module-level refs so the interceptor can call React callbacks
const _authRef = { logout: null, navigate: null };

// Set up the global interceptor once (idempotent via module flag)
let _interceptorInstalled = false;
function _installInterceptor() {
    if (_interceptorInstalled) return;
    _interceptorInstalled = true;

    const AUTH_URLS = ['/api/auth/login', '/api/auth/register', '/api/auth/me', '/api/auth/totp-verify'];

    axios.interceptors.response.use(
        r => r,
        async (err) => {
            const status  = err.response?.status;
            const url     = err.config?.url || '';
            const isAuth  = AUTH_URLS.some(u => url.includes(u));

            if (status === 401 && !isAuth) {
                showToast('Session expired — please log in again', 'warning');
                if (_authRef.logout) await _authRef.logout();
                if (_authRef.navigate) _authRef.navigate('/login');
            } else if (status === 403 && !isAuth) {
                showToast("You don't have permission for this action", 'error');
            } else if (status === 429) {
                const retryAfter = err.response?.headers?.['retry-after'];
                const wait = retryAfter ? ` — please wait ${retryAfter}s` : ' — please wait';
                showToast(`Too many requests${wait}`, 'warning');
            } else if (!err.response && !isAuth) {
                showToast('Connection error — check your network', 'error');
            }
            return Promise.reject(err);
        }
    );
}

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user,    setUser]    = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    // Keep refs fresh so the interceptor can use them without stale closures
    const logout = useCallback(async () => {
        try { await axios.post('/api/auth/logout', {}); } catch { /* swallow */ }
        setUser(false);
        delete axios.defaults.headers.common['X-CSRFToken'];
    }, []);

    useEffect(() => {
        _authRef.logout   = logout;
        _authRef.navigate = navigate;
    }, [logout, navigate]);

    // Install interceptor on mount (once per app lifetime)
    useEffect(() => { _installInterceptor(); }, []);

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

    // Refresh auth + CSRF every 25 minutes
    useEffect(() => {
        const interval = setInterval(fetchMe, 25 * 60 * 1000);
        return () => clearInterval(interval);
    }, [fetchMe]);

    const login = async (username, password) => {
        const { data } = await axios.post('/api/auth/login', { username, password });
        if (data.ok) {
            setUser(data.user);
            await _fetchCsrfToken();
        }
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
