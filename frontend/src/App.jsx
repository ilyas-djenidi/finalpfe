import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link } from 'react-router-dom';
import { AuthProvider, useAuth, ToastContainer } from './context/AuthContext';

// Layout & Components
import Layout from './components/Layout';
import ChatBot from './components/ChatBot';

// Public Pages
import LoginPage    from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';

// Authenticated Pages
import DashboardPage    from './pages/DashboardPage';
import WebScanPage      from './pages/WebScanPage';
import ApacheScanPage   from './pages/ApacheScanPage';
import CodeScanPage     from './pages/CodeScanPage';
import NetworkScanPage  from './pages/NetworkScanPage';
import DastScanPage     from './pages/DastScanPage';
import DependencyScanPage from './pages/DependencyScanPage';
import ReportPage       from './pages/ReportPage';

// Admin Pages
import AdminUsersPage     from './pages/AdminUsersPage';
import AdminScansPage     from './pages/AdminScansPage';
import AuditLogPage       from './pages/AuditLogPage';
import ChatPage           from './pages/ChatPage';
import LandingPage        from './pages/LandingPage';


// ── Error Boundary ─────────────────────────────────────────────────────────
class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, message: '' };
    }
    static getDerivedStateFromError(err) {
        return { hasError: true, message: err?.message || 'Unknown error' };
    }
    componentDidCatch(err, info) {
        console.error('[ErrorBoundary]', err, info);
    }
    render() {
        if (!this.state.hasError) return this.props.children;
        return (
            <div className="min-h-screen bg-black flex items-center justify-center p-8">
                <div className="max-w-md text-center space-y-6">
                    <div className="text-6xl font-orbitron font-black text-red-500">ERR</div>
                    <h2 className="text-white text-xl font-orbitron">Something went wrong</h2>
                    <p className="text-gray-500 font-inter text-sm">{this.state.message}</p>
                    <button
                        onClick={() => { this.setState({ hasError: false }); window.location.reload(); }}
                        className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white font-orbitron text-xs tracking-widest uppercase rounded-xl transition-colors"
                    >
                        Reload Page
                    </button>
                </div>
            </div>
        );
    }
}


// ── 404 Page ────────────────────────────────────────────────────────────────
const NotFoundPage = () => (
    <div className="min-h-screen bg-black flex items-center justify-center p-8">
        <div className="max-w-md text-center space-y-6">
            <div className="text-8xl font-orbitron font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-500 to-purple-500">
                404
            </div>
            <h2 className="text-white text-xl font-orbitron tracking-widest uppercase">Page Not Found</h2>
            <p className="text-gray-500 font-inter text-sm">
                The route you requested does not exist.
            </p>
            <Link
                to="/dashboard"
                className="inline-block px-6 py-3 bg-gradient-to-r from-cyan-600 to-purple-600 text-white font-orbitron text-xs tracking-widest uppercase rounded-xl hover:from-cyan-500 hover:to-purple-500 transition-all"
            >
                Return to Dashboard
            </Link>
        </div>
    </div>
);


// ── Protected Route ────────────────────────────────────────────────────────
const ProtectedRoute = ({ element, adminOnly = false }) => {
    const { user, loading } = useAuth();
    if (loading) return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center">
            <div className="flex gap-1">
                {[0,1,2,3,4].map(i => (
                    <div
                        key={i}
                        className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce"
                        style={{ animationDelay: `${i * 0.12}s` }}
                    />
                ))}
            </div>
        </div>
    );
    if (!user)                                   return <Navigate to="/login"     replace />;
    if (adminOnly && user.role !== 'admin')      return <Navigate to="/dashboard" replace />;
    return <Layout>{element}</Layout>;
};


// ── Smart Root Redirect ────────────────────────────────────────────────────
const RootRedirect = () => {
    const { user, loading } = useAuth();
    if (loading) return null;
    return <Navigate to={user ? '/dashboard' : '/landing'} replace />;
};

// ── App Root ───────────────────────────────────────────────────────────────
function AppInner() {
    React.useEffect(() => {
        const ping = () => fetch('/health').catch(() => {});
        ping();
        const interval = setInterval(ping, 10 * 60 * 1000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-950 font-inter text-slate-900 dark:text-slate-50 transition-colors duration-300">
            <ToastContainer />
            <Routes>
                {/* Public */}
                <Route path="/"         element={<RootRedirect />} />
                <Route path="/landing"  element={<LandingPage />} />
                <Route path="/login"    element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />

                {/* Scan routes — require login */}
                <Route path="/scan/web"          element={<ProtectedRoute element={<WebScanPage />} />} />
                <Route path="/web-scan"          element={<Navigate to="/scan/web"      replace />} />

                <Route path="/scan/apache"       element={<ProtectedRoute element={<ApacheScanPage />} />} />
                <Route path="/apache-scan"       element={<Navigate to="/scan/apache"   replace />} />

                <Route path="/scan/code"         element={<ProtectedRoute element={<CodeScanPage />} />} />
                <Route path="/code-scan"         element={<Navigate to="/scan/code"     replace />} />

                <Route path="/scan/network"      element={<ProtectedRoute element={<NetworkScanPage />} />} />
                <Route path="/network-scan"      element={<Navigate to="/scan/network"  replace />} />

                <Route path="/scan/dast"         element={<ProtectedRoute element={<DastScanPage />} />} />
                <Route path="/dast-scan"         element={<Navigate to="/scan/dast"     replace />} />

                <Route path="/scan/dependencies" element={<ProtectedRoute element={<DependencyScanPage />} />} />
                <Route path="/dependency-scan"   element={<Navigate to="/scan/dependencies" replace />} />

                {/* New route aliases for reorganized nav */}
                <Route path="/scan/network-ext"  element={<ProtectedRoute element={<NetworkScanPage />} />} />
                <Route path="/scan/server-ext"   element={<ProtectedRoute element={<ApacheScanPage />} />} />

                {/* Reports & Dashboard */}
                <Route path="/reports"           element={<ProtectedRoute element={<ReportPage />} />} />
                <Route path="/reports/:token"    element={<ProtectedRoute element={<ReportPage />} />} />
                <Route path="/dashboard"         element={<ProtectedRoute element={<DashboardPage />} />} />

                {/* Admin */}
                <Route path="/admin"             element={<Navigate to="/dashboard" replace />} />
                <Route path="/admin/users"       element={<ProtectedRoute element={<AdminUsersPage />}     adminOnly />} />
                <Route path="/admin/scans"       element={<ProtectedRoute element={<AdminScansPage />}     adminOnly />} />
                <Route path="/audit"             element={<ProtectedRoute element={<AuditLogPage />}       adminOnly />} />

                {/* AI Chat */}
                <Route path="/chat"              element={<ProtectedRoute element={<ChatPage />} />} />

                {/* 404 */}
                <Route path="*" element={<NotFoundPage />} />
            </Routes>
        </div>
    );
}

function App() {
    return (
        <BrowserRouter>
            <ErrorBoundary>
                <AuthProvider>
                    <AppInner />
                </AuthProvider>
            </ErrorBoundary>
        </BrowserRouter>
    );
}

export default App;
