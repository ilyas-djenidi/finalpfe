import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import {
    Send, RotateCcw, Shield, Terminal, Zap, Layers,
    Globe, Key, Package, Bug, ChevronRight,
} from 'lucide-react';

// ── Topic shortcuts ───────────────────────────────────────────────────────────

const TOPICS = [
    { icon: Shield,   title: 'Authentication',  q: 'How do I implement secure authentication with MFA and session management?' },
    { icon: Terminal, title: 'SQL Injection',    q: 'Explain SQL injection with a real attack example and how to prevent it in Python' },
    { icon: Zap,      title: 'XSS Attacks',      q: 'What is Cross-Site Scripting? Show me attack payloads and CSP fixes' },
    { icon: Layers,   title: 'OWASP Top 10',     q: 'Walk me through the OWASP Top 10 2025 with the most critical risks' },
    { icon: Globe,    title: 'Cloud Security',   q: 'What are the most common AWS/cloud misconfigurations and how to fix them?' },
    { icon: Key,      title: 'API Security',     q: 'How do I secure a REST API? Cover authentication, rate limiting, and input validation' },
    { icon: Package,  title: 'Dependencies',     q: 'How do I audit and fix vulnerable npm/pip dependencies in my project?' },
    { icon: Bug,      title: 'Pen Testing',      q: 'What is a penetration testing methodology? Explain recon, scanning, exploitation' },
];

const SCAN_CONTEXTS = [
    { label: 'General',      context: null },
    { label: 'Web Scan',     context: { target: 'example.com',  risk: 'high',     total: 12, scan_type: 'web' } },
    { label: 'Network',      context: { target: '192.168.1.1',  risk: 'critical',  total: 5,  scan_type: 'network_ext' } },
    { label: 'Code Review',  context: { target: 'app.py',       risk: 'medium',   total: 8,  scan_type: 'sast' } },
];

const QUICK_QUESTIONS = [
    'What is SQL injection?',
    'How to prevent XSS?',
    'Explain OWASP Top 10',
    'Secure REST API best practices',
];

// ── Markdown renderer (platform theme) ───────────────────────────────────────

function encodeCode(str) {
    try { return btoa(unescape(encodeURIComponent(str))); }
    catch { return btoa(str); }
}

function renderMarkdown(text) {
    if (!text) return '';
    return text
        .replace(/^### (.+)$/gm, '<h3 class="text-primary-600 dark:text-primary-400 font-bold text-sm mt-3 mb-1">$1</h3>')
        .replace(/^## (.+)$/gm,  '<h2 class="text-slate-800 dark:text-slate-100 font-bold text-sm mt-4 mb-1">$1</h2>')
        .replace(/^# (.+)$/gm,   '<h1 class="text-slate-900 dark:text-white font-bold text-base mt-4 mb-2">$1</h1>')
        .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
        .replace(/\*\*(.+?)\*\*/g,     '<strong class="font-semibold text-slate-900 dark:text-white">$1</strong>')
        .replace(/\*(.+?)\*/g,         '<em>$1</em>')
        .replace(/`([^`\n]+)`/g, '<code class="bg-slate-100 dark:bg-slate-800 text-primary-600 dark:text-primary-400 px-1.5 py-0.5 rounded-md font-mono text-[11px] border border-slate-200 dark:border-slate-700">$1</code>')
        .replace(/^---$/gm, '<hr class="border-slate-200 dark:border-slate-700 my-3" />')
        .replace(/^[•\-] (.+)$/gm, '<div class="flex gap-2 my-0.5"><span class="text-primary-500 font-bold flex-shrink-0 mt-0.5">▸</span><span>$1</span></div>')
        .replace(/^\d+\. (.+)$/gm, '<div class="flex gap-2 my-0.5"><span class="text-primary-500 font-bold flex-shrink-0">›</span><span>$1</span></div>')
        .replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
            const encoded = encodeCode(code.trim());
            return `<div class="my-3 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700">
              <div class="flex items-center justify-between bg-slate-100 dark:bg-slate-800 px-3 py-1.5 border-b border-slate-200 dark:border-slate-700">
                <span class="text-[10px] text-slate-500 dark:text-slate-400 font-mono uppercase tracking-wider">${lang || 'code'}</span>
                <button data-copy="${encoded}" class="copy-btn text-[10px] text-slate-500 hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400 font-medium transition-colors px-2 py-0.5 rounded hover:bg-slate-200 dark:hover:bg-slate-700">Copy</button>
              </div>
              <pre class="bg-slate-950 p-4 text-[11px] text-emerald-400 font-mono overflow-x-auto leading-relaxed">${code.trim()}</pre>
            </div>`;
        })
        .replace(/\n/g, '<br />');
}

// ── Sub-components ────────────────────────────────────────────────────────────

function TypingIndicator() {
    return (
        <div className="flex items-center gap-1.5 px-1 py-2">
            {[0, 1, 2].map(i => (
                <motion.span
                    key={i}
                    className="w-2 h-2 rounded-full bg-primary-400"
                    animate={{ y: [0, -5, 0], opacity: [0.4, 1, 0.4] }}
                    transition={{ duration: 0.8, repeat: Infinity, delay: i * 0.15 }}
                />
            ))}
        </div>
    );
}

function MessageBubble({ msg }) {
    const isUser = msg.role === 'user';
    const bubbleRef = useRef(null);

    useEffect(() => {
        if (!bubbleRef.current || isUser) return;
        const buttons = bubbleRef.current.querySelectorAll('.copy-btn');
        buttons.forEach(btn => {
            const handler = () => {
                try {
                    const code = decodeURIComponent(escape(atob(btn.dataset.copy)));
                    navigator.clipboard.writeText(code);
                    btn.textContent = 'Copied!';
                    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
                } catch { /* clipboard blocked */ }
            };
            btn.addEventListener('click', handler);
        });
    }, [msg.content, isUser]);

    return (
        <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2 }}
            className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'}`}
        >
            {!isUser && (
                <div className="flex-shrink-0 w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 dark:border-cyan-500/20 flex items-center justify-center mt-1 shadow-sm">
                    <span className="text-cyan-500 dark:text-cyan-400 text-sm">✦</span>
                </div>
            )}

            <div className={`max-w-[78%] flex flex-col gap-1 ${isUser ? 'items-end' : 'items-start'}`}>
                <div
                    ref={bubbleRef}
                    className={`rounded-2xl px-4 py-3 text-sm leading-relaxed ${
                        isUser
                            ? 'bg-primary-600 text-white rounded-tr-sm shadow-md shadow-primary-500/20'
                            : 'bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 rounded-tl-sm shadow-sm'
                    }`}
                >
                    {isUser ? (
                        <p className="whitespace-pre-wrap">{msg.content}</p>
                    ) : (
                        <div dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }} />
                    )}
                </div>
                {msg.time && (
                    <span className="text-[10px] text-slate-400 px-1">{msg.time}</span>
                )}
            </div>

            {isUser && (
                <div className="flex-shrink-0 w-8 h-8 rounded-xl bg-primary-50 dark:bg-primary-500/10 border border-primary-200 dark:border-primary-500/20 flex items-center justify-center mt-1 flex-shrink-0">
                    <span className="text-primary-600 dark:text-primary-400 text-[10px] font-bold">You</span>
                </div>
            )}
        </motion.div>
    );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ChatPage() {
    const [messages, setMessages] = useState([{
        role: 'assistant',
        content: (
            'Hello! I\'m **ARIA** — securAX\'s AI security expert.\n\n' +
            'I can help you:\n' +
            '• Understand vulnerabilities from your scans\n' +
            '• Explain attack techniques & real-world impact\n' +
            '• Recommend specific code fixes\n' +
            '• Answer any cybersecurity question\n\n' +
            'Pick a topic on the left or ask me anything!'
        ),
        time: null,
    }]);
    const [input,      setInput]     = useState('');
    const [loading,    setLoading]   = useState(false);
    const [ariaStatus, setAriaStatus] = useState(null);
    const [activeCtx,  setActiveCtx] = useState(SCAN_CONTEXTS[0]);

    const bottomRef   = useRef(null);
    const inputRef    = useRef(null);

    useEffect(() => {
        axios.get('/api/ai/status', { withCredentials: true }).then(r => setAriaStatus(r.data)).catch(() => {});
    }, []);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages, loading]);

    const now = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const sendMessage = useCallback(async (override) => {
        const msg = (override ?? input).trim();
        if (!msg || loading) return;
        setInput('');
        if (inputRef.current) {
            inputRef.current.style.height = 'auto';
        }

        setMessages(prev => [...prev, { role: 'user', content: msg, time: now() }]);
        setLoading(true);

        try {
            const { data } = await axios.post('/api/ai/chat', {
                message: msg,
                context: activeCtx?.context ?? {},
            }, { withCredentials: true });
            const reply    = data.reply || data.response || '…';
            const provider = data.provider || data.ai_mode || 'offline';
            setMessages(prev => [...prev, { role: 'assistant', content: reply, provider, time: now() }]);
        } catch (err) {
            let errText = '⚠️ Connection error. Please try again.';
            if (err.response?.status === 429)          errText = '⚠️ **Rate limit reached** — please wait 60 seconds.';
            else if (err.response?.status === 401)     errText = '🔒 Session expired. Please refresh the page.';
            else if (err.response?.data?.error)        errText = `⚠️ ${err.response.data.error}`;
            setMessages(prev => [...prev, { role: 'assistant', content: errText, provider: 'offline', time: now() }]);
        } finally {
            setLoading(false);
            setTimeout(() => inputRef.current?.focus(), 50);
        }
    }, [input, loading, activeCtx]);

    const clearHistory = async () => {
        if (!window.confirm('Clear chat and server-side history? ARIA will forget this conversation.')) return;
        try { await axios.post('/api/ai/history/clear', {}, { withCredentials: true }); } catch { /* ignore */ }
        setMessages([{ role: 'assistant', content: '🔄 History cleared. How can I help you?', time: now() }]);
    };

    const statusCfg = ariaStatus?.provider === 'gemini'
        ? { dot: 'bg-green-500', text: 'Gemini Online', cls: 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 border-green-200 dark:border-green-500/20' }
        : ariaStatus?.provider === 'ollama'
        ? { dot: 'bg-blue-500',  text: 'Ollama Local',  cls: 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-500/20' }
        : { dot: 'bg-yellow-500',text: 'Offline Mode',  cls: 'bg-yellow-50 dark:bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20' };

    return (
        <div
            className="flex -my-8 -mx-4 sm:-mx-6 lg:-mx-8 overflow-hidden"
            style={{ height: 'calc(100vh - 4rem)' }}
        >
            {/* ── Left sidebar ─────────────────────────────────────────── */}
            <aside className="w-72 flex-shrink-0 flex flex-col bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 overflow-y-auto">

                {/* ARIA identity */}
                <div className="p-5 border-b border-slate-200 dark:border-slate-800">
                    <div className="flex items-center gap-3 mb-3">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 dark:border-cyan-500/20 flex items-center justify-center flex-shrink-0 shadow-sm">
                            <span className="text-cyan-500 dark:text-cyan-400 text-lg">✦</span>
                        </div>
                        <div>
                            <h1 className="text-sm font-bold text-slate-900 dark:text-white tracking-wide">ARIA AI</h1>
                            <p className="text-xs text-slate-500 dark:text-slate-400">Security Intelligence</p>
                        </div>
                    </div>
                    {ariaStatus && (
                        <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${statusCfg.cls}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${statusCfg.dot}`} />
                            {statusCfg.text}
                            {ariaStatus.model && (
                                <span className="opacity-60 font-mono ml-1 text-[10px]">
                                    {ariaStatus.model.length > 14 ? ariaStatus.model.slice(0, 14) + '…' : ariaStatus.model}
                                </span>
                            )}
                        </div>
                    )}
                </div>

                {/* Scan context */}
                <div className="p-4 border-b border-slate-200 dark:border-slate-800">
                    <p className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-2">Scan Context</p>
                    <div className="grid grid-cols-2 gap-1.5">
                        {SCAN_CONTEXTS.map(ctx => (
                            <button
                                key={ctx.label}
                                onClick={() => setActiveCtx(ctx)}
                                className={`px-2.5 py-2 rounded-lg text-xs font-medium transition-all text-left ${
                                    activeCtx.label === ctx.label
                                        ? 'bg-primary-50 dark:bg-primary-500/10 text-primary-700 dark:text-primary-400 border border-primary-200 dark:border-primary-500/20'
                                        : 'text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800'
                                }`}
                            >
                                {ctx.label}
                            </button>
                        ))}
                    </div>
                    {activeCtx?.context && (
                        <div className="mt-2 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-100 dark:border-slate-700 text-[10px] font-mono space-y-0.5">
                            <div className="text-slate-500 dark:text-slate-400">Target: <span className="text-slate-800 dark:text-slate-200">{activeCtx.context.target}</span></div>
                            <div className="text-slate-500 dark:text-slate-400">Risk: <span className={`font-bold ${
                                activeCtx.context.risk === 'critical' ? 'text-red-600 dark:text-red-400' :
                                activeCtx.context.risk === 'high'     ? 'text-orange-600 dark:text-orange-400' :
                                                                         'text-yellow-600 dark:text-yellow-400'
                            }`}>{activeCtx.context.risk?.toUpperCase()}</span></div>
                        </div>
                    )}
                </div>

                {/* Security topics */}
                <div className="flex-1 p-4">
                    <p className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-3">Security Topics</p>
                    <div className="space-y-0.5">
                        {TOPICS.map(t => {
                            const Icon = t.icon;
                            return (
                                <motion.button
                                    key={t.title}
                                    whileHover={{ x: 2 }}
                                    onClick={() => sendMessage(t.q)}
                                    className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all group hover:bg-slate-50 dark:hover:bg-slate-800"
                                >
                                    <div className="flex-shrink-0 p-1.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 group-hover:bg-primary-50 dark:group-hover:bg-primary-500/10 group-hover:text-primary-600 dark:group-hover:text-primary-400 transition-colors">
                                        <Icon className="w-3.5 h-3.5" />
                                    </div>
                                    <div className="min-w-0 flex-1">
                                        <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-white transition-colors truncate">{t.title}</div>
                                        <div className="text-[10px] text-slate-400 dark:text-slate-500 truncate mt-0.5">{t.q.slice(0, 38)}…</div>
                                    </div>
                                    <ChevronRight className="w-3 h-3 text-slate-300 dark:text-slate-600 group-hover:text-primary-400 transition-colors flex-shrink-0 opacity-0 group-hover:opacity-100" />
                                </motion.button>
                            );
                        })}
                    </div>
                </div>

                {/* Footer */}
                <div className="p-4 border-t border-slate-200 dark:border-slate-800">
                    <button
                        onClick={clearHistory}
                        className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium text-red-600 dark:text-red-400 border border-red-200 dark:border-red-500/20 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors"
                    >
                        <RotateCcw className="w-3.5 h-3.5" />
                        Clear History
                    </button>
                </div>
            </aside>

            {/* ── Main chat area ────────────────────────────────────────── */}
            <main className="flex-1 flex flex-col bg-slate-50 dark:bg-slate-950 overflow-hidden">

                {/* Chat header */}
                <div className="flex-shrink-0 flex items-center justify-between px-6 py-3.5 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 shadow-sm">
                    <div className="flex items-center gap-3">
                        <div className="relative w-9 h-9">
                            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 dark:border-cyan-500/20 flex items-center justify-center">
                                <span className="text-cyan-500 dark:text-cyan-400 text-base">✦</span>
                            </div>
                            <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-green-500 border-2 border-white dark:border-slate-900" />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-900 dark:text-white">Chat with ARIA</h2>
                            <p className="text-xs text-slate-500 dark:text-slate-400">
                                {activeCtx?.context
                                    ? `${activeCtx.label} · ${activeCtx.context.target}`
                                    : 'General security assistant'
                                }
                            </p>
                        </div>
                    </div>
                    <span className="text-xs text-slate-400 tabular-nums">
                        {Math.max(0, messages.length - 1)} msg{messages.length !== 2 ? 's' : ''}
                    </span>
                </div>

                {/* Messages */}
                <div className="flex-1 overflow-y-auto px-6 py-6 space-y-5">

                    {/* Quick-start chips — only when no user messages yet */}
                    <AnimatePresence>
                        {messages.length === 1 && !loading && (
                            <motion.div
                                initial={{ opacity: 0, y: 6 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0 }}
                                className="flex flex-wrap gap-2 pb-2"
                            >
                                {QUICK_QUESTIONS.map(q => (
                                    <button
                                        key={q}
                                        onClick={() => sendMessage(q)}
                                        className="px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-full hover:border-primary-400 dark:hover:border-primary-500 hover:text-primary-700 dark:hover:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-500/10 transition-all shadow-sm"
                                    >
                                        {q}
                                    </button>
                                ))}
                            </motion.div>
                        )}
                    </AnimatePresence>

                    {messages.map((m, i) => (
                        <MessageBubble key={i} msg={m} />
                    ))}

                    {loading && (
                        <motion.div
                            initial={{ opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="flex gap-3 justify-start"
                        >
                            <div className="flex-shrink-0 w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 dark:border-cyan-500/20 flex items-center justify-center mt-1 shadow-sm">
                                <span className="text-cyan-500 dark:text-cyan-400 text-sm">✦</span>
                            </div>
                            <div className="bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-2xl rounded-tl-sm px-4 py-3 shadow-sm">
                                <TypingIndicator />
                            </div>
                        </motion.div>
                    )}

                    <div ref={bottomRef} />
                </div>

                {/* Input bar */}
                <div className="flex-shrink-0 px-6 py-4 bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800">
                    <div className="flex gap-3 items-end">
                        <textarea
                            ref={inputRef}
                            rows={1}
                            value={input}
                            onChange={e => {
                                setInput(e.target.value);
                                e.target.style.height = 'auto';
                                e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
                            }}
                            onKeyDown={e => {
                                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
                            }}
                            placeholder="Ask ARIA about any security topic…"
                            className="flex-1 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 resize-none focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all min-h-[46px] max-h-[120px]"
                            style={{ overflowY: 'auto', scrollbarWidth: 'none' }}
                        />
                        <button
                            onClick={() => sendMessage()}
                            disabled={!input.trim() || loading}
                            className={`flex-shrink-0 w-11 h-11 rounded-xl flex items-center justify-center transition-all ${
                                input.trim() && !loading
                                    ? 'bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20'
                                    : 'bg-slate-100 dark:bg-slate-800 text-slate-400 cursor-not-allowed'
                            }`}
                        >
                            <Send className="w-4 h-4" />
                        </button>
                    </div>
                    <p className="text-[10px] text-center text-slate-400 mt-2 select-none">
                        Shift+Enter for new line · Enter to send
                    </p>
                </div>
            </main>
        </div>
    );
}
