import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import ChatBot from '../components/ChatBot';

const SAMPLE_CONTEXTS = [
  { label: 'Web Scan', icon: '🌐', context: { target: 'example.com', risk: 'high', total: 12, scan_type: 'web' } },
  { label: 'Network', icon: '🔌', context: { target: '192.168.1.1', risk: 'critical', total: 5, scan_type: 'network_ext' } },
  { label: 'Code Review', icon: '💻', context: { target: 'app.py', risk: 'medium', total: 8, scan_type: 'sast' } },
  { label: 'No Context', icon: '💬', context: null },
];

const TOPIC_CARDS = [
  { icon: '🔐', title: 'Authentication',    q: 'How do I implement secure authentication with MFA and session management?' },
  { icon: '💉', title: 'SQL Injection',     q: 'Explain SQL injection with a real attack example and how to prevent it in Python' },
  { icon: '🔗', title: 'XSS Attacks',       q: 'What is Cross-Site Scripting? Show me attack payloads and CSP fixes' },
  { icon: '🛡️', title: 'OWASP Top 10',      q: 'Walk me through the OWASP Top 10 2025 with the most critical risks' },
  { icon: '🌩️', title: 'Cloud Security',    q: 'What are the most common AWS/cloud misconfigurations and how to fix them?' },
  { icon: '🔑', title: 'API Security',      q: 'How do I secure a REST API? Cover authentication, rate limiting, and input validation' },
  { icon: '📦', title: 'Dependencies',      q: 'How do I audit and fix vulnerable npm/pip dependencies in my project?' },
  { icon: '🕷️', title: 'Penetration Test', q: 'What is a penetration testing methodology? Explain recon, scanning, exploitation' },
];

function AriaBadge({ provider }) {
  if (!provider) return null;
  const cfg = provider === 'gemini'
    ? { dot: 'bg-green-400', ring: 'bg-green-500/10 border-green-500/30 text-green-400', label: 'Gemini Online' }
    : provider === 'ollama'
    ? { dot: 'bg-blue-400',  ring: 'bg-blue-500/10 border-blue-500/30 text-blue-400',   label: 'Ollama Local' }
    : { dot: 'bg-yellow-400',ring: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400', label: 'Offline Mode' };
  return (
    <span className={`inline-flex items-center gap-1 text-[9px] px-2 py-0.5 rounded-full font-mono border ${cfg.ring}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} style={{ animation: 'pulse 2s infinite' }} />
      {cfg.label}
    </span>
  );
}

export default function ChatPage() {
  const [activeContext, setActiveContext] = useState(SAMPLE_CONTEXTS[3]);
  const [chatKey, setChatKey]             = useState(0);
  const [ariaStatus, setAriaStatus]       = useState(null);

  useEffect(() => {
    axios.get('/api/ai/status').then(r => setAriaStatus(r.data)).catch(() => {});
  }, []);

  const handleContextSwitch = (ctx) => {
    setActiveContext(ctx);
    setChatKey(k => k + 1);
  };

  const handleClearHistory = () => {
    window.dispatchEvent(new CustomEvent('aria-clear-history'));
  };

  return (
    <div className="min-h-screen bg-[#080810] text-white font-inter">
      {/* Ambient background */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 rounded-full opacity-[0.04]"
             style={{ background: 'radial-gradient(circle, #00f5d4 0%, transparent 70%)' }} />
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 rounded-full opacity-[0.03]"
             style={{ background: 'radial-gradient(circle, #8b5cf6 0%, transparent 70%)' }} />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 py-8">

        {/* Page header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 flex items-center justify-center">
              <span className="text-cyan-400 text-lg">✦</span>
            </div>
            <div>
              <h1 className="text-2xl font-orbitron font-bold text-white tracking-wider">
                ARIA <span className="text-cyan-400">AI</span> Chat
              </h1>
              <div className="flex items-center gap-2 mt-0.5">
                <p className="text-xs text-gray-500 font-inter">CyBrain Security Intelligence</p>
                <AriaBadge provider={ariaStatus?.provider} />
                {ariaStatus?.model && (
                  <span className="text-[9px] text-gray-600 font-mono">{ariaStatus.model}</span>
                )}
              </div>
            </div>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* LEFT: Chat window */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="lg:col-span-2"
          >
            <ChatBot key={chatKey} position="inline" context={activeContext?.context} />
          </motion.div>

          {/* RIGHT: Sidebar */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="flex flex-col gap-4"
          >

            {/* Context switcher */}
            <div className="rounded-2xl border border-white/8 overflow-hidden"
                 style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div className="px-4 py-3 border-b border-white/8">
                <p className="text-[10px] font-mono text-gray-500 tracking-widest uppercase">Scan Context</p>
                <p className="text-[11px] text-gray-400 mt-0.5">ARIA adapts answers to your active scan</p>
              </div>
              <div className="p-3 grid grid-cols-2 gap-2">
                {SAMPLE_CONTEXTS.map((ctx) => (
                  <button
                    key={ctx.label}
                    onClick={() => handleContextSwitch(ctx)}
                    className={`flex items-center gap-2 px-3 py-2.5 rounded-xl border text-left transition-all ${
                      activeContext?.label === ctx.label
                        ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                        : 'border-white/8 hover:border-white/15 text-gray-400 hover:text-gray-300'
                    }`}
                  >
                    <span className="text-base">{ctx.icon}</span>
                    <span className="text-[11px] font-inter">{ctx.label}</span>
                  </button>
                ))}
              </div>
              {activeContext?.context && (
                <div className="px-4 pb-3">
                  <div className="text-[10px] text-gray-600 font-mono space-y-0.5">
                    <div>Target: <span className="text-gray-400">{activeContext.context.target}</span></div>
                    <div>Risk: <span className={`font-semibold ${
                      activeContext.context.risk === 'critical' ? 'text-red-400' :
                      activeContext.context.risk === 'high' ? 'text-orange-400' : 'text-yellow-400'
                    }`}>{activeContext.context.risk?.toUpperCase()}</span></div>
                    <div>Findings: <span className="text-gray-400">{activeContext.context.total}</span></div>
                  </div>
                </div>
              )}
            </div>

            {/* Topic cards */}
            <div className="rounded-2xl border border-white/8 overflow-hidden"
                 style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div className="px-4 py-3 border-b border-white/8 flex items-center justify-between">
                <div>
                  <p className="text-[10px] font-mono text-gray-500 tracking-widest uppercase">Security Topics</p>
                  <p className="text-[11px] text-gray-400 mt-0.5">Click to ask instantly</p>
                </div>
                <button
                  onClick={handleClearHistory}
                  title="Clear chat history"
                  className="text-[10px] text-gray-600 hover:text-red-400 font-mono border border-white/8 hover:border-red-500/30 px-2 py-1 rounded-lg transition-all"
                >
                  Clear History
                </button>
              </div>
              <div className="p-3 space-y-2">
                {TOPIC_CARDS.map((t) => (
                  <motion.button
                    key={t.title}
                    whileHover={{ x: 4 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => window.dispatchEvent(new CustomEvent('aria-inject', { detail: t.q }))}
                    className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl border border-white/5 hover:border-cyan-500/20 hover:bg-cyan-500/5 text-left transition-all group"
                  >
                    <span className="text-base flex-shrink-0">{t.icon}</span>
                    <div>
                      <p className="text-[11px] font-semibold text-gray-300 group-hover:text-cyan-300 transition-colors">{t.title}</p>
                      <p className="text-[9px] text-gray-600 mt-0.5 line-clamp-1">{t.q}</p>
                    </div>
                  </motion.button>
                ))}
              </div>
            </div>

            {/* ARIA status card */}
            <div className="rounded-2xl border border-white/8 p-4"
                 style={{ background: 'linear-gradient(135deg, rgba(0,245,212,0.03), rgba(139,92,246,0.03))' }}>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-6 h-6 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 flex items-center justify-center border border-cyan-500/20">
                  <span className="text-cyan-400 text-[10px]">✦</span>
                </div>
                <p className="text-[11px] font-semibold text-gray-300">ARIA Status</p>
                {ariaStatus && <AriaBadge provider={ariaStatus.provider} />}
              </div>
              <div className="space-y-2">
                {[
                  ['Status',   ariaStatus?.status  || 'connecting…'],
                  ['Provider', ariaStatus?.provider || '—'],
                  ['Model',    ariaStatus?.model    || '—'],
                  ['History',  'Per-user isolated'],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-[10px] text-gray-600">{k}</span>
                    <span className="text-[10px] text-gray-400 font-mono">{v}</span>
                  </div>
                ))}
              </div>
              <div className="mt-3 pt-3 border-t border-white/5">
                <p className="text-[9px] text-gray-600 leading-relaxed">
                  Set <code className="text-cyan-500">GEMINI_API_KEY</code> in <code className="text-cyan-500">.env</code> to enable online AI mode.
                  Without a key, ARIA uses its built-in security knowledge base.
                </p>
              </div>
            </div>

          </motion.div>
        </div>
      </div>
    </div>
  );
}
