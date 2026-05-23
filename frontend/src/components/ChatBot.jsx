import React, { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';

const SUGGESTIONS = [
  'What is SQL Injection and how to fix it?',
  'Explain XSS attack techniques',
  'How do I harden Apache configuration?',
  'What is OWASP Top 10 2025?',
  'How to prevent SSRF attacks?',
  'Explain the CVSS scoring system',
  'What does a critical vulnerability mean?',
  'How to implement secure authentication?',
];

// Encode code content safely for data attributes
const encodeCode = (str) => btoa(unescape(encodeURIComponent(str)));

function renderMarkdown(text) {
  if (!text) return '';
  let blockIdx = 0;
  let html = text
    .replace(/^### (.+)$/gm, '<h3 class="text-cyan-300 font-bold text-sm mt-3 mb-1">$1</h3>')
    .replace(/^## (.+)$/gm,  '<h2 class="text-cyan-400 font-bold text-sm mt-4 mb-1">$1</h2>')
    .replace(/^# (.+)$/gm,   '<h1 class="text-cyan-400 font-bold text-base mt-4 mb-1">$1</h1>')
    .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
    .replace(/\*\*(.+?)\*\*/g,     '<strong class="text-white">$1</strong>')
    .replace(/\*(.+?)\*/g,         '<em>$1</em>')
    .replace(/`([^`\n]+)`/g, '<code class="bg-black/50 text-cyan-400 px-1.5 py-0.5 rounded font-mono text-[11px] border border-white/10">$1</code>')
    .replace(/^---$/gm, '<hr class="border-white/10 my-3" />')
    .replace(/^[•\-] (.+)$/gm, '<li class="ml-3 list-none flex gap-2"><span class="text-cyan-500 mt-0.5">▸</span><span>$1</span></li>')
    .replace(/^\d+\. (.+)$/gm, '<li class="ml-3 list-none flex gap-2"><span class="text-cyan-500">›</span><span>$1</span></li>')
    .replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
      const encoded = encodeCode(code.trim());
      return `<div class="my-2 rounded-xl overflow-hidden border border-white/10 relative">
        <div class="flex items-center justify-between bg-white/5 px-3 py-1 border-b border-white/10">
          <span class="text-[10px] text-gray-500 font-mono">${lang || 'code'}</span>
          <button data-copy="${encoded}" class="copy-btn text-[10px] text-gray-500 hover:text-cyan-400 font-mono transition-colors px-2 py-0.5 rounded hover:bg-white/5">Copy</button>
        </div>
        <pre class="bg-black/60 p-3 text-[11px] text-green-300 font-mono overflow-x-auto whitespace-pre-wrap">${code.trim()}</pre>
      </div>`;
    })
    .replace(/\n/g, '<br />');
  return html;
}

function TypingDots() {
  return (
    <div className="flex items-center gap-1.5 py-1">
      {[0, 1, 2].map(i => (
        <span key={i} className="w-2 h-2 rounded-full bg-cyan-400/70"
          style={{ animation: `bounce 1.2s ease-in-out ${i * 0.2}s infinite` }} />
      ))}
    </div>
  );
}

function AiBadge({ provider }) {
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

function MessageBubble({ msg }) {
  const isUser = msg.role === 'user';
  const bubbleRef = useRef(null);

  // Wire up copy buttons inside rendered HTML
  useEffect(() => {
    if (!bubbleRef.current) return;
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
  }, [msg.content]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`flex ${isUser ? 'justify-end' : 'justify-start'} gap-2`}
    >
      {!isUser && (
        <div className="flex-shrink-0 w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 flex items-center justify-center mt-0.5">
          <span className="text-cyan-400 text-xs">✦</span>
        </div>
      )}

      <div className={`max-w-[88%] ${isUser ? 'items-end' : 'items-start'} flex flex-col gap-1`}>
        <div ref={bubbleRef} className={`rounded-2xl px-4 py-3 text-[12px] leading-relaxed font-inter ${
          isUser
            ? 'bg-gradient-to-br from-cyan-500/15 to-cyan-600/10 text-cyan-100 rounded-br-sm border border-cyan-500/20'
            : 'bg-white/[0.04] text-gray-300 rounded-bl-sm border border-white/8'
        }`}>
          {isUser ? (
            <p>{msg.content}</p>
          ) : (
            <div className="prose-cybrain" dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }} />
          )}
        </div>

        {!isUser && msg.provider && (
          <div className="flex items-center gap-2 px-1">
            <AiBadge provider={msg.provider} />
            {msg.time && <span className="text-[9px] text-gray-600">{msg.time}</span>}
          </div>
        )}
        {isUser && msg.time && (
          <span className="text-[9px] text-gray-600 px-1">{msg.time}</span>
        )}
      </div>

      {isUser && (
        <div className="flex-shrink-0 w-7 h-7 rounded-full bg-gradient-to-br from-purple-500/20 to-pink-500/20 border border-purple-500/30 flex items-center justify-center mt-0.5">
          <span className="text-purple-300 text-xs">⬡</span>
        </div>
      )}
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
const ChatBot = ({ context = null, position = 'fixed', scanFindings = null }) => {
  const [open,     setOpen]     = useState(false);
  const [messages, setMessages] = useState([{
    role: 'assistant',
    content: (
      '👋 Hello! I\'m **ARIA** — CyBrain\'s AI security expert.\n\n' +
      'I can help you:\n' +
      '• Understand vulnerabilities from your scans\n' +
      '• Explain attack techniques & real-world impact\n' +
      '• Recommend specific code fixes\n' +
      '• Answer any cybersecurity question\n\n' +
      'Pick a topic below or ask me anything!'
    ),
    provider: null,
    time: null,
  }]);
  const [input,       setInput]       = useState('');
  const [loading,     setLoading]     = useState(false);
  const [ariaStatus,  setAriaStatus]  = useState(null);
  const [clearingHistory, setClearingHistory] = useState(false);

  const bottomRef          = useRef(null);
  const inputRef           = useRef(null);
  const sendMessageRef     = useRef(null);
  const clearHistoryRef    = useRef(null);

  // Fetch ARIA status once on mount
  useEffect(() => {
    axios.get('/api/ai/status').then(r => setAriaStatus(r.data)).catch(() => {});
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 150);
  }, [open]);

  const now = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const sendMessage = useCallback(async (textOverride) => {
    const msg = (textOverride ?? input).trim();
    if (!msg || loading) return;
    setInput('');

    setMessages(prev => [...prev, { role: 'user', content: msg, time: now() }]);
    setLoading(true);

    try {
      const { data } = await axios.post('/api/ai/chat', { message: msg, context: context ?? {} });
      const reply    = data.reply || data.response || '…';
      const provider = data.provider || data.ai_mode || 'offline';
      setMessages(prev => [...prev, { role: 'assistant', content: reply, provider, time: now() }]);
    } catch (err) {
      let errText = '⚠️ Connection error. Please try again.';
      if (err.response?.status === 429) {
        errText = '⚠️ **Rate limit reached** — please wait 60 seconds and try again.';
      } else if (err.response?.status === 401) {
        errText = '🔒 Session expired. Please refresh the page.';
      } else if (err.response?.data?.error) {
        errText = `⚠️ ${err.response.data.error}`;
      }
      setMessages(prev => [...prev, { role: 'assistant', content: errText, provider: 'offline', time: now() }]);
    } finally {
      setLoading(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [input, loading, context]);

  const handleClearHistory = useCallback(async () => {
    if (!window.confirm('Clear chat and server-side history? ARIA will forget this conversation.')) return;
    setClearingHistory(true);
    try {
      await axios.post('/api/ai/history/clear');
    } catch { /* ignore — still clear locally */ }
    setMessages([{
      role: 'assistant',
      content: '🔄 History cleared. How can I help you?',
      provider: null,
      time: now(),
    }]);
    setClearingHistory(false);
  }, []);

  // Keep refs in sync so event handlers always call the latest version
  useEffect(() => { sendMessageRef.current = sendMessage; }, [sendMessage]);

  // aria-inject: topic cards in ChatPage dispatch this event
  useEffect(() => {
    const handler = (e) => {
      if (position === 'fixed') setOpen(true);
      setTimeout(() => sendMessageRef.current(e.detail), position === 'fixed' ? 200 : 0);
    };
    window.addEventListener('aria-inject', handler);
    return () => window.removeEventListener('aria-inject', handler);
  }, [position]);

  // aria-clear-history: sidebar clear button in ChatPage dispatches this event
  useEffect(() => { clearHistoryRef.current = handleClearHistory; }, [handleClearHistory]);
  useEffect(() => {
    const handler = () => clearHistoryRef.current();
    window.addEventListener('aria-clear-history', handler);
    return () => window.removeEventListener('aria-clear-history', handler);
  }, []);

  const handleAnalyzeScan = useCallback(() => {
    if (!scanFindings || loading) return;
    const summary = Array.isArray(scanFindings)
      ? `Analyze these security findings from my scan:\n${scanFindings.slice(0, 20).map(f =>
          `- [${f.severity}] ${f.code || f.title}: ${(f.message || '').slice(0, 120)}`
        ).join('\n')}`
      : `Analyze these scan results: ${JSON.stringify(scanFindings).slice(0, 1000)}`;
    if (position === 'fixed') setOpen(true);
    setTimeout(() => sendMessage(summary), 200);
  }, [scanFindings, loading, position, sendMessage]);

  // ── Sub-renders ─────────────────────────────────────────────────────────────

  const currentProvider = ariaStatus?.provider || null;

  const Header = () => (
    <div className="flex items-center justify-between px-5 py-4 border-b border-white/8"
         style={{ background: 'linear-gradient(135deg, rgba(0,245,212,0.06) 0%, rgba(139,92,246,0.04) 100%)' }}>
      <div className="flex items-center gap-3">
        <div className="relative w-9 h-9">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 flex items-center justify-center">
            <span className="text-cyan-400 text-base" style={{ animation: 'spin 8s linear infinite' }}>✦</span>
          </div>
          <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-green-500 border-2 border-black"
               style={{ animation: 'pulse 2s infinite' }} />
        </div>
        <div>
          <p className="font-orbitron text-white text-[11px] font-bold tracking-widest">ARIA</p>
          <div className="flex items-center gap-2 mt-0.5">
            <p className="text-[9px] text-gray-500 font-inter">CyBrain AI Security Expert</p>
            {currentProvider && <AiBadge provider={currentProvider} />}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={handleClearHistory}
          disabled={clearingHistory}
          title="Clear history"
          className="w-7 h-7 rounded-lg text-gray-600 hover:text-gray-300 hover:bg-white/5 transition-all flex items-center justify-center text-[11px] disabled:opacity-40"
        >
          ⟳
        </button>
        {position === 'fixed' && (
          <button
            onClick={() => setOpen(false)}
            className="w-7 h-7 rounded-lg text-gray-600 hover:text-white hover:bg-white/5 transition-all flex items-center justify-center text-lg leading-none"
          >
            ×
          </button>
        )}
      </div>
    </div>
  );

  const Suggestions = () => (
    messages.length <= 1 && (
      <div className="px-4 py-3 border-b border-white/5 space-y-3">
        {scanFindings && (
          <button
            onClick={handleAnalyzeScan}
            className="w-full text-left text-[10px] text-cyan-300 border border-cyan-500/30 rounded-xl px-3 py-2 hover:bg-cyan-500/10 hover:border-cyan-500/50 transition-all font-inter flex items-center gap-2"
          >
            <span className="text-cyan-400">✦</span>
            Ask ARIA about current scan results
          </button>
        )}
        <div>
          <p className="text-[9px] text-gray-600 mb-2 font-mono tracking-wider uppercase">Quick questions</p>
          <div className="flex flex-wrap gap-1.5">
            {SUGGESTIONS.slice(0, 4).map((s, i) => (
              <motion.button
                key={i}
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                onClick={() => sendMessage(s)}
                className="text-[10px] text-gray-500 border border-white/10 rounded-full px-3 py-1.5 hover:border-cyan-500/40 hover:text-cyan-400 hover:bg-cyan-500/5 transition-all font-inter"
              >
                {s}
              </motion.button>
            ))}
          </div>
        </div>
      </div>
    )
  );

  const Messages = () => (
    <div className="flex-1 overflow-y-auto px-4 py-4 space-y-4 scrollbar-thin scrollbar-thumb-white/10">
      {messages.map((m, i) => (
        <MessageBubble key={i} msg={m} />
      ))}
      {loading && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex justify-start gap-2">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 flex items-center justify-center flex-shrink-0">
            <span className="text-cyan-400 text-xs">✦</span>
          </div>
          <div className="bg-white/[0.04] border border-white/8 rounded-2xl rounded-bl-sm px-4 py-3">
            <TypingDots />
          </div>
        </motion.div>
      )}
      <div ref={bottomRef} />
    </div>
  );

  const InputBar = () => (
    <div className="px-4 py-4 border-t border-white/8" style={{ background: 'rgba(0,0,0,0.3)' }}>
      <div className="flex gap-2 items-end">
        <textarea
          ref={inputRef}
          rows={1}
          value={input}
          onChange={e => {
            setInput(e.target.value);
            e.target.style.height = 'auto';
            e.target.style.height = Math.min(e.target.scrollHeight, 100) + 'px';
          }}
          onKeyDown={e => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
          }}
          placeholder="Ask ARIA about any security topic…"
          className="flex-1 bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-gray-200 text-[12px] font-inter resize-none focus:outline-none focus:border-cyan-500/50 focus:bg-black/60 transition-all placeholder-gray-600 min-h-[44px] max-h-[100px] overflow-y-auto scrollbar-none"
        />
        <motion.button
          onClick={() => sendMessage()}
          disabled={!input.trim() || loading}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          className="flex-shrink-0 w-11 h-11 rounded-xl border flex items-center justify-center text-sm transition-all disabled:opacity-30 disabled:cursor-not-allowed"
          style={{
            background: input.trim() && !loading
              ? 'linear-gradient(135deg, rgba(0,245,212,0.2), rgba(139,92,246,0.2))'
              : 'rgba(255,255,255,0.03)',
            borderColor: input.trim() && !loading ? 'rgba(0,245,212,0.4)' : 'rgba(255,255,255,0.1)',
          }}
        >
          <span className="text-cyan-400" style={{ transform: 'rotate(-45deg)' }}>➤</span>
        </motion.button>
      </div>
      <p className="text-[9px] text-center text-gray-700 mt-2 font-inter tracking-wider">
        Shift+Enter for new line · Enter to send
      </p>
    </div>
  );

  // ── Fixed floating chatbot ──────────────────────────────────────────────────
  if (position === 'fixed') {
    return (
      <>
        <AnimatePresence>
          {open && (
            <motion.div
              initial={{ opacity: 0, scale: 0.92, y: 24 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.92, y: 24 }}
              transition={{ type: 'spring', stiffness: 300, damping: 28 }}
              className="fixed bottom-24 right-5 z-[200] w-[360px] md:w-[420px] flex flex-col rounded-2xl overflow-hidden border border-white/10 shadow-2xl"
              style={{
                height: 'min(580px, calc(100vh - 110px))',
                background: 'rgba(8, 8, 14, 0.97)',
                backdropFilter: 'blur(40px)',
                boxShadow: '0 25px 60px rgba(0,0,0,0.8), 0 0 40px rgba(0,245,212,0.05)',
              }}
            >
              <Header />
              <Suggestions />
              <Messages />
              <InputBar />
            </motion.div>
          )}
        </AnimatePresence>

        <motion.button
          onClick={() => setOpen(o => !o)}
          whileHover={{ scale: 1.08 }}
          whileTap={{ scale: 0.93 }}
          className="fixed bottom-5 right-5 z-[200] w-14 h-14 rounded-2xl flex items-center justify-center shadow-2xl transition-all"
          style={{
            background: open
              ? 'linear-gradient(135deg, rgba(0,245,212,0.15), rgba(139,92,246,0.15))'
              : 'linear-gradient(135deg, rgba(0,245,212,0.1), rgba(139,92,246,0.1))',
            border: `1px solid ${open ? 'rgba(0,245,212,0.5)' : 'rgba(0,245,212,0.3)'}`,
            backdropFilter: 'blur(20px)',
            boxShadow: open
              ? '0 0 30px rgba(0,245,212,0.25), 0 8px 32px rgba(0,0,0,0.6)'
              : '0 0 15px rgba(0,245,212,0.1), 0 8px 24px rgba(0,0,0,0.5)',
          }}
          aria-label={open ? 'Close AI Chat' : 'Open AI Chat'}
        >
          <AnimatePresence mode="wait">
            {open ? (
              <motion.span key="close" initial={{ rotate: -90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: 90, opacity: 0 }} transition={{ duration: 0.15 }}
                className="text-white text-xl leading-none">×</motion.span>
            ) : (
              <motion.span key="open" initial={{ rotate: 90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: -90, opacity: 0 }} transition={{ duration: 0.15 }}
                className="text-cyan-400 text-xl">✦</motion.span>
            )}
          </AnimatePresence>
        </motion.button>

        <AnimatePresence>
          {!open && (
            <motion.div
              initial={{ opacity: 0, x: 10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 10 }}
              transition={{ delay: 2, duration: 0.4 }}
              className="fixed bottom-7 right-20 z-[199] bg-black/80 border border-white/10 rounded-xl px-3 py-2 backdrop-blur-xl pointer-events-none"
              style={{ whiteSpace: 'nowrap' }}
            >
              <p className="text-[11px] text-gray-300 font-inter">Ask <span className="text-cyan-400 font-semibold">ARIA</span> about security</p>
              <div className="absolute right-0 top-1/2 -translate-y-1/2 translate-x-2 w-2 h-2 rotate-45 bg-black/80 border-r border-t border-white/10" />
            </motion.div>
          )}
        </AnimatePresence>
      </>
    );
  }

  // ── Inline (embedded in a page) ─────────────────────────────────────────────
  return (
    <div
      className="w-full flex flex-col rounded-2xl overflow-hidden border border-white/10"
      style={{ height: '600px', background: 'rgba(8, 8, 14, 0.95)', backdropFilter: 'blur(30px)' }}
    >
      <Header />
      <Suggestions />
      <Messages />
      <InputBar />
    </div>
  );
};

export default ChatBot;
