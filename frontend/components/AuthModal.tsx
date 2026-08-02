'use client';
import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Loader2 } from 'lucide-react';
import NVMELogo from './NVMELogo';
import { auth } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';

export default function AuthModal({ open, mode, onClose }: { open: boolean; mode: 'signin' | 'signup'; onClose: () => void }) {
  const [m, setM] = useState<'signin' | 'signup'>(mode);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const setAuth = useAuthStore((s) => s.setAuth);

  const effectiveMode = open ? (mode !== m && !busy ? m : m) : m;

  async function submit() {
    setErr('');
    if (!email || !password || (m === 'signup' && !username)) { setErr('Fill in all fields'); return; }
    if (m === 'signup' && password !== confirm) { setErr('Passwords do not match'); return; }
    setBusy(true);
    try {
      const d = m === 'signup' ? await auth.register(username.trim(), email.trim(), password) : await auth.login(email.trim(), password);
      setAuth(d.user, d.token);
    } catch (e: any) {
      setErr(e.message || 'Auth failed');
    } finally { setBusy(false); }
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
          onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
          <motion.div initial={{ scale: 0.94, y: 16 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.94, y: 16 }}
            transition={{ type: 'spring', damping: 24, stiffness: 300 }}
            className="relative w-full max-w-sm rounded-2xl border border-nvme-gold/25 bg-nvme-surface p-7 shadow-[0_0_60px_rgba(201,162,39,0.15)]">
            <button aria-label="Close" onClick={onClose} className="focus-ring absolute right-4 top-4 rounded-full p-1.5 text-nvme-muted hover:text-white"><X size={18} /></button>
            <div className="mb-6 flex flex-col items-center">
              <NVMELogo size={52} withWordmark={false} />
              <h2 className="mt-3 font-display text-xl tracking-wider">{m === 'signup' ? 'JOIN NVME' : 'WELCOME BACK'}</h2>
              <p className="mt-1 text-xs text-nvme-muted">Watch. Create. Earn.</p>
            </div>

            {m === 'signup' && (
              <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" autoComplete="username"
                className="mb-3 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm outline-none transition-colors focus:border-nvme-gold" />
            )}
            <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" type="email" autoComplete="email"
              className="mb-3 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm outline-none transition-colors focus:border-nvme-gold" />
            <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password"
              autoComplete={m === 'signup' ? 'new-password' : 'current-password'}
              onKeyDown={(e) => e.key === 'Enter' && submit()}
              className="mb-3 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm outline-none transition-colors focus:border-nvme-gold" />
            {m === 'signup' && (
              <input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Confirm password" type="password" autoComplete="new-password"
                onKeyDown={(e) => e.key === 'Enter' && submit()}
                className="mb-3 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm outline-none transition-colors focus:border-nvme-gold" />
            )}

            <button onClick={submit} disabled={busy} className="btn-gold w-full disabled:opacity-60">
              {busy && <Loader2 size={16} className="animate-spin" />} {m === 'signup' ? 'Create account' : 'Sign in'}
            </button>

            <a href={auth.googleUrl()} className="mt-3 flex w-full items-center justify-center gap-2 rounded-xl bg-white px-4 py-3 text-sm font-bold text-black transition-all hover:scale-[1.01] active:scale-[0.99]">
              <svg width="16" height="16" viewBox="0 0 24 24"><path fill="#4285F4" d="M23.5 12.3c0-.9-.1-1.5-.3-2.2H12v4.3h6.5c-.1 1.1-.8 2.7-2.4 3.8l3.7 2.9c2.3-2.1 3.7-5.2 3.7-8.8z"/><path fill="#34A853" d="M12 24c3.2 0 6-1.1 7.9-2.9l-3.7-2.9c-1 .7-2.4 1.2-4.2 1.2-3.2 0-6-2.2-7-5.1l-3.9 3C3.1 21.3 7.2 24 12 24z"/><path fill="#FBBC05" d="M5 14.3c-.2-.7-.4-1.5-.4-2.3s.1-1.6.4-2.3l-3.9-3C.4 8.3 0 10.1 0 12s.4 3.7 1.1 5.3l3.9-3z"/><path fill="#EA4335" d="M12 4.7c1.8 0 3 .8 3.7 1.4l3.3-3.2C17 1.1 15.2 0 12 0 7.2 0 3.1 2.7 1.1 6.7l3.9 3c1-2.9 3.8-5 7-5z"/></svg>
              Sign in with Google
            </a>

            <p className="mt-4 cursor-pointer text-center text-xs text-nvme-muted" onClick={() => { setM(m === 'signup' ? 'signin' : 'signup'); setErr(''); }}>
              {m === 'signup' ? <>Have an account? <b className="text-nvme-gold">Sign in</b></> : <>New here? <b className="text-nvme-gold">Create account</b></>}
            </p>
            <p className="mt-2 min-h-4 text-center text-xs text-nvme-coral">{err}</p>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
