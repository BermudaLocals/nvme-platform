'use client';
import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { UploadCloud, Film, BarChart3, Sparkles, Wallet, Loader2, Copy, Check } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { uploadVideo, videos as videosApi, ai, wallet as walletApi, type NvmeVideo } from '@/lib/api';
import { formatCount, cn } from '@/lib/utils';

const TABS = [
  { id: 'upload', label: 'Upload', icon: UploadCloud },
  { id: 'videos', label: 'My Videos', icon: Film },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'ai', label: 'AI Studio', icon: Sparkles },
  { id: 'wallet', label: 'Wallet', icon: Wallet }
];

export default function StudioPage() {
  const { user, isAuthenticated, hydrated, openAuth } = useAuth();
  const router = useRouter();
  const [tab, setTab] = useState('upload');

  useEffect(() => {
    if (hydrated && !isAuthenticated) openAuth('signin');
  }, [hydrated, isAuthenticated]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!hydrated) return <div className="flex min-h-screen items-center justify-center bg-nvme-bg"><Loader2 className="animate-spin text-nvme-gold" /></div>;
  if (!isAuthenticated || !user) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-nvme-bg px-6 text-center">
        <h1 className="font-display text-3xl">CREATOR STUDIO</h1>
        <p className="mt-3 text-sm text-nvme-muted">Sign in to upload, generate, and earn.</p>
        <button onClick={() => openAuth('signin')} className="btn-gold mt-6">Sign In</button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-nvme-bg pt-16">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-6 sm:px-6 lg:flex-row">
        {/* Sidebar */}
        <aside className="flex gap-2 overflow-x-auto lg:w-56 lg:flex-col lg:gap-1">
          {TABS.map((t) => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={cn('flex shrink-0 items-center gap-2.5 rounded-xl px-4 py-3 text-sm font-bold transition-all',
                tab === t.id ? 'bg-nvme-gold text-black' : 'text-nvme-muted hover:bg-white/5 hover:text-white')}>
              <t.icon size={17} /> {t.label}
            </button>
          ))}
        </aside>

        <div className="min-w-0 flex-1">
          <motion.div key={tab} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
            {tab === 'upload' && <UploadTab username={user.username} />}
            {tab === 'videos' && <VideosTab username={user.username} />}
            {tab === 'analytics' && <AnalyticsTab username={user.username} />}
            {tab === 'ai' && <AITab />}
            {tab === 'wallet' && <WalletTab />}
          </motion.div>
        </div>
      </div>
    </div>
  );
}

/* ---------------- Upload ---------------- */
function UploadTab({ username }: { username: string }) {
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState('');
  const [desc, setDesc] = useState('');
  const [progress, setProgress] = useState(0);
  const [state, setState] = useState<'idle' | 'uploading' | 'done' | 'error'>('idle');
  const [msg, setMsg] = useState('');
  const dropRef = useRef<HTMLDivElement>(null);

  function pick(f?: File | null) {
    if (!f) return;
    if (!f.type.startsWith('video/')) { setMsg('Pick a video file'); setState('error'); return; }
    setFile(f); setState('idle'); setMsg('');
  }

  async function go() {
    if (!file) return;
    setState('uploading'); setMsg('');
    // Simulated smooth progress while the request runs (backend returns once)
    const timer = setInterval(() => setProgress((p) => Math.min(92, p + Math.random() * 7)), 220);
    try {
      await uploadVideo(file, title || file.name, desc);
      clearInterval(timer); setProgress(100); setState('done');
      setMsg('Uploaded! It will appear in the feed shortly.');
      setFile(null); setTitle(''); setDesc('');
    } catch (e: any) {
      clearInterval(timer); setState('error'); setMsg(e.message || 'Upload failed');
    }
  }

  return (
    <div>
      <h2 className="font-display text-2xl">UPLOAD</h2>
      <div
        ref={dropRef}
        onDragOver={(e) => { e.preventDefault(); dropRef.current?.classList.add('border-nvme-gold'); }}
        onDragLeave={() => dropRef.current?.classList.remove('border-nvme-gold')}
        onDrop={(e) => { e.preventDefault(); dropRef.current?.classList.remove('border-nvme-gold'); pick(e.dataTransfer.files?.[0]); }}
        className="mt-5 flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-white/15 bg-nvme-surface p-10 text-center transition-colors"
      >
        <UploadCloud size={40} className="text-nvme-gold" />
        <p className="mt-3 text-sm font-semibold">Drag & drop your video</p>
        <p className="mt-1 text-xs text-nvme-muted">MP4 / WebM / MOV — portrait works best</p>
        <label className="btn-outline mt-5 cursor-pointer !py-2 text-xs">
          Browse files
          <input type="file" accept="video/*" className="hidden" onChange={(e) => pick(e.target.files?.[0])} />
        </label>
        {file && <p className="mt-4 max-w-full truncate text-xs text-nvme-gold">🎬 {file.name} ({(file.size / 1048576).toFixed(1)} MB)</p>}
      </div>

      <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title"
        className="mt-4 w-full rounded-xl border border-white/10 bg-nvme-surface px-4 py-3 text-sm outline-none focus:border-nvme-gold" />
      <textarea value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Caption + #hashtags" rows={3}
        className="mt-3 w-full rounded-xl border border-white/10 bg-nvme-surface px-4 py-3 text-sm outline-none focus:border-nvme-gold" />

      {state === 'uploading' && (
        <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/10">
          <motion.div className="h-full bg-nvme-gold" animate={{ width: `${progress}%` }} transition={{ ease: 'easeOut' }} />
        </div>
      )}
      <button onClick={go} disabled={!file || state === 'uploading'} className="btn-gold mt-5 w-full disabled:opacity-50">
        {state === 'uploading' ? <><Loader2 size={16} className="animate-spin" /> Uploading…</> : 'Publish to NVME'}
      </button>
      <p className={cn('mt-3 text-center text-xs', state === 'error' ? 'text-nvme-coral' : 'text-nvme-gold')}>{msg}</p>
    </div>
  );
}

/* ---------------- My Videos ---------------- */
function VideosTab({ username }: { username: string }) {
  const q = useQuery({ queryKey: ['my-videos', username], queryFn: () => videosApi.byUser(username), staleTime: 60_000 });
  return (
    <div>
      <h2 className="font-display text-2xl">MY VIDEOS</h2>
      {q.isLoading && <div className="py-14 text-center"><Loader2 className="mx-auto animate-spin text-nvme-gold" /></div>}
      {q.data?.length === 0 && <p className="mt-6 rounded-2xl border border-dashed border-white/10 py-14 text-center text-sm text-nvme-muted">No videos yet — upload your first one.</p>}
      <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3">
        {(q.data || []).map((v: NvmeVideo) => (
          <a key={v.id} href={`/feed?v=${v.id}`} className="card-hover overflow-hidden rounded-xl border border-nvme-border bg-nvme-surface">
            <div className="aspect-[3/4] bg-black">
              {v.thumbnail ? <img src={v.thumbnail} alt="" className="h-full w-full object-cover" /> : <video src={v.url} className="h-full w-full object-cover" muted preload="metadata" />}
            </div>
            <p className="truncate p-2 text-xs font-semibold">{v.title || 'Untitled'}</p>
          </a>
        ))}
      </div>
    </div>
  );
}

/* ---------------- Analytics ---------------- */
function AnalyticsTab({ username }: { username: string }) {
  const vids = useQuery({ queryKey: ['my-videos', username], queryFn: () => videosApi.byUser(username), staleTime: 60_000 });
  const stats = useQuery({ queryKey: ['stats', username], queryFn: () => import('@/lib/api').then(m => m.users.stats(username)), staleTime: 60_000, retry: false });
  const totalViews = (vids.data || []).reduce((s, v) => s + (v.views || 0), 0);
  const totalLikes = (vids.data || []).reduce((s, v) => s + (v.like_count || 0), 0);
  return (
    <div>
      <h2 className="font-display text-2xl">ANALYTICS</h2>
      <div className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: 'Videos', value: vids.data?.length ?? 0 },
          { label: 'Views', value: totalViews },
          { label: 'Likes', value: totalLikes },
          { label: 'Followers', value: stats.data?.followers ?? 0 }
        ].map((s) => (
          <div key={s.label} className="rounded-2xl border border-nvme-border bg-nvme-surface p-5 text-center">
            <p className="font-display text-2xl text-nvme-gold">{formatCount(s.value)}</p>
            <p className="mt-1 text-[10px] uppercase tracking-widest text-nvme-muted">{s.label}</p>
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs text-nvme-muted">Deep analytics (retention, traffic sources) ship with the next drop.</p>
    </div>
  );
}

/* ---------------- AI Studio ---------------- */
function AITab() {
  const [prompt, setPrompt] = useState('');
  const [busy, setBusy] = useState('');
  const [results, setResults] = useState<{ kind: string; text: string }[]>([]);
  const [copied, setCopied] = useState<number | null>(null);
  const status = useQuery({ queryKey: ['ai-status'], queryFn: () => ai.status(), staleTime: 60_000, retry: false });

  async function run(kind: 'captions' | 'hashtags' | 'script' | 'generate') {
    if (!prompt.trim()) return;
    setBusy(kind);
    try {
      const d: any = await ai[kind](prompt.trim());
      const text = d.captions ? d.captions.join('\n\n') : d.hashtags ? (Array.isArray(d.hashtags) ? d.hashtags.join(' ') : d.hashtags) : d.script || d.resultUrl || d.result || JSON.stringify(d);
      setResults((r) => [{ kind, text: String(text) }, ...r].slice(0, 10));
    } catch (e: any) {
      setResults((r) => [{ kind, text: `⚠️ ${e.message || 'AI request failed'}` }, ...r]);
    } finally { setBusy(''); }
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <h2 className="font-display text-2xl">AI STUDIO</h2>
        <span className={cn('rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-wider',
          status.data ? 'bg-nvme-gold/15 text-nvme-gold' : 'bg-white/5 text-nvme-muted')}>
          {status.data ? `Online · ${status.data.model || 'kimi-k3'}` : 'Checking…'}
        </span>
      </div>
      <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} rows={3}
        placeholder="Describe your video, topic, or product…"
        className="mt-5 w-full rounded-xl border border-white/10 bg-nvme-surface px-4 py-3 text-sm outline-none focus:border-nvme-gold" />
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {(['captions', 'hashtags', 'script', 'generate'] as const).map((k) => (
          <button key={k} onClick={() => run(k)} disabled={!!busy || !prompt.trim()}
            className="rounded-xl border border-nvme-gold/40 py-2.5 text-xs font-bold capitalize text-nvme-gold transition-all hover:bg-nvme-gold hover:text-black disabled:opacity-40">
            {busy === k ? <Loader2 size={14} className="mx-auto animate-spin" /> : k}
          </button>
        ))}
      </div>
      <div className="mt-5 space-y-3">
        {results.map((r, i) => (
          <div key={i} className="rounded-xl border border-nvme-border bg-nvme-surface p-4">
            <div className="flex items-center justify-between">
              <p className="text-[10px] font-bold uppercase tracking-widest text-nvme-gold">{r.kind}</p>
              <button aria-label="Copy" onClick={() => { navigator.clipboard?.writeText(r.text); setCopied(i); setTimeout(() => setCopied(null), 1200); }}
                className="text-nvme-muted hover:text-nvme-gold">
                {copied === i ? <Check size={14} /> : <Copy size={14} />}
              </button>
            </div>
            <p className="mt-2 whitespace-pre-wrap text-sm text-white/90">{r.text}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------------- Wallet ---------------- */
function WalletTab() {
  const bal = useQuery({ queryKey: ['wallet'], queryFn: () => walletApi.balance(), staleTime: 60_000, retry: false });
  const [addr, setAddr] = useState('');
  const [linked, setLinked] = useState(false);
  return (
    <div>
      <h2 className="font-display text-2xl">WALLET</h2>
      <div className="mt-5 rounded-2xl border border-nvme-gold/30 bg-gradient-to-br from-nvme-surface to-black p-8 text-center">
        <p className="text-[10px] uppercase tracking-[0.3em] text-nvme-muted">NVME Balance</p>
        <p className="mt-2 font-display text-5xl text-nvme-gold">
          {bal.isLoading ? '…' : formatCount(bal.data?.balance ?? bal.data?.coins ?? 0)}
        </p>
        <p className="mt-1 text-xs text-nvme-muted">coins</p>
      </div>
      <div className="mt-5 flex gap-2">
        <input value={addr} onChange={(e) => setAddr(e.target.value)} placeholder="0x… wallet address"
          className="flex-1 rounded-xl border border-white/10 bg-nvme-surface px-4 py-3 text-sm outline-none focus:border-nvme-gold" />
        <button onClick={async () => { try { await walletApi.connect(addr); setLinked(true); } catch { /* offline */ } }} disabled={!addr.startsWith('0x')}
          className="btn-gold !px-5 disabled:opacity-40">
          {linked ? <Check size={16} /> : 'Connect'}
        </button>
      </div>
      <p className="mt-3 text-xs text-nvme-muted">Cash-out + gifting settle through the NVME wallet rails. PayPal payouts via Store.</p>
    </div>
  );
}
