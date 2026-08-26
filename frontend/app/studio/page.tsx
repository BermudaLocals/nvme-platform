'use client';
import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  UploadCloud, Film, BarChart3, Sparkles, Wallet, Loader2, Copy, Check,
  Radio, Video, Phone, MessageCircle, Palette, Image as ImageIcon, Wand2, SlidersHorizontal, X
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { uploadVideo, videos as videosApi, ai, wallet as walletApi, type NvmeVideo } from '@/lib/api';
import { formatCount, cn } from '@/lib/utils';

// PREMIUM TABS - Added LIVE HUB as first
const TABS = [
  { id: 'live', label: 'LIVE Hub', icon: Radio },
  { id: 'upload', label: 'Upload', icon: UploadCloud },
  { id: 'videos', label: 'My Videos', icon: Film },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'ai', label: 'AI Studio', icon: Sparkles },
  { id: 'wallet', label: 'Wallet', icon: Wallet }
];

// Filter state stays alive across modes - PERSISTENT
const FILTERS = [
  { id: 'none', label: 'Normal', class: '' },
  { id: 'bw', label: 'B&W', class: 'grayscale' },
  { id: 'warm', label: 'Warm', class: 'sepia' },
  { id: 'vivid', label: 'Vivid', class: 'saturate-150 contrast-125' },
  { id: 'cool', label: 'Cool', class: 'hue-rotate-30' },
];

const GREEN_SCREEN_ASSETS = [
  { id: 'none', label: 'None', url: null },
  { id: 'beach', label: 'Beach', url: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=600' },
  { id: 'city', label: 'City', url: 'https://images.unsplash.com/photo-1444723121867-7a241cacace9?w=600' },
  { id: 'studio-bg', label: 'Studio', url: 'https://images.unsplash.com/photo-1598488035139-bdbb22374218?w=600' },
];

export default function StudioPage() {
  const { user, isAuthenticated, hydrated, openAuth } = useAuth();
  const router = useRouter();
  const [tab, setTab] = useState('live'); // Start on LIVE HUB

  useEffect(() => {
    if (hydrated &&!isAuthenticated) openAuth('signin');
  }, [hydrated, isAuthenticated]);

  if (!hydrated) return <div className="flex min-h-screen items-center justify-center bg-nvme-bg"><Loader2 className="animate-spin text-nvme-gold" /></div>;
  if (!isAuthenticated ||!user) {
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
        {/* Sidebar - now horizontal scroll on mobile, vertical on desktop */}
        <aside className="flex gap-2 overflow-x-auto lg:w-56 lg:flex-col lg:gap-1">
          {TABS.map((t) => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={cn('flex shrink-0 items-center gap-2.5 rounded-xl px-4 py-3 text-sm font-bold transition-all',
                tab === t.id? 'bg-nvme-gold text-black' : 'text-nvme-muted hover:bg-white/5 hover:text-white')}>
              <t.icon size={17} /> {t.label}
            </button>
          ))}
        </aside>

        <div className="min-w-0 flex-1">
          <motion.div key={tab} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
            {tab === 'live' && <LiveHubTab username={user.username} />}
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

/* ---------------- NEW: LIVE HUB WITH SELECTOR RING ---------------- */
function LiveHubTab({ username }: { username: string }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [liveMode, setLiveMode] = useState<'youtube'|'tiktok'|'call'|'dm'>('tiktok');
  const [activeFilter, setActiveFilter] = useState('none');
  const [greenScreen, setGreenScreen] = useState<string | null>(null);
  const [filterIntensity, setFilterIntensity] = useState(100);
  const [showFilters, setShowFilters] = useState(false);
  const [showGreen, setShowGreen] = useState(false);
  const [showEffects, setShowEffects] = useState(false);

  // Mobile-first camera start
  useEffect(() => {
    if (navigator.mediaDevices && videoRef.current) {
      navigator.mediaDevices.getUserMedia({ video: true, audio: true }).then(s => {
        if (videoRef.current) videoRef.current.srcObject = s;
      }).catch(()=>{});
    }
  }, [liveMode]);

  const filterClass = FILTERS.find(f=>f.id===activeFilter)?.class || '';

  const MODES = [
    { id: 'youtube', label: 'YouTube', icon: Film, desc: 'Long-form' },
    { id: 'tiktok', label: 'TikTok LIVE', icon: Radio, desc: 'Vertical Live' },
    { id: 'call', label: 'Call', icon: Phone, desc: 'WhatsApp Video/Call' },
    { id: 'dm', label: 'DM', icon: MessageCircle, desc: 'Live Chat' },
  ] as const;

  return (
    <div className="relative">
      <div className="flex items-center justify-between">
        <h2 className="font-display text-2xl">LIVE HUB</h2>
        <span className="rounded-full bg-red-500/15 px-3 py-1 text- font-bold uppercase tracking-widest text-red-400 animate-pulse">● Live Engine</span>
      </div>

      {/* CENTER SELECTOR RING - Everything passes through here */}
      <div className="mt-6 relative mx-auto w-full max-w-">
        {/* Ring Labels */}
        <div className="flex justify-between px-2 pb-3">
          {MODES.map(m => (
            <button key={m.id} onClick={()=>setLiveMode(m.id)}
              className={cn('flex flex-col items-center gap-1 rounded-full px-3 py-1.5 text- font-bold uppercase tracking-wider transition-all',
                liveMode===m.id? 'bg-nvme-gold text-black scale-110' : 'bg-white/5 text-nvme-muted hover:bg-white/10')}>
              <m.icon size={14} /> {m.label}
            </button>
          ))}
        </div>

        {/* THE CENTER RING - Preview */}
        <div className="relative aspect-[9/14] sm:aspect-[9/12] overflow-hidden rounded-[2.5rem] border- border-nvme-gold/50 bg-black shadow-[0_0_40px_rgba(255,215,0,0.25)]">
          {/* Green Screen Background Pass-through */}
          {greenScreen && (
            <img src={greenScreen} alt="green screen" className="absolute inset-0 h-full w-full object-cover" />
          )}
          {/* Live Video */}
          <video
            ref={videoRef} autoPlay muted playsInline
            className={cn('absolute inset-0 h-full w-full object-cover transition-all', filterClass)}
            style={{ opacity: filterIntensity/100, mixBlendMode: greenScreen? 'normal' : 'normal' }}
          />
          {/* Filter Overlay */}
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent" />

          {/* Center HUD */}
          <div className="absolute bottom-20 left-1/2 -translate-x-1/2 flex gap-2">
             <span className="rounded-full bg-black/60 px-3 py-1 text- font-bold backdrop-blur">{MODES.find(m=>m.id===liveMode)?.desc}</span>
             <span className="rounded-full bg-black/60 px-3 py-1 text- font-bold backdrop-blur">{FILTERS.find(f=>f.id===activeFilter)?.label}</span>
          </div>

          {/* MOBILE-FIRST LIVE DOCK - Always visible */}
          <div className="absolute bottom-3 left-3 right-3 flex items-center justify-between rounded-full bg-black/70 p-2 backdrop-blur-xl border border-white/10">
            <button onClick={()=>setShowFilters(!showFilters)} className={cn('rounded-full p-3 transition-all', showFilters? 'bg-nvme-gold text-black' : 'bg-white/10 text-white hover:bg-white/20')}>
              <Palette size={18} />
            </button>
            <button onClick={()=>setShowGreen(!showGreen)} className={cn('rounded-full p-3 transition-all', showGreen? 'bg-nvme-gold text-black' : 'bg-white/10 text-white hover:bg-white/20')}>
              <ImageIcon size={18} />
            </button>
            <button className="rounded-full bg-red-500 px-6 py-3 text-xs font-black uppercase tracking-widest text-white shadow-lg">Go Live</button>
            <button onClick={()=>setShowEffects(!showEffects)} className={cn('rounded-full p-3 transition-all', showEffects? 'bg-nvme-gold text-black' : 'bg-white/10 text-white hover:bg-white/20')}>
              <Wand2 size={18} />
            </button>
            <button onClick={()=>setFilterIntensity(100)} className="rounded-full bg-white/10 p-3 text-white hover:bg-white/20">
              <SlidersHorizontal size={18} />
            </button>
          </div>
        </div>
      </div>

      {/* BOTTOM SHEETS - Pass through the ring */}
      <AnimatePresence>
        {showFilters && (
          <motion.div initial={{ y: 100, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 100, opacity: 0 }}
            className="fixed inset-x-0 bottom-0 z-50 mx-auto max-w-6xl rounded-t- border border-white/10 bg-nvme-surface/95 p-5 backdrop-blur-2xl sm:bottom-6 sm:rounded-2xl">
            <div className="flex items-center justify-between">
              <p className="text-xs font-bold uppercase tracking-widest text-nvme-gold">Filters - Mobile First - Stays On</p>
              <button onClick={()=>setShowFilters(false)} className="rounded-full bg-white/10 p-1.5"><X size={14}/></button>
            </div>
            <div className="mt-4 flex gap-3 overflow-x-auto pb-2">
              {FILTERS.map(f => (
                <button key={f.id} onClick={()=>setActiveFilter(f.id)}
                  className={cn('shrink-0 rounded-2xl border px-5 py-3 text-xs font-bold transition-all',
                    activeFilter===f.id? 'border-nvme-gold bg-nvme-gold text-black' : 'border-white/10 bg-white/5 text-white hover:bg-white/10')}>
                  {f.label}
                </button>
              ))}
            </div>
            <div className="mt-4">
              <label className="text- uppercase tracking-widest text-nvme-muted">Intensity {filterIntensity}%</label>
              <input type="range" min="0" max="100" value={filterIntensity} onChange={e=>setFilterIntensity(parseInt(e.target.value))} className="mt-2 w-full accent-nvme-gold" />
            </div>
          </motion.div>
        )}
        {showGreen && (
          <motion.div initial={{ y: 100, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 100, opacity: 0 }}
            className="fixed inset-x-0 bottom-0 z-50 mx-auto max-w-6xl rounded-t- border border-white/10 bg-nvme-surface/95 p-5 backdrop-blur-2xl sm:bottom-6 sm:rounded-2xl">
            <div className="flex items-center justify-between">
              <p className="text-xs font-bold uppercase tracking-widest text-nvme-gold">Green Screen Settings - Passes Through Ring</p>
              <button onClick={()=>setShowGreen(false)} className="rounded-full bg-white/10 p-1.5"><X size={14}/></button>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {GREEN_SCREEN_ASSETS.map(g => (
                <button key={g.id} onClick={()=>setGreenScreen(g.url)}
                  className={cn('overflow-hidden rounded-2xl border-2 text-left transition-all',
                    greenScreen===g.url? 'border-nvme-gold' : 'border-white/10 hover:border-white/20')}>
                  {g.url? <img src={g.url} alt={g.label} className="h-24 w-full object-cover" /> : <div className="flex h-24 items-center justify-center bg-white/5 text-xs">No BG</div>}
                  <p className="p-2 text- font-bold">{g.label}</p>
                </button>
              ))}
            </div>
            <p className="mt-3 text- text-nvme-muted">Tip: This green screen stays applied when you switch between YouTube / TikTok LIVE / Call modes because it passes through the center selector ring.</p>
          </motion.div>
        )}
        {showEffects && (
          <motion.div initial={{ y: 100, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 100, opacity: 0 }}
            className="fixed inset-x-0 bottom-0 z-50 mx-auto max-w-6xl rounded-t- border border-white/10 bg-nvme-surface/95 p-5 backdrop-blur-2xl sm:bottom-6 sm:rounded-2xl">
            <div className="flex items-center justify-between">
              <p className="text-xs font-bold uppercase tracking-widest text-nvme-gold">Effects & Features</p>
              <button onClick={()=>setShowEffects(false)} className="rounded-full bg-white/10 p-1.5"><X size={14}/></button>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2">
              {[
                { label: 'Beauty', icon: '✨' },
                { label: 'Blur', icon: '💫' },
                { label: 'AI Background', icon: '🤖' },
                { label: 'Captions', icon: '💬' },
                { label: 'Timer', icon: '⏱️' },
                { label: 'Duet', icon: '👥' },
              ].map(e => (
                <button key={e.label} className="rounded-xl bg-white/5 py-4 text-xs font-bold hover:bg-white/10">
                  <span className="block text-lg">{e.icon}</span>{e.label}
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="mt-6 rounded-2xl border border-nvme-gold/20 bg-nvme-surface p-4">
        <p className="text- font-bold uppercase tracking-widest text-nvme-gold">How it works (5-year-old smart):</p>
        <p className="mt-2 text-xs leading-relaxed text-nvme-muted">
          Think of the gold ring as a donut. The video is the hole in the middle. Filters and Green Screen are sprinkles.
          When you sprinkle, they stay on the donut even when you change the donut flavor from YouTube to TikTok LIVE to WhatsApp Call.
          That's "pass-through center selector ring". Your filters stay mobile-first at the bottom so your thumb can always reach them.
        </p>
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
        <label className="btn-outline mt-5 cursor-pointer!py-2 text-xs">
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
        {state === 'uploading'? <><Loader2 size={16} className="animate-spin" /> Uploading…</> : 'Publish to NVME'}
      </button>
      <p className={cn('mt-3 text-center text-xs', state === 'error'? 'text-nvme-coral' : 'text-nvme-gold')}>{msg}</p>
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
              {v.thumbnail? <img src={v.thumbnail} alt="" className="h-full w-full object-cover" /> : <video src={v.url} className="h-full w-full object-cover" muted preload="metadata" />}
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
          { label: 'Videos', value: vids.data?.length?? 0 },
          { label: 'Views', value: totalViews },
          { label: 'Likes', value: totalLikes },
          { label: 'Followers', value: stats.data?.followers?? 0 }
        ].map((s) => (
          <div key={s.label} className="rounded-2xl border border-nvme-border bg-nvme-surface p-5 text-center">
            <p className="font-display text-2xl text-nvme-gold">{formatCount(s.value)}</p>
            <p className="mt-1 text- uppercase tracking-widest text-nvme-muted">{s.label}</p>
          </div>
        ))}
      </div>
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
      const text = d.captions? d.captions.join('\n\n') : d.hashtags? (Array.isArray(d.hashtags)? d.hashtags.join(' ') : d.hashtags) : d.script || d.resultUrl || d.result || JSON.stringify(d);
      setResults((r) => [{ kind, text: String(text) },...r].slice(0, 10));
    } catch (e: any) {
      setResults((r) => [{ kind, text: `⚠ ${e.message || 'AI request failed'}` },...r]);
    } finally { setBusy(''); }
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <h2 className="font-display text-2xl">AI STUDIO</h2>
        <span className={cn('rounded-full px-3 py-1 text- font-bold uppercase tracking-wider',
          status.data? 'bg-nvme-gold/15 text-nvme-gold' : 'bg-white/5 text-nvme-muted')}>
          {status.data? `Online · ${status.data.model || 'kimi-k3'}` : 'Checking…'}
        </span>
      </div>
      <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} rows={3}
        placeholder="Describe your video, topic, or product…"
        className="mt-5 w-full rounded-xl border border-white/10 bg-nvme-surface px-4 py-3 text-sm outline-none focus:border-nvme-gold" />
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {(['captions', 'hashtags', 'script', 'generate'] as const).map((k) => (
          <button key={k} onClick={() => run(k)} disabled={!!busy ||!prompt.trim()}
            className="rounded-xl border border-nvme-gold/40 py-2.5 text-xs font-bold capitalize text-nvme-gold transition-all hover:bg-nvme-gold hover:text-black disabled:opacity-40">
            {busy === k? <Loader2 size={14} className="mx-auto animate-spin" /> : k}
          </button>
        ))}
      </div>
      <div className="mt-5 space-y-3">
        {results.map((r, i) => (
          <div key={i} className="rounded-xl border border-nvme-border bg-nvme-surface p-4">
            <div className="flex items-center justify-between">
              <p className="text- font-bold uppercase tracking-widest text-nvme-gold">{r.kind}</p>
              <button aria-label="Copy" onClick={() => { navigator.clipboard?.writeText(r.text); setCopied(i); setTimeout(() => setCopied(null), 1200); }}
                className="text-nvme-muted hover:text-nvme-gold">
                {copied === i? <Check size={14} /> : <Copy size={14} />}
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
        <p className="text- uppercase tracking-[0.3em] text-nvme-muted">NVME Balance</p>
        <p className="mt-2 font-display text-5xl text-nvme-gold">
          {bal.isLoading? '…' : formatCount(bal.data?.balance?? bal.data?.coins?? 0)}
        </p>
        <p className="mt-1 text-xs text-nvme-muted">coins</p>
      </div>
      <div className="mt-5 flex gap-2">
        <input value={addr} onChange={(e) => setAddr(e.target.value)} placeholder="0x… wallet address"
          className="flex-1 rounded-xl border border-white/10 bg-nvme-surface px-4 py-3 text-sm outline-none focus:border-nvme-gold" />
        <button onClick={async () => { try { await walletApi.connect(addr); setLinked(true); } catch { /* offline */ } }} disabled={!addr.startsWith('0x')}
          className="btn-gold!px-5 disabled:opacity-40">
          {linked? <Check size={16} /> : 'Connect'}
        </button>
      </div>
    </div>
  );
}
