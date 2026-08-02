'use client';
import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Search, TrendingUp, Clock, Heart, Loader2, Play } from 'lucide-react';
import { search as searchApi, videos as videosApi, type NvmeVideo, type NvmeUser } from '@/lib/api';
import { formatCount, gradientFor, cn } from '@/lib/utils';

const CATS = ['All', 'Music', 'Comedy', 'Film', 'Gaming', 'Fashion', 'Sports'];
const FILTERS = [
  { id: 'trending', label: 'Trending', icon: TrendingUp },
  { id: 'newest', label: 'Newest', icon: Clock },
  { id: 'liked', label: 'Most Liked', icon: Heart }
];

export default function DiscoverPage() {
  return (
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center bg-nvme-bg"><Loader2 className="animate-spin text-nvme-gold" /></div>}>
      <DiscoverInner />
    </Suspense>
  );
}

function DiscoverInner() {
  const params = useSearchParams();
  const [q, setQ] = useState('');
  const [debounced, setDebounced] = useState('');
  const [cat, setCat] = useState(params.get('cat') || 'All');
  const [filter, setFilter] = useState('trending');

  useEffect(() => {
    const t = setTimeout(() => setDebounced(q.trim()), 350);
    return () => clearTimeout(t);
  }, [q]);

  const searchQ = useQuery({
    queryKey: ['search', debounced],
    queryFn: () => searchApi(debounced),
    enabled: debounced.length > 0,
    staleTime: 60_000
  });

  const trendingQ = useQuery({
    queryKey: ['discover-grid'],
    queryFn: () => videosApi.feed(),
    staleTime: 5 * 60_000
  });

  let grid: NvmeVideo[] = debounced ? (searchQ.data?.videos || []) : (trendingQ.data?.items || []);
  if (filter === 'newest') grid = [...grid].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  if (filter === 'liked') grid = [...grid].sort((a, b) => (b.like_count || 0) - (a.like_count || 0));

  const people: NvmeUser[] = debounced ? (searchQ.data?.users || []) : [];
  const loading = debounced ? searchQ.isLoading : trendingQ.isLoading;

  return (
    <div className="min-h-screen bg-nvme-bg px-4 pb-20 pt-24 sm:px-6">
      <div className="mx-auto max-w-6xl">
        <h1 className="font-display text-3xl tracking-wide">DISCOVER</h1>

        {/* Search */}
        <div className="relative mt-5">
          <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-nvme-muted" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search creators, videos, sounds…"
            aria-label="Search"
            className="w-full rounded-full border border-white/10 bg-nvme-surface py-3.5 pl-11 pr-4 text-sm outline-none transition-colors focus:border-nvme-gold" />
        </div>

        {/* Category pills */}
        <div className="mt-5 flex gap-2 overflow-x-auto pb-1 [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
          {CATS.map((c) => (
            <button key={c} onClick={() => setCat(c)}
              className={cn('shrink-0 rounded-full border px-4 py-2 text-xs font-bold transition-all',
                cat === c ? 'border-nvme-gold bg-nvme-gold text-black' : 'border-white/15 text-nvme-muted hover:border-nvme-gold/50 hover:text-white')}>
              {c}
            </button>
          ))}
        </div>

        {/* Filter pills */}
        <div className="mt-3 flex gap-2">
          {FILTERS.map((f) => (
            <button key={f.id} onClick={() => setFilter(f.id)}
              className={cn('flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[11px] font-bold transition-all',
                filter === f.id ? 'bg-white text-black' : 'bg-white/5 text-nvme-muted hover:text-white')}>
              <f.icon size={12} /> {f.label}
            </button>
          ))}
        </div>

        {/* People results */}
        {people.length > 0 && (
          <div className="mt-6">
            <p className="mb-3 text-xs font-bold uppercase tracking-widest text-nvme-muted">People</p>
            <div className="flex gap-3 overflow-x-auto pb-2">
              {people.map((u) => (
                <div key={u.id} className="flex w-36 shrink-0 flex-col items-center rounded-2xl border border-nvme-border bg-nvme-surface p-4">
                  <span className={cn('flex h-12 w-12 items-center justify-center overflow-hidden rounded-full bg-gradient-to-br text-sm font-black text-black', gradientFor(u.username))}>
                    {u.avatar_url ? <img src={u.avatar_url} alt="" className="h-full w-full object-cover" /> : (u.username || 'N')[0].toUpperCase()}
                  </span>
                  <p className="mt-2 max-w-full truncate text-xs font-bold">@{u.username}</p>
                  <p className="text-[10px] text-nvme-muted">{formatCount(u.followers)} followers</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Video grid */}
        <p className="mb-3 mt-6 text-xs font-bold uppercase tracking-widest text-nvme-muted">
          {debounced ? 'Videos' : 'Trending on NVME'}
        </p>
        {loading ? (
          <div className="py-16 text-center"><Loader2 className="mx-auto animate-spin text-nvme-gold" size={30} /></div>
        ) : grid.length === 0 ? (
          <p className="rounded-2xl border border-dashed border-white/10 py-16 text-center text-sm text-nvme-muted">
            {debounced ? `No results for “${debounced}”` : 'Nothing here yet — check back soon.'}
          </p>
        ) : (
          <div className="columns-2 gap-3 sm:columns-3 lg:columns-4">
            {grid.map((v, i) => (
              <motion.a key={v.id || i} href={`/feed?v=${v.id}`}
                initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.04, 0.5) }}
                className="group relative mb-3 block break-inside-avoid overflow-hidden rounded-2xl border border-nvme-border bg-nvme-surface transition-all hover:-translate-y-1 hover:border-nvme-gold/60">
                <div className={cn('flex aspect-[3/4] items-center justify-center bg-gradient-to-br', gradientFor(v.username))}>
                  {v.thumbnail
                    ? <img src={v.thumbnail} alt={v.title || 'NVME video'} className="h-full w-full object-cover" loading="lazy" />
                    : <Play size={34} className="text-black/40" />}
                </div>
                <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent p-3 pt-8">
                  <p className="line-clamp-1 text-xs font-bold">{v.title || v.description || `@${v.username}`}</p>
                  <p className="mt-0.5 flex items-center gap-2 text-[10px] text-nvme-muted">
                    <span>@{v.username}</span>
                    <span className="flex items-center gap-1"><Heart size={10} /> {formatCount(v.like_count)}</span>
                    <span className="flex items-center gap-1"><Play size={10} /> {formatCount(v.views)}</span>
                  </p>
                </div>
              </motion.a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
