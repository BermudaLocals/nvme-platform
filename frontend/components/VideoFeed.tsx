'use client';
import { useEffect, useRef, useState } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Loader2, RefreshCw } from 'lucide-react';
import VideoCard from './VideoCard';
import { videos, type NvmeVideo } from '@/lib/api';

export default function VideoFeed() {
  const containerRef = useRef<HTMLDivElement>(null);
  const videoEls = useRef<Map<number, HTMLVideoElement>>(new Map());
  const cardEls = useRef<Map<number, HTMLDivElement>>(new Map());
  const [activeIdx, setActiveIdx] = useState(0);
  const [pullY, setPullY] = useState(0);
  const touchStart = useRef(0);

  const query = useInfiniteQuery({
    queryKey: ['feed'],
    queryFn: ({ pageParam }) => videos.feed(pageParam as string | undefined),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor,
    staleTime: 5 * 60 * 1000
  });

  const items: NvmeVideo[] = (query.data?.pages || []).flatMap((p) => p.items);

  // TikTok autoplay: play the card 60%+ visible, pause everything else
  useEffect(() => {
    const root = containerRef.current;
    if (!root) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        const idx = Number((e.target as HTMLElement).dataset.idx);
        const v = videoEls.current.get(idx);
        if (!v) return;
        if (e.intersectionRatio >= 0.6) {
          setActiveIdx(idx);
          videos.view(items[idx]?.id);
          v.play().catch(() => {});
        } else {
          v.pause();
        }
      });
    }, { root, threshold: [0, 0.25, 0.6, 0.9] });
    cardEls.current.forEach((el) => obs.observe(el));
    return () => obs.disconnect();
  }, [items.length]);

  // Load more when near the end
  useEffect(() => {
    if (activeIdx >= items.length - 3 && query.hasNextPage && !query.isFetchingNextPage) {
      query.fetchNextPage();
    }
  }, [activeIdx]); // eslint-disable-line react-hooks/exhaustive-deps

  // Pull-to-refresh (only at the top)
  function onTouchStart(e: React.TouchEvent) {
    if ((containerRef.current?.scrollTop || 0) <= 0) touchStart.current = e.touches[0].clientY;
  }
  function onTouchMove(e: React.TouchEvent) {
    if (!touchStart.current) return;
    const dy = e.touches[0].clientY - touchStart.current;
    if (dy > 0) setPullY(Math.min(110, dy * 0.5));
  }
  function onTouchEnd() {
    if (pullY > 70) query.refetch();
    setPullY(0);
    touchStart.current = 0;
  }

  if (query.isLoading) {
    return (
      <div className="flex h-full items-center justify-center bg-black">
        <div className="text-center">
          <Loader2 className="mx-auto animate-spin text-nvme-gold" size={36} />
          <p className="mt-3 text-sm text-nvme-muted">Loading your feed…</p>
        </div>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="flex h-full items-center justify-center bg-black">
        <div className="text-center">
          <p className="text-nvme-coral">Feed failed to load</p>
          <button onClick={() => query.refetch()} className="btn-gold mt-4"><RefreshCw size={15} /> Retry</button>
        </div>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="flex h-full items-center justify-center bg-black px-8 text-center">
        <div>
          <p className="font-display text-2xl">NO VIDEOS YET</p>
          <p className="mt-2 text-sm text-nvme-muted">Be the first creator — upload from the Studio.</p>
          <a href="/studio" className="btn-gold mt-5 inline-flex">Open Studio</a>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="feed-snap relative h-full overflow-y-auto bg-black"
      onTouchStart={onTouchStart} onTouchMove={onTouchMove} onTouchEnd={onTouchEnd}
    >
      {pullY > 0 && (
        <motion.div style={{ height: pullY }} className="flex items-end justify-center pb-2 text-nvme-gold">
          <RefreshCw size={22} className={pullY > 70 ? 'animate-spin' : ''} />
        </motion.div>
      )}
      {items.map((v, i) => (
        <div key={v.id || i} data-idx={i} className="h-full w-full">
          <VideoCard
            video={v}
            isActive={activeIdx === i}
            registerRef={(el) => { el ? videoEls.current.set(i, el) : videoEls.current.delete(i); }}
            ref={(el) => { el ? cardEls.current.set(i, el) : cardEls.current.delete(i); }}
          />
        </div>
      ))}
      {query.isFetchingNextPage && (
        <div className="flex h-24 items-center justify-center text-nvme-gold"><Loader2 className="animate-spin" /></div>
      )}
    </div>
  );
}
