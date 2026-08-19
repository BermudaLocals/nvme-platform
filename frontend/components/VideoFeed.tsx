'use client';

import { useEffect, useRef, useState } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Loader2, RefreshCw } from 'lucide-react';
import VideoCard from './VideoCard';
import { videos, type NvmeVideo } from '@/lib/api';

export default function VideoFeed() {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const videoEls = useRef<Map<number, HTMLVideoElement>>(new Map());
  const cardEls = useRef<Map<number, HTMLDivElement>>(new Map());

  const [activeIdx, setActiveIdx] = useState(0);
  const [pullY, setPullY] = useState(0);

  const touchStart = useRef(0);
  const sessionId = useRef<string | undefined>(undefined);

  const query = useInfiniteQuery({
    queryKey: ['feed', 'for-you'],
    queryFn: async ({ pageParam }) => {
      const result = await videos.feed(
        pageParam as string | undefined,
        sessionId.current
      );

      if (result.sessionId) {
        sessionId.current = result.sessionId;
      }

      return result;
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor,
    staleTime: 30 * 1000,
    refetchOnWindowFocus: false
  });

  const items: NvmeVideo[] =
    (query.data?.pages || []).flatMap(
      (page) => page.items
    );

  useEffect(() => {
    const root = containerRef.current;

    if (!root) return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          const idx = Number(
            (entry.target as HTMLElement).dataset.idx
          );

          const video = videoEls.current.get(idx);
          const item = items[idx];

          if (!video || !item) return;

          if (entry.intersectionRatio >= 0.6) {
            setActiveIdx(idx);

            video.play().catch(() => {});

            videos.event(
              'impression',
              item.id,
              {
                position_ms: Math.round(
                  video.currentTime * 1000
                )
              }
            ).catch(() => {});
          } else {
            video.pause();
          }
        });
      },
      {
        root,
        threshold: [0, 0.25, 0.6, 0.9]
      }
    );

    cardEls.current.forEach((element) => {
      observer.observe(element);
    });

    return () => observer.disconnect();
  }, [items.length]);

  useEffect(() => {
    if (
      activeIdx >= items.length - 3 &&
      query.hasNextPage &&
      !query.isFetchingNextPage
    ) {
      query.fetchNextPage();
    }
  }, [
    activeIdx,
    items.length,
    query.hasNextPage,
    query.isFetchingNextPage
  ]);

  function onTouchStart(
    event: React.TouchEvent
  ) {
    if (
      (containerRef.current?.scrollTop || 0) <= 0
    ) {
      touchStart.current =
        event.touches[0].clientY;
    }
  }

  function onTouchMove(
    event: React.TouchEvent
  ) {
    if (!touchStart.current) return;

    const delta =
      event.touches[0].clientY -
      touchStart.current;

    if (delta > 0) {
      setPullY(
        Math.min(110, delta * 0.5)
      );
    }
  }

  function onTouchEnd() {
    if (pullY > 70) {
      query.refetch();
    }

    setPullY(0);
    touchStart.current = 0;
  }

  if (query.isLoading) {
    return (
      <div className="flex h-full w-full items-center justify-center">
        <Loader2 className="animate-spin text-nvme-gold" />
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center">
        <p className="text-nvme-muted">
          Feed failed to load
        </p>

        <button
          onClick={() => query.refetch()}
          className="btn-gold mt-4"
        >
          Retry
        </button>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center">
        <p className="text-lg font-bold">
          NO VIDEOS YET
        </p>

        <p className="mt-2 text-sm text-nvme-muted">
          Be the first creator — upload from the Studio.
        </p>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="h-full w-full overflow-y-auto snap-y snap-mandatory"
      onTouchStart={onTouchStart}
      onTouchMove={onTouchMove}
      onTouchEnd={onTouchEnd}
    >
      {pullY > 0 && (
        <motion.div
          style={{ height: pullY }}
          className="flex items-end justify-center pb-2 text-nvme-gold"
        >
          <RefreshCw
            size={18}
            className={
              pullY > 70
                ? 'animate-spin'
                : ''
            }
          />
        </motion.div>
      )}

      {items.map((video, index) => (
        <div
          key={video.id || index}
          data-idx={index}
          className="h-full w-full snap-start"
          ref={(element) => {
            if (element) {
              cardEls.current.set(
                index,
                element
              );
            } else {
              cardEls.current.delete(index);
            }
          }}
        >
          <VideoCard
            video={video}
            isActive={activeIdx === index}
            registerRef={(element) => {
              if (element) {
                videoEls.current.set(
                  index,
                  element
                );
              } else {
                videoEls.current.delete(index);
              }
            }}
          />
        </div>
      ))}

      {query.isFetchingNextPage && (
        <div className="flex h-16 items-center justify-center">
          <Loader2 className="animate-spin text-nvme-gold" />
        </div>
      )}
    </div>
  );
}
