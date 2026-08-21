'use client';
import { forwardRef, useCallback, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Heart, MessageCircle, Share2, Bookmark, Music2, X, Send, Loader2, ImagePlus } from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { videos, type NvmeVideo, type NvmeComment } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { formatCount, gradientFor, cn } from '@/lib/utils';

interface Props {
  video: NvmeVideo;
  isActive: boolean;
  registerRef: (el: HTMLVideoElement | null) => void;
}

const VideoCard = forwardRef<HTMLDivElement, Props>(function VideoCard({ video, isActive, registerRef }, ref) {
  const [liked, setLiked] = useState(false);
  const [likeCount, setLikeCount] = useState(video.like_count || 0);
  const [commentCount, setCommentCount] = useState(video.comment_count || 0);
  const [saved, setSaved] = useState(!!video.is_saved);
  const [muted, setMuted] = useState(true);
  const [heartBurst, setHeartBurst] = useState<number | null>(null);
  const [commentsOpen, setCommentsOpen] = useState(false);
  const [commentText, setCommentText] = useState('');
  const [commentImg, setCommentImg] = useState<string | null>(null);
  const localVid = useRef<HTMLVideoElement | null>(null);
  const lastTap = useRef(0);
  const qc = useQueryClient();
  const { openAuth } = useAuthStore();

  useEffect(() => {
    if (localVid.current) localVid.current.muted = muted;
  }, [muted]);

  const doLike = useCallback(async () => {
    if (liked) return;
    setLiked(true);
    setLikeCount((c) => c + 1);
    try { await videos.like(video.id); } catch { setLiked(false); setLikeCount((c) => Math.max(0, c - 1)); }
  }, [liked, video.id]);

  const doSave = useCallback(async () => {
    const next = !saved;
    setSaved(next);
    try { await videos.save(video.id); } catch { setSaved(!next); }
  }, [saved, video.id]);

  function onTap() {
    const now = Date.now();
    if (now - lastTap.current < 280) {
      // double-tap → like + heart burst
      setHeartBurst(now);
      doLike();
      lastTap.current = 0;
      return;
    }
    lastTap.current = now;
    setTimeout(() => {
      if (lastTap.current && Date.now() - lastTap.current >= 280) {
        const v = localVid.current;
        if (v) { v.paused ? v.play().catch(() => {}) : v.pause(); }
        lastTap.current = 0;
      }
    }, 290);
  }

  const commentsQuery = useQuery({
    queryKey: ['comments', video.id],
    queryFn: () => videos.comments(video.id),
    enabled: commentsOpen,
    staleTime: 60_000
  });

  const postMutation = useMutation({
    mutationFn: () => videos.postComment(video.id, commentText, commentImg),
    onSuccess: () => {
      setCommentText(''); setCommentImg(null);
      setCommentCount((c) => c + 1);
      qc.invalidateQueries({ queryKey: ['comments', video.id] });
    }
  });

  function attachPhoto(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    const img = new Image();
    const url = URL.createObjectURL(f);
    img.onload = () => {
      const MAX = 900;
      const scale = Math.min(1, MAX / Math.max(img.width, img.height));
      const c = document.createElement('canvas');
      c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
      c.getContext('2d')!.drawImage(img, 0, 0, c.width, c.height);
      setCommentImg(c.toDataURL('image/jpeg', 0.8));
      URL.revokeObjectURL(url);
    };
    img.src = url;
  }

  function share() {
    const url = `${location.origin}/feed?v=${video.id}`;
    if (navigator.share) navigator.share({ title: video.title || 'NVME', url }).catch(() => {});
    else navigator.clipboard?.writeText(url);
  }

  return (
    <div ref={ref} className="feed-snap-item relative h-full w-full overflow-hidden bg-black" onClick={onTap}>
      <video
        ref={(el) => { localVid.current = el; registerRef(el); }}
        className="absolute inset-0 h-full w-full object-cover"
        src={video.url}
        poster={video.thumbnail || undefined}
        loop muted playsInline preload="metadata"
        aria-label={video.title || 'NVME video'}
      />
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-t from-black/85 via-transparent to-black/40" />

      {/* Double-tap heart burst */}
      <AnimatePresence>
        {heartBurst && (
          <motion.div key={heartBurst}
            initial={{ scale: 0, opacity: 0 }} animate={{ scale: [0, 1.4, 1], opacity: [0, 1, 0.9], rotate: [0, -8, 0] }}
            exit={{ scale: 1.6, opacity: 0 }} transition={{ duration: 0.7 }}
            className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <Heart size={110} className="fill-nvme-coral text-nvme-coral drop-shadow-[0_0_30px_rgba(255,62,62,0.8)]" />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Top-left creator chip */}
      <div className="absolute left-4 top-4 flex items-center gap-2.5" onClick={(e) => e.stopPropagation()}>
        <span className={cn('flex h-10 w-10 items-center justify-center overflow-hidden rounded-full border-2 border-nvme-gold bg-gradient-to-br text-sm font-black text-black', gradientFor(video.username))}>
          {video.avatar_url ? <img src={video.avatar_url} alt="" className="h-full w-full object-cover" /> : (video.username || 'N')[0].toUpperCase()}
        </span>
        <div>
          <p className="text-sm font-bold text-white drop-shadow">@{video.username || 'nvme'}</p>
          <p className="text-[10px] uppercase tracking-wider text-nvme-gold">NVME Creator</p>
        </div>
      </div>

      {/* Mute pill */}
      <button aria-label={muted ? 'Unmute' : 'Mute'} onClick={(e) => { e.stopPropagation(); setMuted(!muted); }}
        className="focus-ring absolute right-4 top-4 rounded-full bg-black/50 px-3 py-1.5 text-xs font-bold backdrop-blur">
        {muted ? '🔇' : '🔊'}
      </button>

      {/* Right action rail */}
      <div className="absolute bottom-24 right-3 flex flex-col items-center gap-5" onClick={(e) => e.stopPropagation()}>
        <motion.button whileTap={{ scale: 0.75 }} aria-label="Like" onClick={doLike} className="flex flex-col items-center gap-1">
          <motion.span animate={liked ? { scale: [1, 1.5, 1] } : {}} transition={{ type: 'spring', stiffness: 500, damping: 12 }}>
            <Heart size={30} className={liked ? 'fill-nvme-coral text-nvme-coral' : 'text-white'} />
          </motion.span>
          <span className="text-xs font-bold">{formatCount(likeCount)}</span>
        </motion.button>
        <button aria-label="Comments" onClick={() => setCommentsOpen(true)} className="flex flex-col items-center gap-1">
          <MessageCircle size={30} className="text-white" />
          <span className="text-xs font-bold">{formatCount(commentCount)}</span>
        </button>
        <button aria-label="Share" onClick={share} className="flex flex-col items-center gap-1">
          <Share2 size={30} className="text-white" />
          <span className="text-xs font-bold">Share</span>
        </button>
        <button aria-label="Save" onClick={doSave} className="flex flex-col items-center gap-1">
          <Bookmark size={30} className={saved ? 'fill-nvme-gold text-nvme-gold' : 'text-white'} />
          <span className="text-xs font-bold">Save</span>
        </button>
      </div>

      {/* Caption + music */}
      <div className="absolute bottom-6 left-4 right-20" onClick={(e) => e.stopPropagation()}>
        <p className="line-clamp-2 text-sm text-white/95">{video.description || video.title || ''}</p>
        <p className="mt-2 flex items-center gap-2 text-xs text-nvme-muted">
          <Music2 size={13} className="text-nvme-gold" />
          <span className="animate-pulse">original sound — @{video.username || 'nvme'}</span>
        </p>
      </div>

      {/* Comments sheet */}
      <AnimatePresence>
        {commentsOpen && (
          <motion.div initial={{ y: '100%' }} animate={{ y: 0 }} exit={{ y: '100%' }} transition={{ type: 'spring', damping: 30, stiffness: 280 }}
            className="absolute inset-x-0 bottom-0 z-20 flex max-h-[72%] flex-col rounded-t-3xl border-t border-nvme-gold/20 bg-nvme-surface"
            onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-white/5 px-5 py-3.5">
              <p className="text-sm font-bold">{formatCount(commentCount)} comments</p>
              <button aria-label="Close comments" onClick={() => setCommentsOpen(false)} className="focus-ring rounded-full p-1.5 text-nvme-muted hover:text-white"><X size={18} /></button>
            </div>
            <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
              {commentsQuery.isLoading && <p className="py-6 text-center text-sm text-nvme-muted"><Loader2 className="mx-auto animate-spin" /></p>}
              {commentsQuery.isError && <p className="py-6 text-center text-sm text-nvme-coral">Couldn&apos;t load comments. Tap to retry.</p>}
              {commentsQuery.data?.length === 0 && <p className="py-6 text-center text-sm text-nvme-muted">Be the first to comment ✨</p>}
              {(commentsQuery.data || []).map((c: NvmeComment) => (
                <div key={c.id} className="flex gap-3">
                  <span className={cn('flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-gradient-to-br text-[11px] font-black text-black', gradientFor(c.username))}>
                    {c.avatar_url ? <img src={c.avatar_url} alt="" className="h-full w-full object-cover" /> : (c.username || 'N')[0].toUpperCase()}
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-nvme-gold">@{c.username} <span className="font-normal text-nvme-muted">{c.display_name}</span></p>
                    {c.text && <p className="mt-0.5 text-sm text-white/90">{c.text}</p>}
                    {c.image_url && <img src={c.image_url} alt="comment attachment" className="mt-2 max-h-40 rounded-xl" />}
                  </div>
                </div>
              ))}
            </div>
            <div className="border-t border-white/5 p-3">
              {commentImg && (
                <div className="relative mb-2 inline-block">
                  <img src={commentImg} alt="preview" className="h-14 rounded-lg" />
                  <button aria-label="Remove photo" onClick={() => setCommentImg(null)} className="absolute -right-1.5 -top-1.5 rounded-full bg-nvme-coral p-0.5"><X size={12} /></button>
                </div>
              )}
              <div className="flex items-center gap-2">
                <label aria-label="Attach photo" className="cursor-pointer rounded-full p-2 text-nvme-muted transition-colors hover:text-nvme-gold">
                  <ImagePlus size={20} /><input type="file" accept="image/*" className="hidden" onChange={attachPhoto} />
                </label>
                <input value={commentText} onChange={(e) => setCommentText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (commentText.trim() || commentImg) && postMutation.mutate()}
                  placeholder="Add a comment..."
                  className="flex-1 rounded-full border border-white/10 bg-black/40 px-4 py-2.5 text-sm outline-none focus:border-nvme-gold" />
                <button aria-label="Post comment" disabled={(!commentText.trim() && !commentImg) || postMutation.isPending}
                  onClick={() => postMutation.mutate()}
                  className="focus-ring rounded-full bg-nvme-gold p-2.5 text-black transition-all hover:bg-nvme-goldlight disabled:opacity-40">
                  {postMutation.isPending ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
});

export default VideoCard;
