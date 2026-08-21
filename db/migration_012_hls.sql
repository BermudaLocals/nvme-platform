-- ════════════════════════════════════════════════════════════════════════
-- Migration 012: HLS adaptive streaming
-- Adds videos.hls_url — the Cloudinary eager HLS master playlist (.m3u8)
-- URL, requested as an async streaming-profile transformation at upload
-- time and stored deterministically (sp_<profile> URL rewrite, same trick
-- as the thumbnail). NULL for rows uploaded before this migration; the
-- player falls back to the plain MP4 video_url for those, and also while
-- the async transcode is still finishing. getRankedFeed selects the
-- column straight through onto feed items.
-- Safe to re-run — idempotent (IF NOT EXISTS).
-- Run with: npm run migrate
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE videos ADD COLUMN IF NOT EXISTS hls_url TEXT;
