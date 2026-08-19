'use strict';

const crypto = require('crypto');

function registerFeedEngine(app, db, optionalAuth) {
  const MAX_LIMIT = 30;
  const DEFAULT_LIMIT = 12;

  function decodeCursor(value) {
    if (!value) return 0;
    try {
      const decoded = Buffer.from(String(value), 'base64url').toString('utf8');
      const offset = Number(decoded);
      return Number.isInteger(offset) && offset >= 0 ? offset : 0;
    } catch {
      return 0;
    }
  }

  function encodeCursor(offset) {
    return Buffer.from(String(offset), 'utf8').toString('base64url');
  }

  app.get('/api/feed/v2', optionalAuth, async (req, res) => {
    const started = Date.now();

    try {
      const limit = Math.min(
        Math.max(Number.parseInt(req.query.limit, 10) || DEFAULT_LIMIT, 1),
        MAX_LIMIT
      );

      const offset = decodeCursor(req.query.cursor);
      const userId = req.user?.id || null;
      const sessionId =
        typeof req.query.session_id === 'string' && req.query.session_id.length <= 128
          ? req.query.session_id
          : crypto.randomUUID();

      const result = await db.query(
        `
        WITH candidate_videos AS (
          SELECT
            v.id,
            v.video_url AS url,
            v.thumbnail_url AS thumbnail,
            v.title,
            v.description,
            v.tags,
            COALESCE(v.view_count, 0)::bigint AS views,
            COALESCE(v.like_count, 0)::bigint AS like_count,
            COALESCE(v.comment_count, 0)::bigint AS comment_count,
            v.created_at,
            v.user_id AS author_id,
            u.username,
            u.avatar_url,
            COALESCE(v.is_trending, false) AS is_trending,

            EXTRACT(
              EPOCH FROM (NOW() - v.created_at)
            ) / 3600.0 AS age_hours,

            CASE
              WHEN $1::uuid IS NOT NULL
                AND EXISTS (
                  SELECT 1
                  FROM follows f
                  WHERE f.follower_id = $1::uuid
                    AND f.following_id = v.user_id
                )
              THEN 1
              ELSE 0
            END AS from_followed_creator,

            CASE
              WHEN $1::uuid IS NOT NULL
                AND EXISTS (
                  SELECT 1
                  FROM video_likes vl
                  WHERE vl.user_id = $1::uuid
                    AND vl.video_id = v.id
                )
              THEN 1
              ELSE 0
            END AS already_liked,

            CASE
              WHEN $1::uuid IS NOT NULL
                AND EXISTS (
                  SELECT 1
                  FROM feed_events fe
                  WHERE fe.user_id = $1::uuid
                    AND fe.video_id = v.id
                    AND fe.event_type = 'view'
                    AND fe.created_at > NOW() - INTERVAL '24 hours'
                )
              THEN 1
              ELSE 0
            END AS recently_viewed

          FROM videos v
          JOIN users u ON u.id = v.user_id
          WHERE v.is_published = true
            AND COALESCE(u.is_banned, false) = false
            AND v.video_url IS NOT NULL
            AND v.video_url <> ''
            AND v.created_at > NOW() - INTERVAL '30 days'
        ),

        scored_videos AS (
          SELECT
            cv.*,

            (
              GREATEST(
                0,
                35 - LEAST(cv.age_hours, 35)
              )

              + LEAST(
                18,
                LN(1 + cv.views) * 3.5
              )

              + LEAST(
                16,
                LN(1 + cv.like_count) * 4.0
              )

              + LEAST(
                10,
                LN(1 + cv.comment_count) * 3.5
              )

              + CASE
                  WHEN cv.is_trending THEN 14
                  ELSE 0
                END

              + CASE
                  WHEN cv.from_followed_creator = 1 THEN 18
                  ELSE 0
                END

              - CASE
                  WHEN cv.recently_viewed = 1 THEN 35
                  ELSE 0
                END

              - CASE
                  WHEN cv.already_liked = 1 THEN 4
                  ELSE 0
                END
            ) AS recommendation_score

          FROM candidate_videos cv
        )

        SELECT
          id,
          url,
          thumbnail,
          title,
          description,
          views,
          like_count,
          comment_count,
          created_at,
          author_id,
          username,
          avatar_url,
          tags,
          is_trending,
          recommendation_score
        FROM scored_videos
        ORDER BY
          recommendation_score DESC,
          created_at DESC,
          id DESC
        OFFSET $2
        LIMIT $3
        `,
        [userId, offset, limit + 1]
      );

      const hasMore = result.rows.length > limit;
      const rows = result.rows.slice(0, limit);

      const items = rows.map((row) => ({
        id: row.id,
        url: row.url,
        thumbnail: row.thumbnail,
        title: row.title,
        description: row.description,
        views: Number(row.views || 0),
        like_count: Number(row.like_count || 0),
        comment_count: Number(row.comment_count || 0),
        created_at: row.created_at,
        author_id: row.author_id,
        username: row.username,
        avatar_url: row.avatar_url,
        tags: Array.isArray(row.tags) ? row.tags : [],
        is_trending: Boolean(row.is_trending)
      }));

      if (userId && items.length) {
        await db.query(
          `
          INSERT INTO feed_events
            (
              user_id,
              session_id,
              event_type,
              video_id,
              metadata
            )
          VALUES
            ($1, $2, 'feed_impression', $3, $4::jsonb)
          `,
          [
            userId,
            sessionId,
            items[0].id,
            JSON.stringify({
              count: items.length,
              offset,
              latency_ms: Date.now() - started
            })
          ]
        );
      }

      res.json({
        feed: items,
        items,
        nextCursor: hasMore ? encodeCursor(offset + limit) : undefined,
        sessionId,
        algorithm: 'nvme-for-you-v1',
        latencyMs: Date.now() - started
      });
    } catch (error) {
      console.error('Feed engine error:', error);

      res.status(500).json({
        error: 'Failed to fetch personalized feed'
      });
    }
  });

  app.post('/api/feed/events', optionalAuth, async (req, res) => {
    try {
      const {
        video_id,
        event_type,
        session_id,
        watch_ms,
        duration_ms,
        position_ms,
        completion_rate,
        metadata
      } = req.body || {};

      const allowedEvents = new Set([
        'impression',
        'view',
        'watch_start',
        'watch_progress',
        'watch_complete',
        'skip',
        'like',
        'unlike',
        'comment',
        'share',
        'save',
        'follow',
        'profile_open',
        'sound_open',
        'hashtag_open',
        'not_interested'
      ]);

      if (!event_type || !allowedEvents.has(event_type)) {
        return res.status(400).json({
          error: 'Invalid event_type'
        });
      }

      if (video_id) {
        const video = await db.query(
          'SELECT id FROM videos WHERE id = $1 LIMIT 1',
          [video_id]
        );

        if (!video.rows.length) {
          return res.status(404).json({
            error: 'Video not found'
          });
        }
      }

      await db.query(
        `
        INSERT INTO feed_events
          (
            user_id,
            session_id,
            event_type,
            video_id,
            watch_ms,
            duration_ms,
            position_ms,
            completion_rate,
            metadata
          )
        VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9::jsonb
          )
        `,
        [
          req.user?.id || null,
          typeof session_id === 'string' && session_id.length <= 128
            ? session_id
            : null,
          event_type,
          video_id || null,
          Number.isFinite(Number(watch_ms)) ? Number(watch_ms) : null,
          Number.isFinite(Number(duration_ms)) ? Number(duration_ms) : null,
          Number.isFinite(Number(position_ms)) ? Number(position_ms) : null,
          Number.isFinite(Number(completion_rate))
            ? Math.max(0, Math.min(1, Number(completion_rate)))
            : null,
          JSON.stringify(
            metadata && typeof metadata === 'object'
              ? metadata
              : {}
          )
        ]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error('Feed event error:', error);

      res.status(500).json({
        error: 'Failed to record feed event'
      });
    }
  });

  app.post('/api/feed/not-interested', optionalAuth, async (req, res) => {
    try {
      const { video_id, session_id } = req.body || {};

      if (!video_id) {
        return res.status(400).json({
          error: 'video_id is required'
        });
      }

      await db.query(
        `
        INSERT INTO feed_events
          (
            user_id,
            session_id,
            event_type,
            video_id
          )
        VALUES
          ($1, $2, 'not_interested', $3)
        `,
        [
          req.user?.id || null,
          typeof session_id === 'string' && session_id.length <= 128
            ? session_id
            : null,
          video_id
        ]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error('Not interested error:', error);

      res.status(500).json({
        error: 'Failed to update recommendation preference'
      });
    }
  });

  console.log('[NVME-FEED] recommendation engine mounted');
}

module.exports = registerFeedEngine;
