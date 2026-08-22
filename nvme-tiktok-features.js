// ============================================================
// NVME.LIVE — Discovery Features Module
// Salvaged from the old TikTok-parity module: hashtags, sounds,
// duets, challenges. Every query below targets the REAL schema
// (videos.video_url / thumbnail_url / view_count / tags /
// caption / hashtags, users.avatar_url, likes) — see
// db/schema.sql + migrations 002/004. Schema for this module
// lives in db/migration_013_discovery.sql, extended for real
// song uploads by db/migration_015_sounds_upload.sql
// (npm run migrate);
// mounting this file does zero DB work at require-time.
// NOT salvaged (wrong money/gift model in the old module):
// /api/search (collided with server.js), tips, creator fund,
// shop/product links, leaderboard, series, creator subs.
// ============================================================
'use strict';

module.exports = function(app, db, authMiddleware, optionalAuth, requireAdmin) {

  // Normalize a user-supplied tag: lowercase, no '#', [a-z0-9_] only
  // (also makes it safe to interpolate into the regexes below).
  const cleanTag = t =>
    String(t || '')
      .toLowerCase()
      .replace(/^#/, '')
      .replace(/[^a-z0-9_]/g, '')
      .slice(0, 30);

  // All the places a hashtag can live on a video: the tags[] column
  // (upload flow), the hashtags[] column (scraper flow — entries keep
  // their '#'), and inline #tokens in description (upload) / caption
  // (scraper). $1 is the cleaned lowercase tag.
  const TAG_MATCH_SQL = `
    EXISTS (
      SELECT 1
      FROM UNNEST(COALESCE(v.tags, '{}') || COALESCE(v.hashtags, '{}')) AS t
      WHERE LOWER(TRIM(LEADING '#' FROM t)) = $1
    )
    OR v.description ~* '(^|[^a-z0-9_])#' || $1 || '([^a-z0-9_]|$)'
    OR v.caption ~* '(^|[^a-z0-9_])#' || $1 || '([^a-z0-9_]|$)'
  `;

  // (video id, normalized tag) pairs across all tag sources — used for
  // trending / all / search aggregations. COUNT(DISTINCT vid) so a tag
  // present in both the array and the text counts once per video.
  const tagSourcesSql = recentOnly => `
    SELECT v.id AS vid, LOWER(TRIM(LEADING '#' FROM t)) AS tag
    FROM videos v,
         UNNEST(COALESCE(v.tags, '{}') || COALESCE(v.hashtags, '{}')) AS t
    WHERE v.is_published = true
    ${recentOnly ? `AND v.created_at > NOW() - INTERVAL '7 days'` : ''}
    UNION ALL
    SELECT v.id, LOWER(m[1])
    FROM videos v,
         LATERAL regexp_matches(
           COALESCE(v.description, '') || ' ' || COALESCE(v.caption, ''),
           '#([A-Za-z0-9_]+)', 'g'
         ) AS m
    WHERE v.is_published = true
    ${recentOnly ? `AND v.created_at > NOW() - INTERVAL '7 days'` : ''}
  `;

  // ── HASHTAGS ─────────────────────────────────────────────────

  // GET /api/hashtags/trending — top 20 hashtags by video count (7 days)
  app.get('/api/hashtags/trending', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT tag, COUNT(DISTINCT vid)::int AS video_count
        FROM (${tagSourcesSql(true)}) x
        WHERE tag <> ''
        GROUP BY tag
        ORDER BY video_count DESC, tag
        LIMIT 20
      `);
      res.json({ ok: true, hashtags: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/hashtags/all — all-time top hashtags
  app.get('/api/hashtags/all', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT tag, COUNT(DISTINCT vid)::int AS video_count
        FROM (${tagSourcesSql(false)}) x
        WHERE tag <> ''
        GROUP BY tag
        ORDER BY video_count DESC, tag
        LIMIT 50
      `);
      res.json({ ok: true, hashtags: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/hashtags/search?q= — hashtag name search (discovery only;
  // the platform-wide /api/search lives in server.js and is untouched)
  app.get('/api/hashtags/search', async (req, res) => {
    try {
      const q = cleanTag(req.query.q);
      if (!q) return res.json({ ok: true, hashtags: [] });
      const { rows } = await db.query(`
        SELECT tag, COUNT(DISTINCT vid)::int AS video_count
        FROM (${tagSourcesSql(false)}) x
        WHERE tag LIKE '%' || $1 || '%'
        GROUP BY tag
        ORDER BY video_count DESC, tag
        LIMIT 10
      `, [q]);
      res.json({ ok: true, hashtags: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/hashtags/:tag/videos — published videos carrying this tag,
  // ranked by the basic engagement counters (likes + comments + views)
  app.get('/api/hashtags/:tag/videos', optionalAuth, async (req, res) => {
    try {
      const tag = cleanTag(req.params.tag);
      if (!tag) return res.status(400).json({ error: 'invalid tag' });
      const viewerId = req.user ? req.user.id : null;
      const { rows } = await db.query(`
        SELECT v.id, v.video_url AS url, v.thumbnail_url AS thumbnail, v.hls_url,
               v.title, v.description, v.tags, v.created_at,
               v.view_count AS views, v.like_count, v.comment_count,
               u.id AS author_id, u.username, u.avatar_url,
               EXISTS (
                 SELECT 1 FROM likes l
                 WHERE l.video_id = v.id AND l.user_id = $2::uuid
               ) AS is_liked
        FROM videos v
        JOIN users u ON u.id = v.user_id
        WHERE v.is_published = true
          AND (${TAG_MATCH_SQL})
        ORDER BY (
          COALESCE(v.like_count, 0)
          + COALESCE(v.comment_count, 0)
          + COALESCE(v.view_count, 0)
        ) DESC, v.created_at DESC
        LIMIT 30
      `, [tag, viewerId]);
      res.json({ ok: true, tag, videos: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── SOUNDS ────────────────────────────────────────────────────

  // GET /api/sounds — sounds library
  app.get('/api/sounds', async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT * FROM sounds ORDER BY use_count DESC, created_at DESC LIMIT 50'
      );
      res.json({ ok: true, sounds: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/sounds/trending
  app.get('/api/sounds/trending', async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT * FROM sounds ORDER BY use_count DESC, created_at DESC LIMIT 20'
      );
      res.json({ ok: true, sounds: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/sounds/:id
  app.get('/api/sounds/:id', async (req, res) => {
    try {
      const { rows } = await db.query('SELECT * FROM sounds WHERE id=$1', [req.params.id]);
      if (!rows.length) return res.status(404).json({ error: 'sound not found' });
      res.json({ ok: true, sound: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/sounds — create a sound
  app.post('/api/sounds', authMiddleware, async (req, res) => {
    try {
      const { name, artist, url, cover_url, duration_sec } = req.body;
      if (!name || !url) return res.status(400).json({ error: 'name and url required' });
      const { rows } = await db.query(
        'INSERT INTO sounds (name, artist, url, cover_url, duration_sec) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [name, artist || 'Unknown', url, cover_url || null, duration_sec || 30]
      );
      res.json({ ok: true, sound: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/sounds/:id/videos — published videos using this sound
  app.get('/api/sounds/:id/videos', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.video_url AS url, v.thumbnail_url AS thumbnail,
               v.view_count AS views, u.username, u.avatar_url
        FROM videos v JOIN users u ON u.id = v.user_id
        WHERE v.sound_id = $1 AND v.is_published = true
        ORDER BY v.view_count DESC LIMIT 30
      `, [req.params.id]);
      res.json({ ok: true, videos: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── DUETS (videos.duet_of links a video to the one it duets) ──

  // GET /api/videos/:id/duets — published duets of this video
  app.get('/api/videos/:id/duets', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.video_url AS url, v.thumbnail_url AS thumbnail,
               v.view_count AS views, v.created_at,
               u.username, u.avatar_url
        FROM videos v JOIN users u ON u.id = v.user_id
        WHERE v.duet_of = $1 AND v.is_published = true
        ORDER BY v.created_at DESC LIMIT 20
      `, [req.params.id]);
      res.json({ ok: true, duets: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // PUT /api/videos/:id/duet — link/unlink your own video as a duet
  app.put('/api/videos/:id/duet', authMiddleware, async (req, res) => {
    try {
      const { duet_of } = req.body;
      if (duet_of) {
        if (duet_of === req.params.id) {
          return res.status(400).json({ error: 'video cannot duet itself' });
        }
        const { rows: target } = await db.query(
          'SELECT id FROM videos WHERE id=$1 AND is_published = true',
          [duet_of]
        );
        if (!target.length) return res.status(404).json({ error: 'duet target not found' });
      }
      const { rows } = await db.query(
        'UPDATE videos SET duet_of=$1 WHERE id=$2 AND user_id=$3 RETURNING id, duet_of',
        [duet_of || null, req.params.id, req.user.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'video not found or not yours' });
      res.json({ ok: true, duet_of: rows[0].duet_of });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // PUT /api/videos/:id/sound — attach/change/clear the sound on your own
  // video. Accepts { sound_id } (null clears). The sound must exist and be
  // public; usage counters (013 use_count + 015 usage_count) follow the
  // change: old sound -1, new sound +1.
  app.put('/api/videos/:id/sound', authMiddleware, async (req, res) => {
    try {
      const { sound_id } = req.body;
      if (sound_id) {
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sound_id)) {
          return res.status(400).json({ error: 'invalid sound_id' });
        }
        const { rows: sound } = await db.query(
          'SELECT id FROM sounds WHERE id=$1 AND is_public = true',
          [sound_id]
        );
        if (!sound.length) return res.status(404).json({ error: 'sound not found' });
      }
      const { rows: cur } = await db.query(
        'SELECT sound_id FROM videos WHERE id=$1 AND user_id=$2',
        [req.params.id, req.user.id]
      );
      if (!cur.length) return res.status(404).json({ error: 'video not found or not yours' });
      const prev = cur[0].sound_id;
      const next = sound_id || null;
      if (prev === next) return res.json({ ok: true, sound_id: next });
      await db.query(
        'UPDATE videos SET sound_id=$1 WHERE id=$2',
        [next, req.params.id]
      );
      if (prev) {
        await db.query(
          'UPDATE sounds SET usage_count = GREATEST(COALESCE(usage_count,0)-1,0), use_count = GREATEST(COALESCE(use_count,0)-1,0) WHERE id=$1',
          [prev]
        );
      }
      if (next) {
        await db.query(
          'UPDATE sounds SET usage_count = COALESCE(usage_count,0)+1, use_count = COALESCE(use_count,0)+1 WHERE id=$1',
          [next]
        );
      }
      res.json({ ok: true, sound_id: next });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── HASHTAG CHALLENGES ───────────────────────────────────────

  // GET /api/challenges — active hashtag challenges
  app.get('/api/challenges', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT hc.*, COUNT(v.id)::int AS participant_count
        FROM hashtag_challenges hc
        LEFT JOIN videos v ON v.is_published = true AND (
          EXISTS (
            SELECT 1
            FROM UNNEST(COALESCE(v.tags, '{}') || COALESCE(v.hashtags, '{}')) AS t
            WHERE LOWER(TRIM(LEADING '#' FROM t)) = hc.tag
          )
          OR v.description ~* '(^|[^a-z0-9_])#' || hc.tag || '([^a-z0-9_]|$)'
          OR v.caption ~* '(^|[^a-z0-9_])#' || hc.tag || '([^a-z0-9_]|$)'
        )
        WHERE hc.ends_at IS NULL OR hc.ends_at > NOW()
        GROUP BY hc.id
        ORDER BY participant_count DESC, hc.created_at DESC
        LIMIT 10
      `);
      res.json({ ok: true, challenges: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/challenges — create challenge (admin only)
  app.post('/api/challenges', authMiddleware, requireAdmin, async (req, res) => {
    try {
      const { description, prize_coins, ends_at } = req.body;
      const tag = cleanTag(req.body.tag);
      if (!tag) return res.status(400).json({ error: 'tag required' });
      const { rows } = await db.query(
        'INSERT INTO hashtag_challenges (tag, description, prize_coins, ends_at) VALUES ($1,$2,$3,$4) ON CONFLICT (tag) DO UPDATE SET description=$2, prize_coins=$3, ends_at=$4 RETURNING *',
        [tag, description || null, prize_coins || 0, ends_at || null]
      );
      res.json({ ok: true, challenge: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  console.log('[nvme-discovery] ✅ routes mounted: hashtags (trending/all/search/:tag/videos), sounds, duets, video sound attach, challenges');
};
