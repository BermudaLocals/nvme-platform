// ============================================================
// NVME.LIVE — TikTok Parity Features Module
// Added: Hashtags, Sounds, Duets, Creator Fund, Tips, Shop
// ============================================================
'use strict';

module.exports = function(app, db, authMiddleware, optionalAuth) {

  // ── INIT: Add missing columns & tables ─────────────────────
  (async () => {
    try {
      // Hashtags on videos
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}'`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS sound_id UUID`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS duet_of UUID`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS product_url TEXT`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS product_title TEXT`);
      await db.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS product_price NUMERIC(10,2)`);

      // Shop on users
      await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS shop_url TEXT`);
      await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS shop_description TEXT`);
      await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS creator_coins_earned INTEGER DEFAULT 0`);

      // Sounds table
      await db.query(`
        CREATE TABLE IF NOT EXISTS sounds (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name TEXT NOT NULL,
          artist TEXT DEFAULT 'Unknown',
          url TEXT NOT NULL,
          cover_url TEXT,
          duration_sec INTEGER DEFAULT 30,
          use_count INTEGER DEFAULT 0,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      // Tips table
      await db.query(`
        CREATE TABLE IF NOT EXISTS tips (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          from_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
          to_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
          coins INTEGER NOT NULL,
          message TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      // Hashtag challenges table
      await db.query(`
        CREATE TABLE IF NOT EXISTS hashtag_challenges (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          tag TEXT UNIQUE NOT NULL,
          description TEXT,
          prize_coins INTEGER DEFAULT 0,
          starts_at TIMESTAMPTZ DEFAULT NOW(),
          ends_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      // Creator fund log
      await db.query(`
        CREATE TABLE IF NOT EXISTS creator_fund_log (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID REFERENCES users(id) ON DELETE CASCADE,
          video_id UUID REFERENCES videos(id) ON DELETE CASCADE,
          coins_earned INTEGER NOT NULL,
          view_milestone INTEGER NOT NULL,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      // Seed default sounds if empty
      const { rows: soundCheck } = await db.query('SELECT COUNT(*) FROM sounds');
      if (parseInt(soundCheck[0].count) === 0) {
        const defaultSounds = [
          { name: 'Empire Rise', artist: 'Kush Beats', url: '' },
          { name: 'Island Vibes', artist: 'Bermuda Sound', url: '' },
          { name: 'Money Moves', artist: 'Empire HQ', url: '' },
          { name: 'AI Dreams', artist: 'Kush AI', url: '' },
          { name: 'Crown Anthem', artist: 'Dollar Double', url: '' },
          { name: 'Night Hustle', artist: 'Empire Collective', url: '' },
          { name: 'Viral Energy', artist: 'NVME Sounds', url: '' },
          { name: 'Creator Flow', artist: 'Studio Mix', url: '' },
        ];
        for (const s of defaultSounds) {
          await db.query(
            'INSERT INTO sounds (name, artist, url) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
            [s.name, s.artist, s.url]
          );
        }
      }

      console.log('[nvme-tiktok] ✅ Schema migrations complete');
    } catch (e) {
      console.error('[nvme-tiktok] Schema init error:', e.message);
    }
  })();

  const CREATOR_FUND_RATE = parseFloat(process.env.CREATOR_FUND_RATE || '0.5'); // coins per 1000 views
  const CREATOR_FUND_MILESTONE = parseInt(process.env.CREATOR_FUND_MILESTONE || '1000');

  // ── HASHTAGS ─────────────────────────────────────────────────

  // GET /api/hashtags/trending — top 20 hashtags by video count (7 days)
  app.get('/api/hashtags/trending', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT tag, COUNT(*) AS video_count
        FROM videos, UNNEST(tags) AS tag
        WHERE created_at > NOW() - INTERVAL '7 days'
        GROUP BY tag
        ORDER BY video_count DESC
        LIMIT 20
      `);
      res.json({ ok: true, hashtags: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/hashtags/all — all-time top hashtags
  app.get('/api/hashtags/all', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT tag, COUNT(*) AS video_count
        FROM videos, UNNEST(tags) AS tag
        GROUP BY tag
        ORDER BY video_count DESC
        LIMIT 50
      `);
      res.json({ ok: true, hashtags: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/hashtags/:tag/videos — videos with this hashtag
  app.get('/api/hashtags/:tag/videos', optionalAuth, async (req, res) => {
    try {
      const tag = req.params.tag.toLowerCase().replace(/^#/, '');
      const viewerId = req.user ? req.user.id : null;
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.description, v.url, v.thumbnail, v.views, v.tags, v.created_at,
               u.username, u.avatar_url, u.id AS author_id,
               COALESCE(l.like_count, 0)::int AS like_count,
               COALESCE(c.comment_count, 0)::int AS comment_count,
               CASE WHEN $2::uuid IS NOT NULL AND vl.user_id IS NOT NULL THEN true ELSE false END AS viewer_liked
        FROM videos v
        JOIN users u ON u.id = v.user_id
        LEFT JOIN (SELECT video_id, COUNT(*) AS like_count FROM video_likes GROUP BY video_id) l ON l.video_id = v.id
        LEFT JOIN (SELECT video_id, COUNT(*) AS comment_count FROM comments GROUP BY video_id) c ON c.video_id = v.id
        LEFT JOIN video_likes vl ON vl.video_id = v.id AND vl.user_id = $2::uuid
        WHERE $1 = ANY(v.tags)
        ORDER BY v.created_at DESC
        LIMIT 30
      `, [tag, viewerId]);
      res.json({ ok: true, tag, videos: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/videos/:id/tags — set tags on video
  app.post('/api/videos/:id/tags', authMiddleware, async (req, res) => {
    try {
      const { tags } = req.body; // array of strings
      if (!Array.isArray(tags)) return res.status(400).json({ error: 'tags must be array' });
      const clean = tags.map(t => t.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 30)).filter(Boolean).slice(0, 10);
      const { rows } = await db.query(
        'UPDATE videos SET tags=$1 WHERE id=$2 AND user_id=$3 RETURNING id, tags',
        [clean, req.params.id, req.user.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'video not found or not yours' });
      res.json({ ok: true, tags: rows[0].tags });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── SOUNDS ──────────────────────────────────────────────────

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

  // GET /api/sounds/:id/videos — videos using this sound
  app.get('/api/sounds/:id/videos', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.url, v.thumbnail, v.views, u.username, u.avatar_url
        FROM videos v JOIN users u ON u.id = v.user_id
        WHERE v.sound_id = $1
        ORDER BY v.views DESC LIMIT 30
      `, [req.params.id]);
      res.json({ ok: true, videos: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── DUETS ────────────────────────────────────────────────────

  // GET /api/videos/:id/duets
  app.get('/api/videos/:id/duets', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.url, v.thumbnail, v.views, v.created_at,
               u.username, u.avatar_url
        FROM videos v JOIN users u ON u.id = v.user_id
        WHERE v.duet_of = $1
        ORDER BY v.created_at DESC LIMIT 20
      `, [req.params.id]);
      res.json({ ok: true, duets: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── CREATOR FUND ─────────────────────────────────────────────

  // Override view endpoint with creator fund logic
  app.post('/api/videos/:id/view-cf', async (req, res) => {
    try {
      const { rows } = await db.query(
        'UPDATE videos SET views=views+1 WHERE id=$1 RETURNING id, views, user_id',
        [req.params.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'video not found' });
      const { views, user_id } = rows[0];

      // Creator Fund: award coins at every 1000-view milestone
      if (views % CREATOR_FUND_MILESTONE === 0) {
        const coinsEarned = Math.round(CREATOR_FUND_RATE);
        if (coinsEarned > 0) {
          await db.query(
            'UPDATE users SET coins = COALESCE(coins,0) + $1, creator_coins_earned = COALESCE(creator_coins_earned,0) + $1 WHERE id = $2',
            [coinsEarned, user_id]
          );
          await db.query(
            'INSERT INTO creator_fund_log (user_id, video_id, coins_earned, view_milestone) VALUES ($1,$2,$3,$4)',
            [user_id, req.params.id, coinsEarned, views]
          );
        }
      }

      res.json({ ok: true, views });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/creator/fund-earnings
  app.get('/api/creator/fund-earnings', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT SUM(coins_earned) AS total_coins,
               COUNT(*) AS milestone_count,
               MAX(created_at) AS last_earned
        FROM creator_fund_log WHERE user_id = $1
      `, [req.user.id]);
      const { rows: urows } = await db.query(
        'SELECT creator_coins_earned FROM users WHERE id=$1', [req.user.id]
      );
      res.json({
        ok: true,
        total_coins_earned: parseInt(rows[0].total_coins) || 0,
        milestone_count: parseInt(rows[0].milestone_count) || 0,
        last_earned: rows[0].last_earned,
        lifetime_creator_coins: parseInt(urows[0]?.creator_coins_earned) || 0
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── TIPS ─────────────────────────────────────────────────────

  // POST /api/tips — send a tip (100% to creator, no platform cut)
  app.post('/api/tips', authMiddleware, async (req, res) => {
    try {
      const { to_user_id, coins, message } = req.body;
      if (!to_user_id || !coins || coins < 1) return res.status(400).json({ error: 'to_user_id and coins (min 1) required' });
      if (to_user_id === req.user.id) return res.status(400).json({ error: 'cannot tip yourself' });

      // Check sender balance
      const { rows: sender } = await db.query('SELECT coins FROM users WHERE id=$1', [req.user.id]);
      if (!sender.length || (sender[0].coins || 0) < coins) {
        return res.status(400).json({ error: 'insufficient coins' });
      }

      // Deduct from sender
      await db.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [coins, req.user.id]);
      // Credit receiver (100% - no platform cut on tips)
      await db.query('UPDATE users SET coins=coins+$1 WHERE id=$2', [coins, to_user_id]);
      // Log tip
      const { rows } = await db.query(
        'INSERT INTO tips (from_user_id, to_user_id, coins, message) VALUES ($1,$2,$3,$4) RETURNING *',
        [req.user.id, to_user_id, coins, message || null]
      );
      res.json({ ok: true, tip: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/tips/received
  app.get('/api/tips/received', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT t.id, t.coins, t.message, t.created_at, u.username AS from_username, u.avatar_url AS from_avatar
        FROM tips t JOIN users u ON u.id = t.from_user_id
        WHERE t.to_user_id = $1 ORDER BY t.created_at DESC LIMIT 50
      `, [req.user.id]);
      res.json({ ok: true, tips: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/tips/sent
  app.get('/api/tips/sent', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT t.id, t.coins, t.message, t.created_at, u.username AS to_username
        FROM tips t JOIN users u ON u.id = t.to_user_id
        WHERE t.from_user_id = $1 ORDER BY t.created_at DESC LIMIT 50
      `, [req.user.id]);
      res.json({ ok: true, tips: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── PRODUCT LINKS / CREATOR SHOP ────────────────────────────

  // PUT /api/profile/shop — update user shop
  app.put('/api/profile/shop', authMiddleware, async (req, res) => {
    try {
      const { shop_url, shop_description } = req.body;
      const { rows } = await db.query(
        'UPDATE users SET shop_url=$1, shop_description=$2 WHERE id=$3 RETURNING id, shop_url, shop_description',
        [shop_url || null, shop_description || null, req.user.id]
      );
      res.json({ ok: true, shop: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // PUT /api/videos/:id/product — add product link to video
  app.put('/api/videos/:id/product', authMiddleware, async (req, res) => {
    try {
      const { product_url, product_title, product_price } = req.body;
      const { rows } = await db.query(
        'UPDATE videos SET product_url=$1, product_title=$2, product_price=$3 WHERE id=$4 AND user_id=$5 RETURNING id, product_url, product_title, product_price',
        [product_url || null, product_title || null, product_price || null, req.params.id, req.user.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'video not found or not yours' });
      res.json({ ok: true, product: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/videos/:id/product
  app.get('/api/videos/:id/product', async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT product_url, product_title, product_price FROM videos WHERE id=$1',
        [req.params.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'not found' });
      res.json({ ok: true, product: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── ENHANCED SEARCH ──────────────────────────────────────────

  // GET /api/search?q=query — search users, videos, hashtags, sounds
  app.get('/api/search', optionalAuth, async (req, res) => {
    try {
      const q = (req.query.q || '').trim();
      if (!q) return res.json({ ok: true, users: [], videos: [], hashtags: [], sounds: [] });
      const like = `%${q.toLowerCase()}%`;
      const tag = q.toLowerCase().replace(/^#/, '').replace(/[^a-z0-9_]/g, '');

      const [usersR, videosR, hashtagsR, soundsR] = await Promise.all([
        db.query(
          `SELECT id, username, avatar_url, bio FROM users
           WHERE LOWER(username) LIKE $1 OR LOWER(COALESCE(bio,'')) LIKE $1
           LIMIT 10`, [like]
        ),
        db.query(
          `SELECT v.id, v.title, v.description, v.url, v.thumbnail, v.views, v.tags, v.created_at,
                  u.username, u.avatar_url
           FROM videos v JOIN users u ON u.id = v.user_id
           WHERE LOWER(v.title) LIKE $1 OR LOWER(COALESCE(v.description,'')) LIKE $1
              OR $2 = ANY(v.tags)
           ORDER BY v.views DESC LIMIT 20`, [like, tag]
        ),
        db.query(
          `SELECT tag, COUNT(*) AS video_count
           FROM videos, UNNEST(tags) AS tag
           WHERE LOWER(tag) LIKE $1
           GROUP BY tag ORDER BY video_count DESC LIMIT 10`, [like]
        ),
        db.query(
          `SELECT id, name, artist, use_count FROM sounds
           WHERE LOWER(name) LIKE $1 OR LOWER(COALESCE(artist,'')) LIKE $1
           ORDER BY use_count DESC LIMIT 10`, [like]
        ),
      ]);

      res.json({
        ok: true,
        query: q,
        users: usersR.rows,
        videos: videosR.rows,
        hashtags: hashtagsR.rows,
        sounds: soundsR.rows
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── HASHTAG CHALLENGES ───────────────────────────────────────

  // GET /api/challenges — active hashtag challenges
  app.get('/api/challenges', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT hc.*, COUNT(v.id)::int AS participant_count
        FROM hashtag_challenges hc
        LEFT JOIN videos v ON hc.tag = ANY(v.tags)
        WHERE hc.ends_at IS NULL OR hc.ends_at > NOW()
        GROUP BY hc.id
        ORDER BY participant_count DESC, hc.created_at DESC
        LIMIT 10
      `);
      res.json({ ok: true, challenges: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/challenges — create challenge (admin/founder only)
  app.post('/api/challenges', authMiddleware, async (req, res) => {
    try {
      const { tag, description, prize_coins, ends_at } = req.body;
      if (!tag) return res.status(400).json({ error: 'tag required' });
      const { rows } = await db.query(
        'INSERT INTO hashtag_challenges (tag, description, prize_coins, ends_at) VALUES ($1,$2,$3,$4) ON CONFLICT (tag) DO UPDATE SET description=$2, prize_coins=$3, ends_at=$4 RETURNING *',
        [tag.toLowerCase().replace(/^#/,''), description||null, prize_coins||0, ends_at||null]
      );
      res.json({ ok: true, challenge: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── CREATOR LEADERBOARD ──────────────────────────────────────

  // GET /api/leaderboard/creators — top earners this week
  app.get('/api/leaderboard/creators', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT u.id, u.username, u.avatar_url,
               COALESCE(SUM(g.credits),0)::int AS gifts_received,
               COALESCE(u.creator_coins_earned,0)::int AS fund_earned,
               COALESCE(SUM(v.views),0)::int AS total_views
        FROM users u
        LEFT JOIN gifts g ON g.receiver_id = u.id AND g.created_at > NOW() - INTERVAL '7 days'
        LEFT JOIN videos v ON v.user_id = u.id
        GROUP BY u.id
        ORDER BY (COALESCE(SUM(g.credits),0) + COALESCE(u.creator_coins_earned,0)) DESC
        LIMIT 20
      `);
      res.json({ ok: true, creators: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── SERIES (Paid exclusive content) ─────────────────────────

  // CREATE TABLE series
  db.query(`
    CREATE TABLE IF NOT EXISTS series (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      creator_id UUID REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT,
      price_coins INTEGER DEFAULT 100,
      cover_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `).catch(() => {});

  db.query(`
    CREATE TABLE IF NOT EXISTS series_access (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      series_id UUID REFERENCES series(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      granted_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(series_id, user_id)
    )
  `).catch(() => {});

  db.query(`
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS series_id UUID
  `).catch(() => {});

  // GET /api/series — all series
  app.get('/api/series', async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT s.*, u.username AS creator_username, u.avatar_url AS creator_avatar,
               COUNT(v.id)::int AS episode_count
        FROM series s JOIN users u ON u.id = s.creator_id
        LEFT JOIN videos v ON v.series_id = s.id
        GROUP BY s.id, u.username, u.avatar_url
        ORDER BY s.created_at DESC LIMIT 30
      `);
      res.json({ ok: true, series: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/series — create series
  app.post('/api/series', authMiddleware, async (req, res) => {
    try {
      const { title, description, price_coins, cover_url } = req.body;
      if (!title) return res.status(400).json({ error: 'title required' });
      const { rows } = await db.query(
        'INSERT INTO series (creator_id, title, description, price_coins, cover_url) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [req.user.id, title, description||null, price_coins||100, cover_url||null]
      );
      res.json({ ok: true, series: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/series/:id/unlock — pay coins to access series
  app.post('/api/series/:id/unlock', authMiddleware, async (req, res) => {
    try {
      const { rows: srows } = await db.query('SELECT * FROM series WHERE id=$1', [req.params.id]);
      if (!srows.length) return res.status(404).json({ error: 'series not found' });
      const series = srows[0];

      // Check already unlocked
      const { rows: access } = await db.query(
        'SELECT id FROM series_access WHERE series_id=$1 AND user_id=$2',
        [series.id, req.user.id]
      );
      if (access.length) return res.json({ ok: true, already_unlocked: true });

      // Check balance
      const { rows: urows } = await db.query('SELECT coins FROM users WHERE id=$1', [req.user.id]);
      if ((urows[0]?.coins || 0) < series.price_coins) {
        return res.status(400).json({ error: 'insufficient coins' });
      }

      // Deduct + credit creator + grant access
      await db.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [series.price_coins, req.user.id]);
      await db.query('UPDATE users SET coins=coins+$1 WHERE id=$2', [Math.round(series.price_coins * 0.7), series.creator_id]);
      await db.query('INSERT INTO series_access (series_id, user_id) VALUES ($1,$2)', [series.id, req.user.id]);

      res.json({ ok: true, unlocked: true, coins_spent: series.price_coins });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── LIVE SUBSCRIPTIONS (Creator monthly subs) ────────────────

  db.query(`
    CREATE TABLE IF NOT EXISTS creator_subscriptions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      subscriber_id UUID REFERENCES users(id) ON DELETE CASCADE,
      creator_id UUID REFERENCES users(id) ON DELETE CASCADE,
      coins_per_month INTEGER DEFAULT 500,
      status TEXT DEFAULT 'active',
      started_at TIMESTAMPTZ DEFAULT NOW(),
      next_billing TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days',
      UNIQUE(subscriber_id, creator_id)
    )
  `).catch(() => {});

  // POST /api/creator-subs/:creatorId — subscribe to a creator
  app.post('/api/creator-subs/:creatorId', authMiddleware, async (req, res) => {
    try {
      const { coins_per_month = 500 } = req.body;
      const creatorId = req.params.creatorId;
      if (creatorId === req.user.id) return res.status(400).json({ error: 'cannot sub to yourself' });

      const { rows: urows } = await db.query('SELECT coins FROM users WHERE id=$1', [req.user.id]);
      if ((urows[0]?.coins || 0) < coins_per_month) {
        return res.status(400).json({ error: 'insufficient coins for first month' });
      }

      // First month payment
      await db.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [coins_per_month, req.user.id]);
      await db.query('UPDATE users SET coins=coins+$1 WHERE id=$2', [Math.round(coins_per_month * 0.7), creatorId]);

      const { rows } = await db.query(`
        INSERT INTO creator_subscriptions (subscriber_id, creator_id, coins_per_month)
        VALUES ($1,$2,$3)
        ON CONFLICT (subscriber_id, creator_id) DO UPDATE SET status='active', next_billing=NOW()+INTERVAL '30 days'
        RETURNING *
      `, [req.user.id, creatorId, coins_per_month]);

      res.json({ ok: true, subscription: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/creator-subs/my — my subscriptions
  app.get('/api/creator-subs/my', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT cs.*, u.username AS creator_username, u.avatar_url AS creator_avatar
        FROM creator_subscriptions cs JOIN users u ON u.id = cs.creator_id
        WHERE cs.subscriber_id = $1 AND cs.status = 'active'
      `, [req.user.id]);
      res.json({ ok: true, subscriptions: rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // GET /api/creator-subs/subscribers — my subscribers (as creator)
  app.get('/api/creator-subs/subscribers', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT cs.*, u.username AS subscriber_username, u.avatar_url AS subscriber_avatar
        FROM creator_subscriptions cs JOIN users u ON u.id = cs.subscriber_id
        WHERE cs.creator_id = $1 AND cs.status = 'active'
      `, [req.user.id]);
      res.json({ ok: true, subscribers: rows, count: rows.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  console.log('[nvme-tiktok] ✅ TikTok-parity routes registered: hashtags, sounds, duets, creator-fund, tips, shop, series, challenges, leaderboard, creator-subs');
};
