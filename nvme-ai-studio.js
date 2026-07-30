// ============================================================
// NVME.LIVE — AI Studio Module (Kimi K3 via OpenRouter)
// Endpoints: captions, hashtags, scripts, comment replies,
//            feed ranking, status. Powers TikTok/Epic Studio UX.
// ============================================================
'use strict';

module.exports = function(app, db, authMiddleware, optionalAuth) {

  const AI_MODEL = process.env.AI_MODEL || 'moonshotai/kimi-k3';
  const OR_URL = 'https://openrouter.ai/api/v1/chat/completions';

  function aiKey() {
    return process.env.OPENROUTER_API_KEY || process.env.API_KEY_OPENROUTER || '';
  }

  async function kimi(messages, opts = {}) {
    const key = aiKey();
    if (!key) {
      const e = new Error('AI offline: set OPENROUTER_API_KEY');
      e.code = 'NO_KEY';
      throw e;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs || 60000);
    try {
      const r = await fetch(OR_URL, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${key}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://nvme.live',
          'X-Title': 'NVME.LIVE AI Studio'
        },
        body: JSON.stringify({
          model: AI_MODEL,
          messages,
          temperature: opts.temperature ?? 0.8,
          max_tokens: opts.maxTokens ?? 900
        }),
        signal: controller.signal
      });
      if (!r.ok) {
        const txt = await r.text().catch(() => '');
        throw new Error(`OpenRouter ${r.status}: ${txt.slice(0, 200)}`);
      }
      const data = await r.json();
      return (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content || '').trim();
    } finally {
      clearTimeout(timer);
    }
  }

  function parseJSONLoose(text, fallback) {
    try {
      const m = text.match(/[\[\{][\s\S]*[\]\}]/);
      return m ? JSON.parse(m[0]) : fallback;
    } catch (_) { return fallback; }
  }

  async function logGen(userId, kind, prompt, result) {
    try {
      await db.query(
        'INSERT INTO ai_generations (user_id, kind, prompt, result) VALUES ($1,$2,$3,$4)',
        [userId || null, kind, String(prompt).slice(0, 2000), String(result).slice(0, 4000)]
      );
    } catch (_) { /* logging must never break generation */ }
  }

  // ── INIT: usage log table ──────────────────────────────────
  (async () => {
    try {
      await db.query(`
        CREATE TABLE IF NOT EXISTS ai_generations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID,
          kind TEXT NOT NULL,
          prompt TEXT,
          result TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);
      await db.query('CREATE INDEX IF NOT EXISTS idx_ai_gen_user ON ai_generations(user_id, created_at DESC)');
      console.log('[AI-STUDIO] ready — model:', AI_MODEL);
    } catch (e) { console.error('[AI-STUDIO] init warn:', e.message); }
  })();

  // ── STATUS (public) ────────────────────────────────────────
  app.get('/api/ai/status', (req, res) => {
    res.json({ ok: !!aiKey(), model: AI_MODEL, studio: 'nvme-ai-studio v1', ts: new Date().toISOString() });
  });

  // ── CAPTIONS: 5 scroll-stopping variants + hashtags ───────
  app.post('/api/ai/captions', authMiddleware, async (req, res) => {
    try {
      const { title = '', description = '', niche = 'general', tone = 'bold' } = req.body || {};
      if (!title && !description) return res.status(400).json({ error: 'title or description required' });
      const out = await kimi([
        { role: 'system', content: 'You are a TikTok growth strategist. Return ONLY a JSON array of 5 objects: {"caption": string (<120 chars, may include emojis), "hashtags": string (4-6 space-separated #tags)}. No markdown, no commentary.' },
        { role: 'user', content: `Video title: ${title}\nDescription: ${description}\nNiche: ${niche}\nTone: ${tone}\nPlatform: NVME.LIVE (short-form vertical video, TikTok-style feed)` }
      ], { maxTokens: 700 });
      const captions = parseJSONLoose(out, null);
      if (!Array.isArray(captions)) return res.status(502).json({ error: 'AI returned unexpected format', raw: out.slice(0, 300) });
      await logGen(req.user.id, 'captions', `${title} | ${description}`, out);
      res.json({ captions: captions.slice(0, 5), model: AI_MODEL });
    } catch (e) {
      res.status(e.code === 'NO_KEY' ? 503 : 502).json({ error: e.message });
    }
  });

  // ── HASHTAG LAB: niche tag sets ranked by reach tier ──────
  app.post('/api/ai/hashtags', authMiddleware, async (req, res) => {
    try {
      const { topic = '', niche = 'general' } = req.body || {};
      if (!topic) return res.status(400).json({ error: 'topic required' });
      const out = await kimi([
        { role: 'system', content: 'You are a short-form video SEO expert. Return ONLY JSON: {"mega":["#tag"...3], "mid":["#tag"...5], "niche":["#tag"...5], "branded":["#tag"...2]}. mega=huge reach, mid=100k-1M, niche=targeted, branded=NVME-themed. No markdown.' },
        { role: 'user', content: `Topic: ${topic}\nNiche: ${niche}` }
      ], { maxTokens: 400 });
      const tags = parseJSONLoose(out, null);
      if (!tags) return res.status(502).json({ error: 'AI returned unexpected format' });
      await logGen(req.user.id, 'hashtags', topic, out);
      res.json({ ...tags, model: AI_MODEL });
    } catch (e) {
      res.status(e.code === 'NO_KEY' ? 503 : 502).json({ error: e.message });
    }
  });

  // ── SCRIPT STUDIO: viral short-form script (hook/beat/CTA) ─
  app.post('/api/ai/script', authMiddleware, async (req, res) => {
    try {
      const { topic = '', style = 'educational', duration = 30 } = req.body || {};
      if (!topic) return res.status(400).json({ error: 'topic required' });
      const out = await kimi([
        { role: 'system', content: 'You are an elite short-form scriptwriter. Return ONLY JSON: {"hook": string (first 3 seconds, spoken), "beats": [string] (3-5 visual/action beats), "cta": string, "caption": string, "hashtags": string}. Scripts must fit the requested duration. No markdown.' },
        { role: 'user', content: `Topic: ${topic}\nStyle: ${style}\nDuration: ${duration}s vertical video` }
      ], { maxTokens: 800, temperature: 0.9 });
      const script = parseJSONLoose(out, null);
      if (!script) return res.status(502).json({ error: 'AI returned unexpected format' });
      await logGen(req.user.id, 'script', `${topic} (${style}, ${duration}s)`, out);
      res.json({ ...script, model: AI_MODEL });
    } catch (e) {
      res.status(e.code === 'NO_KEY' ? 503 : 502).json({ error: e.message });
    }
  });

  // ── COMMENT REPLY: 3 on-brand reply suggestions ───────────
  app.post('/api/ai/comment-reply', authMiddleware, async (req, res) => {
    try {
      const { comment = '', videoTitle = '', tone = 'friendly' } = req.body || {};
      if (!comment) return res.status(400).json({ error: 'comment required' });
      const out = await kimi([
        { role: 'system', content: 'You are a creator-community manager. Return ONLY a JSON array of 3 short reply strings (<100 chars each), varied: one warm, one witty, one engagement-baiting question. No markdown.' },
        { role: 'user', content: `Comment: "${comment}"\nOn video: ${videoTitle}\nCreator tone: ${tone}` }
      ], { maxTokens: 300 });
      const replies = parseJSONLoose(out, null);
      if (!Array.isArray(replies)) return res.status(502).json({ error: 'AI returned unexpected format' });
      await logGen(req.user.id, 'comment-reply', comment, out);
      res.json({ replies: replies.slice(0, 3), model: AI_MODEL });
    } catch (e) {
      res.status(e.code === 'NO_KEY' ? 503 : 502).json({ error: e.message });
    }
  });

  // ── FEED RANK: engagement-weighted For-You ordering ───────
  // Pulls recent videos with live engagement signals and returns
  // ranked IDs. Falls back to recency if AI unavailable.
  app.get('/api/ai/feed-rank', optionalAuth, async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT v.id, v.title, v.caption,
               COALESCE(v.likes_count,0) likes, COALESCE(v.views_count,0) views,
               COALESCE(v.comments_count,0) comments,
               EXTRACT(EPOCH FROM (NOW() - v.created_at))/3600 age_hrs
        FROM videos v
        WHERE v.created_at > NOW() - INTERVAL '7 days'
        ORDER BY v.created_at DESC LIMIT 60
      `);
      if (rows.length < 3 || !aiKey()) {
        return res.json({ ranked: rows.map(r => r.id), source: 'recency', model: null });
      }
      const digest = rows.map((r, i) =>
        `${i}:${r.id}|likes${r.likes}|views${r.views}|comments${r.comments}|age${Math.round(r.age_hrs)}h|${(r.title || '').slice(0, 40)}`
      ).join('\n');
      const out = await kimi([
        { role: 'system', content: 'You are a For-You feed ranking engine. Rank for watch-time potential: favor engagement rate over raw views, penalize stale posts, diversify creators. Return ONLY a JSON array of the numeric indices in ranked order.' },
        { role: 'user', content: digest }
      ], { maxTokens: 300, temperature: 0.2 });
      const order = parseJSONLoose(out, null);
      if (!Array.isArray(order)) return res.json({ ranked: rows.map(r => r.id), source: 'recency-fallback', model: AI_MODEL });
      const ranked = order.filter(i => Number.isInteger(i) && rows[i]).map(i => rows[i].id);
      const missing = rows.map(r => r.id).filter(id => !ranked.includes(id));
      res.json({ ranked: [...ranked, ...missing], source: 'kimi-k3', model: AI_MODEL });
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // ── CREATOR ANALYTICS: usage stats for the AI Studio tab ──
  app.get('/api/ai/usage', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(
        `SELECT kind, COUNT(*)::int count, MAX(created_at) last_used
         FROM ai_generations WHERE user_id=$1 GROUP BY kind ORDER BY count DESC`,
        [req.user.id]
      );
      res.json({ usage: rows, model: AI_MODEL });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  console.log('[AI-STUDIO] routes mounted: /api/ai/{status,captions,hashtags,script,comment-reply,feed-rank,usage}');
};
