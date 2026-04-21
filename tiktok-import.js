// ============================================================
// NVME TikTok Import Module
// Pull contacts (following/followers) and badges from TikTok
// via TikTok Login Kit + Display API
// ============================================================
//
// Docs: https://developers.tiktok.com/doc/login-kit-web
// Docs: https://developers.tiktok.com/doc/display-api-overview
//
// Scopes §§secret(POSTGRESQL://NEONDB_OWNER:NPG_NX6JVZR2QMYG@EP-FALLING-PAPER-A62FLHPD.US-WEST-2.AWS.NEON.TECH/NEONDB?SSLMODE)d (add these in TikTok Developer Portal):
//   - user.info.basic   -> username, avatar, display_name, bio
//   - user.info.profile -> follower_count, following_count, likes_count, video_count, is_verified
//   - user.info.stats   -> expanded stats
//   - video.list        -> user's own video list
//   - (Note) TikTok does NOT expose follower usernames for privacy.
//     What we can pull: counts + user's own videos. For "contacts"
//     we return the lists the API allows + offer an invite link.
//
// ENV:
//   TIKTOK_CLIENT_KEY
//   TIKTOK_CLIENT_SECRET
//   TIKTOK_REDIRECT_URI  (e.g. https://nvme.live/api/tiktok/callback)

const crypto = require('crypto');
const https = require('https');

const CLIENT_KEY    = process.env.TIKTOK_CLIENT_KEY     || '';
const CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET  || '';
const REDIRECT_URI  = process.env.TIKTOK_REDIRECT_URI   || 'https://nvme.live/api/tiktok/callback';
const SCOPES = ['user.info.basic','user.info.profile','user.info.stats','video.list'].join(',');

const tokenStore = new Map(); // userId -> { access_token, refresh_token, open_id, expires_at }
const stateStore = new Map(); // state -> { userId, created }

function postForm(host, path, body) {
  return new Promise((resolve, reject) => {
    const data = typeof body === 'string' ? body : new URLSearchParams(body).toString();
    const req = https.request({
      host, path, method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let chunks = '';
      res.on('data', c => chunks += c);
      res.on('end', () => { try { resolve(JSON.parse(chunks)); } catch(e){ resolve({ raw: chunks }); } });
    });
    req.on('error', reject);
    req.write(data); req.end();
  });
}

function postJSON(host, path, token, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body || {});
    const req = https.request({
      host, path, method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token,
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let chunks = '';
      res.on('data', c => chunks += c);
      res.on('end', () => { try { resolve(JSON.parse(chunks)); } catch(e){ resolve({ raw: chunks }); } });
    });
    req.on('error', reject);
    req.write(data); req.end();
  });
}

function buildAuthUrl(userId) {
  const state = crypto.randomBytes(16).toString('hex');
  stateStore.set(state, { userId, created: Date.now() });
  const params = new URLSearchParams({
    client_key: CLIENT_KEY,
    scope: SCOPES,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    state
  });
  return 'https://www.tiktok.com/v2/auth/authorize/?' + params.toString();
}

async function exchangeCode(code) {
  return postForm('open.tiktokapis.com', '/v2/oauth/token/', {
    client_key: CLIENT_KEY,
    client_secret: CLIENT_SECRET,
    code,
    grant_type: 'authorization_code',
    redirect_uri: REDIRECT_URI
  });
}

async function refreshToken(refresh) {
  return postForm('open.tiktokapis.com', '/v2/oauth/token/', {
    client_key: CLIENT_KEY,
    client_secret: CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: refresh
  });
}

async function fetchUserInfo(token) {
  // TikTok Display API: /v2/user/info/
  return postJSON('open.tiktokapis.com',
    '/v2/user/info/?fields=open_id,union_id,avatar_url,display_name,bio_description,is_verified,follower_count,following_count,likes_count,video_count,username',
    token, {});
}

async function fetchVideoList(token, cursor = 0, max = 20) {
  return postJSON('open.tiktokapis.com',
    '/v2/video/list/?fields=id,title,cover_image_url,video_description,duration,view_count,like_count,comment_count,share_count,create_time',
    token, { cursor, max_count: max });
}

function setupRoutes(app) {
  // Config status
  app.get('/api/tiktok/config', (req, res) => {
    res.json({
      configured: !!(CLIENT_KEY && CLIENT_SECRET),
      scopes: SCOPES.split(','),
      redirectUri: REDIRECT_URI,
      docs: 'https://developers.tiktok.com/doc/login-kit-web'
    });
  });

  // Start OAuth -> returns the TikTok authorize URL for the user to visit
  app.get('/api/tiktok/connect', (req, res) => {
    if (!CLIENT_KEY) return res.status(503).json({ error: 'TIKTOK_CLIENT_KEY not set' });
    const userId = req.query.userId || 'anon_' + crypto.randomBytes(4).toString('hex');
    const url = buildAuthUrl(userId);
    res.json({ userId, authorizeUrl: url });
  });

  // OAuth callback: TikTok redirects here with ?code=...&state=...
  app.get('/api/tiktok/callback', async (req, res) => {
    const { code, state, error } = req.query;
    if (error) return res.status(400).json({ error, description: req.query.error_description });
    if (!code || !state) return res.status(400).json({ error: 'missing_code_or_state' });
    const stateData = stateStore.get(state);
    if (!stateData) return res.status(400).json({ error: 'invalid_state' });
    stateStore.delete(state);

    try {
      const tok = await exchangeCode(code);
      if (tok.error) return res.status(400).json({ error: tok.error, details: tok });
      const expires_at = Date.now() + ((tok.expires_in || 86400) * 1000);
      tokenStore.set(stateData.userId, {
        access_token: tok.access_token,
        refresh_token: tok.refresh_token,
        open_id: tok.open_id,
        expires_at
      });
      res.send('<html><body style="background:#07070f;color:#fff;font-family:sans-serif;text-align:center;padding:80px;"><h1>TikTok connected</h1><p>You can close this tab.</p></body></html>');
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Get the authenticated user's TikTok profile (badges, follower/following counts, verified flag)
  app.get('/api/tiktok/user/:userId', async (req, res) => {
    const t = tokenStore.get(req.params.userId);
    if (!t) return res.status(404).json({ error: 'not_connected' });
    try {
      const info = await fetchUserInfo(t.access_token);
      const u = info?.data?.user || {};
      res.json({
        open_id: u.open_id,
        username: u.username,
        display_name: u.display_name,
        avatar_url: u.avatar_url,
        bio: u.bio_description,
        badges: {
          verified: !!u.is_verified,
          creator: (u.follower_count || 0) >= 1000,
          topCreator: (u.follower_count || 0) >= 100000,
          megaCreator: (u.follower_count || 0) >= 1000000
        },
        contacts: {
          followerCount: u.follower_count || 0,
          followingCount: u.following_count || 0,
          likesCount: u.likes_count || 0,
          videoCount: u.video_count || 0,
          note: 'TikTok does not expose follower/following lists via API for privacy. We expose counts + let users invite contacts via share link.'
        },
        inviteUrl: 'https://nvme.live/invite?from=' + encodeURIComponent(u.username || u.open_id)
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Pull the user's own videos (useful to import content to NVME)
  app.get('/api/tiktok/videos/:userId', async (req, res) => {
    const t = tokenStore.get(req.params.userId);
    if (!t) return res.status(404).json({ error: 'not_connected' });
    try {
      const list = await fetchVideoList(t.access_token, parseInt(req.query.cursor) || 0, parseInt(req.query.max) || 20);
      res.json(list);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Badge derivation (can be called without tokens; give it a follower count)
  app.get('/api/tiktok/badges/derive', (req, res) => {
    const followers = parseInt(req.query.followers || 0);
    const verified  = req.query.verified === 'true';
    res.json({
      badges: {
        verified,
        creator:      followers >= 1000,
        topCreator:   followers >= 100000,
        megaCreator:  followers >= 1000000,
        eliteCreator: followers >= 10000000
      }
    });
  });

  // Refresh a user's TikTok token (call before it expires)
  app.post('/api/tiktok/refresh/:userId', async (req, res) => {
    const t = tokenStore.get(req.params.userId);
    if (!t) return res.status(404).json({ error: 'not_connected' });
    try {
      const r = await refreshToken(t.refresh_token);
      if (r.error) return res.status(400).json(r);
      tokenStore.set(req.params.userId, {
        access_token: r.access_token,
        refresh_token: r.refresh_token || t.refresh_token,
        open_id: t.open_id,
        expires_at: Date.now() + ((r.expires_in || 86400) * 1000)
      });
      res.json({ refreshed: true, expiresAt: new Date(Date.now() + ((r.expires_in || 86400) * 1000)).toISOString() });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

module.exports = { setupRoutes, buildAuthUrl, exchangeCode, fetchUserInfo, fetchVideoList };
