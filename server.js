'use strict';
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3090;

// ── DB ──────────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ── Middleware ───────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false }));

// ── Auth helper ──────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'kush-empire-jwt-secret-2026';
function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' }); }
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'invalid token' }); }
}

// ── DB Init ──────────────────────────────────────────────────
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      plan TEXT DEFAULT 'free',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS videos (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT,
      url TEXT NOT NULL,
      thumbnail TEXT,
      views INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS subscriptions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      plan TEXT NOT NULL,
      paypal_subscription_id TEXT,
      status TEXT DEFAULT 'active',
      starts_at TIMESTAMPTZ DEFAULT NOW(),
      ends_at TIMESTAMPTZ
    );
  `).catch(e => console.warn('DB init warning:', e.message));
}

// ── Routes: Health ───────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  app: 'nvme.live',
  status: 'ONLINE',
  version: '1.0.0',
  empire: 'Dollar Double Empire',
  founder: 'John B. Jefferis .Esq — Digital King AGI',
  ts: new Date().toISOString()
}));

// ── Routes: Auth ─────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password || !username) return res.status(400).json({ error: 'email, password, username required' });
    if (password.length < 8) return res.status(400).json({ error: 'password min 8 chars' });
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await db.query(
      'INSERT INTO users (email, password_hash, username) VALUES ($1,$2,$3) RETURNING id, email, username, plan, created_at',
      [email.toLowerCase().trim(), hash, username.trim()]
    );
    const user = rows[0];
    res.status(201).json({ ok: true, token: signToken({ id: user.id, email: user.email }), user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'email or username already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const { rows } = await db.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (!rows.length) return res.status(401).json({ error: 'invalid credentials' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    res.json({ ok: true, token: signToken({ id: user.id, email: user.email }), user: { id: user.id, email: user.email, username: user.username, plan: user.plan } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT id, email, username, plan, created_at FROM users WHERE id=$1', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'user not found' });
    res.json({ ok: true, user: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Routes: Videos ───────────────────────────────────────────
app.get('/api/videos', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT v.*, u.username FROM videos v JOIN users u ON u.id=v.user_id ORDER BY v.created_at DESC LIMIT 50');
    res.json({ ok: true, videos: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos', authMiddleware, async (req, res) => {
  try {
    const { title, description, url, thumbnail } = req.body;
    if (!title || !url) return res.status(400).json({ error: 'title and url required' });
    const { rows } = await db.query(
      'INSERT INTO videos (user_id, title, description, url, thumbnail) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, title, description || '', url, thumbnail || '']
    );
    res.status(201).json({ ok: true, video: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/like', authMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query('UPDATE videos SET likes=likes+1 WHERE id=$1 RETURNING id, likes', [req.params.id]);
    res.json({ ok: true, likes: rows[0]?.likes });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Routes: Payments (PayPal ONLY) ──────────────────────────
app.post('/api/subscribe', authMiddleware, async (req, res) => {
  try {
    const { plan, paypal_subscription_id } = req.body;
    const plans = { pro: 9.99, creator: 24.99, enterprise: 99.99 };
    if (!plans[plan]) return res.status(400).json({ error: 'invalid plan' });
    await db.query('UPDATE users SET plan=$1 WHERE id=$2', [plan, req.user.id]);
    await db.query(
      'INSERT INTO subscriptions (user_id, plan, paypal_subscription_id) VALUES ($1,$2,$3)',
      [req.user.id, plan, paypal_subscription_id || 'manual']
    );
    res.json({ ok: true, plan, message: 'subscription activated' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/donate', (req, res) => {
  res.redirect(process.env.PAYPAL_DONATE_LINK || 'https://paypal.me/DollarDoubleEmpire');
});

// ── Frontend: Landing Page ───────────────────────────────────
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>nvme.live — The Future of Short Video Entertainment</title>
<style>
  :root{--bg:#0a0a0f;--card:#13131a;--border:#1e1e2e;--accent:#7c3aed;--accent2:#06b6d4;--text:#f8fafc;--muted:#64748b}
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;min-height:100vh}
  nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 2rem;border-bottom:1px solid var(--border);position:sticky;top:0;background:rgba(10,10,15,0.95);backdrop-filter:blur(12px);z-index:100}
  .logo{font-size:1.5rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .nav-links{display:flex;gap:1.5rem;align-items:center}
  .nav-links a{color:var(--muted);text-decoration:none;transition:color .2s}  
  .nav-links a:hover{color:var(--text)}
  .btn{padding:.6rem 1.4rem;border-radius:8px;border:none;cursor:pointer;font-weight:600;transition:all .2s;text-decoration:none;display:inline-block}
  .btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff}
  .btn-primary:hover{opacity:.9;transform:translateY(-1px)}
  .btn-outline{border:1px solid var(--accent);color:var(--accent);background:transparent}
  .btn-outline:hover{background:var(--accent);color:#fff}
  .hero{text-align:center;padding:6rem 2rem 4rem;max-width:800px;margin:0 auto}
  .hero h1{font-size:clamp(2.5rem,6vw,4.5rem);font-weight:900;line-height:1.1;margin-bottom:1.5rem}
  .hero h1 span{background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .hero p{font-size:1.2rem;color:var(--muted);margin-bottom:2.5rem;max-width:600px;margin-left:auto;margin-right:auto}
  .hero-cta{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1.5rem;padding:3rem 2rem;max-width:900px;margin:0 auto}
  .stat{text-align:center;padding:1.5rem;background:var(--card);border-radius:16px;border:1px solid var(--border)}
  .stat-num{font-size:2.5rem;font-weight:900;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .stat-label{color:var(--muted);font-size:.9rem;margin-top:.25rem}
  .features{padding:4rem 2rem;max-width:1100px;margin:0 auto}
  .features h2{text-align:center;font-size:2.5rem;font-weight:800;margin-bottom:3rem}
  .features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.5rem}
  .feature-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;transition:border-color .2s}
  .feature-card:hover{border-color:var(--accent)}
  .feature-icon{font-size:2.5rem;margin-bottom:1rem}
  .feature-card h3{font-size:1.2rem;font-weight:700;margin-bottom:.75rem}
  .feature-card p{color:var(--muted);line-height:1.6}
  .pricing{padding:4rem 2rem;background:linear-gradient(180deg,var(--bg),var(--card));}
  .pricing h2{text-align:center;font-size:2.5rem;font-weight:800;margin-bottom:.75rem}
  .pricing-subtitle{text-align:center;color:var(--muted);margin-bottom:3rem}
  .pricing-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1.5rem;max-width:900px;margin:0 auto}
  .plan{background:var(--bg);border:1px solid var(--border);border-radius:16px;padding:2rem}
  .plan.featured{border-color:var(--accent);position:relative}
  .plan.featured::before{content:'POPULAR';position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;padding:.25rem .75rem;border-radius:99px;font-size:.75rem;font-weight:700}
  .plan-name{font-size:1.1rem;font-weight:700;margin-bottom:.5rem}
  .plan-price{font-size:3rem;font-weight:900;margin:.75rem 0}
  .plan-price span{font-size:1rem;color:var(--muted);font-weight:400}
  .plan ul{list-style:none;margin:1.5rem 0;display:flex;flex-direction:column;gap:.75rem}
  .plan ul li{color:var(--muted);display:flex;align-items:center;gap:.5rem}
  .plan ul li::before{content:'✓';color:var(--accent);font-weight:700}
  .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;align-items:center;justify-content:center}
  .modal-overlay.active{display:flex}
  .modal{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:2.5rem;width:100%;max-width:440px;position:relative}
  .modal h2{font-size:1.5rem;font-weight:800;margin-bottom:.5rem}
  .modal p{color:var(--muted);margin-bottom:1.5rem;font-size:.9rem}
  .form-group{margin-bottom:1rem}
  .form-group label{display:block;color:var(--muted);font-size:.85rem;margin-bottom:.4rem;font-weight:500}
  .form-group input{width:100%;padding:.75rem 1rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:1rem;outline:none;transition:border-color .2s}
  .form-group input:focus{border-color:var(--accent)}
  .modal-close{position:absolute;top:1rem;right:1rem;background:none;border:none;color:var(--muted);font-size:1.5rem;cursor:pointer}
  .tab-btns{display:flex;gap:.5rem;margin-bottom:1.5rem;background:var(--bg);padding:.35rem;border-radius:8px}
  .tab-btn{flex:1;padding:.5rem;border:none;border-radius:6px;cursor:pointer;font-weight:600;font-size:.9rem;background:none;color:var(--muted);transition:all .2s}
  .tab-btn.active{background:var(--accent);color:#fff}
  .msg{padding:.75rem 1rem;border-radius:8px;margin-bottom:1rem;font-size:.9rem;display:none}
  .msg.error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#f87171;display:block}
  .msg.success{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#4ade80;display:block}
  footer{text-align:center;padding:3rem 2rem;color:var(--muted);border-top:1px solid var(--border)}
  footer a{color:var(--muted);text-decoration:none}
  footer a:hover{color:var(--text)}
  @media(max-width:640px){.hero{padding:4rem 1.5rem 3rem}.hero-cta{flex-direction:column;align-items:center}nav{padding:1rem}}
</style>
</head>
<body>
<nav>
  <div class="logo">nvme.live</div>
  <div class="nav-links">
    <a href="#features">Features</a>
    <a href="#pricing">Pricing</a>
    <a class="btn btn-outline" href="#" onclick="openModal('login')">Log In</a>
    <a class="btn btn-primary" href="#" onclick="openModal('register')">Get Started</a>
  </div>
</nav>

<section class="hero">
  <h1>The Future of<br><span>Short Video</span><br>Entertainment</h1>
  <p>AI-powered creator platform. Upload, share, and monetize your short videos. Built for the next generation of content creators.</p>
  <div class="hero-cta">
    <a class="btn btn-primary" href="#" onclick="openModal('register')" style="font-size:1.1rem;padding:.85rem 2.5rem">Start Creating Free</a>
    <a class="btn btn-outline" href="#features" style="font-size:1.1rem;padding:.85rem 2.5rem">See Features</a>
  </div>
</section>

<div class="stats">
  <div class="stat"><div class="stat-num">57</div><div class="stat-label">AI Agents Working</div></div>
  <div class="stat"><div class="stat-num">4K</div><div class="stat-label">Max Resolution</div></div>
  <div class="stat"><div class="stat-num">99.9%</div><div class="stat-label">Uptime SLA</div></div>
  <div class="stat"><div class="stat-num">$0</div><div class="stat-label">to Start</div></div>
</div>

<section class="features" id="features">
  <h2>Everything You Need to Create</h2>
  <div class="features-grid">
    <div class="feature-card">
      <div class="feature-icon">🎬</div>
      <h3>AI Video Enhancement</h3>
      <p>Automatic captions, smart trimming, and AI-powered quality enhancement on every upload.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">💰</div>
      <h3>Creator Monetization</h3>
      <p>Earn from views, tips, and subscriptions. PayPal payouts weekly, no minimum threshold.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🌍</div>
      <h3>Global Distribution</h3>
      <p>CDN-powered delivery to 190+ countries. Your content loads fast everywhere, always.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🔒</div>
      <h3>Privacy Controls</h3>
      <p>Public, private, or subscriber-only content. You control who sees what, always.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📊</div>
      <h3>Real-Time Analytics</h3>
      <p>Live view counts, engagement metrics, and revenue dashboard updated every 30 seconds.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🤖</div>
      <h3>AI Empire Powered</h3>
      <p>57 specialized AI agents working 24/7 to optimize your content reach and monetization.</p>
    </div>
  </div>
</section>

<section class="pricing" id="pricing">
  <h2>Simple Pricing</h2>
  <p class="pricing-subtitle">Start free. Upgrade when you're ready.</p>
  <div class="pricing-grid">
    <div class="plan">
      <div class="plan-name">Free</div>
      <div class="plan-price">$0<span>/mo</span></div>
      <ul>
        <li>5 videos/month</li>
        <li>720p max resolution</li>
        <li>Basic analytics</li>
        <li>Community support</li>
      </ul>
      <a class="btn btn-outline" style="width:100%;text-align:center" href="#" onclick="openModal('register')">Get Started</a>
    </div>
    <div class="plan featured">
      <div class="plan-name">Pro Creator</div>
      <div class="plan-price">$9.99<span>/mo</span></div>
      <ul>
        <li>Unlimited videos</li>
        <li>4K resolution</li>
        <li>Advanced analytics</li>
        <li>Monetization enabled</li>
        <li>Priority AI processing</li>
      </ul>
      <a class="btn btn-primary" style="width:100%;text-align:center" href="#" onclick="openModal('register')">Start Pro</a>
    </div>
    <div class="plan">
      <div class="plan-name">Creator+</div>
      <div class="plan-price">$24.99<span>/mo</span></div>
      <ul>
        <li>Everything in Pro</li>
        <li>Custom branding</li>
        <li>API access</li>
        <li>Dedicated AI agent</li>
        <li>White-label option</li>
      </ul>
      <a class="btn btn-outline" style="width:100%;text-align:center" href="#" onclick="openModal('register')">Start Creator+</a>
    </div>
  </div>
</section>

<footer>
  <p style="margin-bottom:.75rem"><strong>nvme.live</strong> &mdash; Dollar Double Empire | Founder: John B. Jefferis .Esq</p>
  <p><a href="/health">System Status</a> &bull; <a href="/donate">Support Us</a> &bull; &copy; 2026 nvme.live</p>
</footer>

<!-- Auth Modal -->
<div class="modal-overlay" id="authModal" onclick="closeModalOutside(event)">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()">&times;</button>
    <div class="tab-btns">
      <button class="tab-btn active" id="tabLogin" onclick="switchTab('login')">Log In</button>
      <button class="tab-btn" id="tabRegister" onclick="switchTab('register')">Sign Up</button>
    </div>
    <div id="msgBox" class="msg"></div>
    <div id="loginForm">
      <h2>Welcome back</h2>
      <p>Sign in to your nvme.live account</p>
      <div class="form-group"><label>Email</label><input type="email" id="loginEmail" placeholder="you@email.com"></div>
      <div class="form-group"><label>Password</label><input type="password" id="loginPass" placeholder="Password"></div>
      <button class="btn btn-primary" style="width:100%;margin-top:.5rem" onclick="doLogin()">Log In</button>
    </div>
    <div id="registerForm" style="display:none">
      <h2>Join nvme.live</h2>
      <p>Create your free creator account</p>
      <div class="form-group"><label>Username</label><input type="text" id="regUsername" placeholder="yourcreatorname"></div>
      <div class="form-group"><label>Email</label><input type="email" id="regEmail" placeholder="you@email.com"></div>
      <div class="form-group"><label>Password</label><input type="password" id="regPass" placeholder="Min 8 characters"></div>
      <button class="btn btn-primary" style="width:100%;margin-top:.5rem" onclick="doRegister()">Create Account</button>
    </div>
  </div>
</div>

<script>
const API = '';
function openModal(tab) { document.getElementById('authModal').classList.add('active'); switchTab(tab); }
function closeModal() { document.getElementById('authModal').classList.remove('active'); }
function closeModalOutside(e) { if (e.target.id === 'authModal') closeModal(); }
function switchTab(tab) {
  document.getElementById('loginForm').style.display = tab === 'login' ? 'block' : 'none';
  document.getElementById('registerForm').style.display = tab === 'register' ? 'block' : 'none';
  document.getElementById('tabLogin').classList.toggle('active', tab === 'login');
  document.getElementById('tabRegister').classList.toggle('active', tab === 'register');
  document.getElementById('msgBox').className = 'msg';
}
function showMsg(msg, type) {
  const el = document.getElementById('msgBox');
  el.textContent = msg; el.className = 'msg ' + type;
}
async function doLogin() {
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPass').value;
  try {
    const r = await fetch(API + '/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email, password}) });
    const d = await r.json();
    if (!r.ok) return showMsg(d.error || 'Login failed', 'error');
    localStorage.setItem('nvme_token', d.token);
    showMsg('Welcome back, ' + d.user.username + '! Redirecting...', 'success');
    setTimeout(() => closeModal(), 1500);
  } catch(e) { showMsg('Network error. Try again.', 'error'); }
}
async function doRegister() {
  const username = document.getElementById('regUsername').value;
  const email = document.getElementById('regEmail').value;
  const password = document.getElementById('regPass').value;
  try {
    const r = await fetch(API + '/api/auth/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username, email, password}) });
    const d = await r.json();
    if (!r.ok) return showMsg(d.error || 'Registration failed', 'error');
    localStorage.setItem('nvme_token', d.token);
    showMsg('Account created! Welcome to nvme.live!', 'success');
    setTimeout(() => closeModal(), 1500);
  } catch(e) { showMsg('Network error. Try again.', 'error'); }
}
</script>
</body>
</html>`);
});

// ── Start ─────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[nvme.live] ONLINE :${PORT} | Empire: Dollar Double Empire`);
  });
}).catch(e => {
  console.error('[nvme.live] DB init failed:', e.message);
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[nvme.live] ONLINE :${PORT} (no DB — check DATABASE_URL)`);
  });
});
