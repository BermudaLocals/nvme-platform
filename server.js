require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'NVME.live', version: '2.0', timestamp: new Date() });
});

app.get('/api/test', (req, res) => {
  res.json({ message: 'NVME Mothership Online', timestamp: new Date() });
});

app.post('/api/auth/register', (req, res) => {
  const { email, password, display_name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const token = crypto.randomBytes(32).toString('hex');
  res.json({ success: true, token, user: { email, display_name: display_name || email.split('@')[0], plan: 'free' } });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const token = crypto.randomBytes(32).toString('hex');
  res.json({ success: true, token, user: { email, plan: 'free' } });
});

app.post('/api/auth/magic-link', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  res.json({ success: true, message: 'Magic link sent — check your inbox' });
});

app.get('/api/auth/me', (req, res) => {
  res.json({ user: { email: 'user@example.com', plan: 'free' } });
});

app.post('/api/auth/logout', (req, res) => res.json({ success: true }));

app.post('/api/ai/chat', (req, res) => {
  res.json({ reply: "Hi! I'm Zara, your NVME guide. How can I help you earn today?" });
});

app.get('/api/payments/providers', (req, res) => {
  res.json({ providers: ['paypal', 'ton', 'momo', 'payeer'], active: 4 });
});

app.post('/api/payments/checkout', (req, res) => {
  res.json({ plan: req.body.plan, status: 'initiated' });
});

app.post('/api/game/crown-anchor/roll', (req, res) => {
  const { bets = [] } = req.body;
  const symbols = ['crown', 'anchor', 'heart', 'diamond', 'club', 'spade'];
  const roll = [0,1,2].map(() => symbols[Math.floor(Math.random() * 6)]);
  const results = bets.map(b => ({ ...b, matches: roll.filter(s => s === b.symbol).length, payout: b.amount * roll.filter(s => s === b.symbol).length }));
  res.json({ roll, results, total_payout: results.reduce((a, b) => a + b.payout, 0) });
});

app.get('/api/feed', (req, res) => res.json({ items: [], total: 0 }));
app.get('/api/jobs', (req, res) => res.json({ jobs: [], total: 0 }));

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('⚓ NVME.live v2.0 running on port ' + PORT);
});
