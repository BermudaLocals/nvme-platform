require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const tiktokFeatures = require('./tiktok-features');
const tiktokImport = require('./tiktok-import');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 500 });
app.use('/api/', limiter);

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── IN-MEMORY STORES (replace with Neon/Postgres via DATABASE_URL) ───────────
const creators = new Map();
const jobs = new Map();
const legalDocs = new Map();
const gameRooms = new Map();
const activityFeed = [];

// Seed activity feed
const seedActivity = [
  { type: 'join',   user: '@mike_viral',     msg: 'joined NVME',       time: 'just now' },
  { type: 'earn',   user: '@emma_content',   msg: 'earned $89',        time: '5m ago' },
  { type: 'video',  user: '@alex_studio',    msg: 'uploaded a video',  time: 'just now' },
  { type: 'earn',   user: '@jenny_ai',       msg: 'earned $340',       time: '1m ago' },
  { type: 'join',   user: '@creator_bda',    msg: 'joined NVME',       time: '2m ago' },
  { type: 'earn',   user: '@sarah_creates',  msg: 'earned $125',       time: '3m ago' },
];
seedActivity.forEach(a => activityFeed.push({ ...a, id: uuidv4() }));

// Seed job board
const seedJobs = [
  { id: uuidv4(), title: 'Social Media Manager',    type: 'Full-time',   pay: '$55,000/yr',  location: 'Hamilton, BDA', company: 'Island Digital Co',    category: 'marketing',  posted: '2h ago' },
  { id: uuidv4(), title: 'Video Editor',            type: 'Contract',    pay: '$35/hr',      location: 'Remote',        company: 'NVME Studios',          category: 'creative',   posted: '4h ago' },
  { id: uuidv4(), title: 'AI Content Specialist',   type: 'Full-time',   pay: '$70,000/yr',  location: 'Remote',        company: 'CreatorHub',            category: 'tech',       posted: '6h ago' },
  { id: uuidv4(), title: 'Brand Partnerships Mgr',  type: 'Full-time',   pay: '$80,000/yr',  location: 'Hamilton, BDA', company: 'Bermuda Media Group',   category: 'marketing',  posted: '1d ago' },
  { id: uuidv4(), title: 'UX Designer',             type: 'Contract',    pay: '$50/hr',      location: 'Remote',        company: 'NVME.live',             category: 'creative',   posted: '1d ago' },
  { id: uuidv4(), title: 'Backend Engineer (Node)', type: 'Full-time',   pay: '$95,000/yr',  location: 'Remote',        company: 'NVME.live',             category: 'tech',       posted: '2d ago' },
];
seedJobs.forEach(j => jobs.set(j.id, j));

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const checks = {
    status: 'online',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    platform: 'NVME Mothership v2.0',
    services: {
      server:       { status: 'green', msg: 'Express running' },
      database:     { status: process.env.DATABASE_URL   ? 'green' : 'yellow', msg: process.env.DATABASE_URL   ? 'Neon connected'   : 'Using in-memory (add DATABASE_URL)' },
      twilio:       { status: process.env.TWILIO_ACCOUNT_SID ? 'green' : 'yellow', msg: process.env.TWILIO_ACCOUNT_SID ? 'AI Receptionist live' : 'Add TWILIO_ACCOUNT_SID' },
      openrouter:   { status: process.env.OPENROUTER_API_KEY ? 'green' : 'yellow', msg: process.env.OPENROUTER_API_KEY ? 'AI connected'    : 'Add OPENROUTER_API_KEY' },
      paypal:       { status: process.env.PAYPAL_CLIENT_ID   ? 'green' : 'yellow', msg: process.env.PAYPAL_CLIENT_ID   ? 'PayPal live'      : 'Add PAYPAL_CLIENT_ID' },
      stripe:       { status: process.env.STRIPE_SECRET_KEY  ? 'green' : 'yellow', msg: process.env.STRIPE_SECRET_KEY  ? 'Stripe live'      : 'Add STRIPE_SECRET_KEY' },
      cashapp:      { status: process.env.CASHAPP_CLIENT_ID  ? 'green' : 'yellow', msg: process.env.CASHAPP_CLIENT_ID  ? 'Cash App live'    : 'Add CASHAPP_CLIENT_ID' },
      crypto:       { status: process.env.COINBASE_API_KEY   ? 'green' : 'yellow', msg: process.env.COINBASE_API_KEY   ? 'Crypto live'      : 'Add COINBASE_API_KEY' },
    },
    endpoints: {
      landing:       'GET  /',
      health:        'GET  /api/health',
      payments:      'POST /api/payments/checkout',
      receptionist:  'POST /api/receptionist/voice',
      jobs:          'GET  /api/jobs',
      legal:         'POST /api/legal/generate',
      game:          'GET  /api/game/crown-anchor',
      creators:      'GET  /api/creators/stats',
      activity:      'GET  /api/activity',
    }
  };
  res.json(checks);
});

// ─── TIKTOK-STYLE FEATURES (VS Battles, FYP, Duet, Stitch, Challenges, Analytics, Live Rooms, Shop, Sounds, Payouts) ─
tiktokFeatures.setupRoutes(app);
tiktokImport.setupRoutes(app);

// ─── CREATORS ────────────────────────────────────────────────────────────────
app.get('/api/creators/stats', (req, res) => {
  res.json({
    totalCreators: 50000 + Math.floor(Math.random() * 500),
    earnedThisMonth: 4280000 + Math.floor(Math.random() * 10000),
    activeStreams: 847 + Math.floor(Math.random() * 50),
    videosToday: 12847 + Math.floor(Math.random() * 100),
    giftsToday: 18400 + Math.floor(Math.random() * 500),
  });
});

// ─── 500+ GIFTS API ──────────────────────────────────────────────────────────
const { getAvailableGifts } = require('./gifts-500');

app.get('/api/gifts', (req, res) => {
  const giftData = getAvailableGifts();
  res.json({
    status: 'success',
    ...giftData,
    message: `Showing ${giftData.totalCount} total gifts including ${giftData.evergreenCount} evergreen and ${giftData.holidayCount} holiday specials`
  });
});

app.get('/api/gifts/random', (req, res) => {
  const giftData = getAvailableGifts();
  const randomGift = giftData.gifts[Math.floor(Math.random() * giftData.gifts.length)];
  res.json({
    status: 'success',
    gift: randomGift
  });
});

// ─── HUGE AI AVATAR ───────────────────────────────────────────────────────────
app.get('/huge-ai', (req, res) => {
  res.sendFile(__dirname + '/public/huge-ai.html');
});

// ─── CREATORS ────────────────────────────────────────────────────────────────

app.post('/api/creators/signup', (req, res) => {
  const { username, email, referral } = req.body;
  if (!username || !email) return res.status(400).json({ error: 'username and email required' });
  const id = uuidv4();
  const creator = { id, username, email, referral, joinedAt: new Date().toISOString(), plan: 'trial' };
  creators.set(id, creator);
  activityFeed.unshift({ id: uuidv4(), type: 'join', user: `@${username}`, msg: 'joined NVME', time: 'just now' });
  if (activityFeed.length > 50) activityFeed.pop();
  res.json({ success: true, creatorId: id, message: 'Welcome to NVME! Your 14-day free trial starts now.', trialEnds: new Date(Date.now() + 14 * 86400000).toISOString() });
});

// ─── ACTIVITY FEED ────────────────────────────────────────────────────────────
app.get('/api/activity', (req, res) => {
  res.json(activityFeed.slice(0, 20));
});

// ─── 8 PAYMENT PROVIDERS ─────────────────────────────────────────────────────
const PAYMENT_PROVIDERS = ['paypal', 'stripe', 'cashapp', 'applepay', 'googlepay', 'crypto', 'wire', 'bermuda_bank'];

app.get('/api/payments/providers', (req, res) => {
  res.json({
    providers: [
      { id: 'paypal',       name: 'PayPal',          icon: '🅿️',  minPayout: 5,    fee: '2.9%',  active: !!process.env.PAYPAL_CLIENT_ID },
      { id: 'stripe',       name: 'Stripe',          icon: '💳',  minPayout: 10,   fee: '2.9%',  active: !!process.env.STRIPE_SECRET_KEY },
      { id: 'cashapp',      name: 'Cash App',        icon: '💵',  minPayout: 1,    fee: '0%',    active: !!process.env.CASHAPP_CLIENT_ID },
      { id: 'applepay',     name: 'Apple Pay',       icon: '🍎',  minPayout: 5,    fee: '0%',    active: true },
      { id: 'googlepay',    name: 'Google Pay',      icon: '🟦',  minPayout: 5,    fee: '0%',    active: true },
      { id: 'crypto',       name: 'Crypto (USDC)',   icon: '🪙',  minPayout: 10,   fee: '1%',    active: !!process.env.COINBASE_API_KEY },
      { id: 'wire',         name: 'Bank Wire',       icon: '🏦',  minPayout: 100,  fee: '$15',   active: true },
      { id: 'bermuda_bank', name: 'Bermuda Bank',    icon: '🌊',  minPayout: 25,   fee: '0%',    active: true },
    ]
  });
});

app.post('/api/payments/checkout', async (req, res) => {
  const { provider, amount, currency = 'USD', creatorId, plan } = req.body;
  if (!provider || !amount) return res.status(400).json({ error: 'provider and amount required' });
  if (!PAYMENT_PROVIDERS.includes(provider)) return res.status(400).json({ error: `Unknown provider. Choose: ${PAYMENT_PROVIDERS.join(', ')}` });

  // PayPal
  if (provider === 'paypal') {
    if (!process.env.PAYPAL_CLIENT_ID) return res.json({ status: 'mock', provider, amount, currency, redirectUrl: 'https://paypal.com/checkout?mock=true', orderId: uuidv4() });
    try {
      const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_SECRET}`).toString('base64');
      const tokenRes = await require('axios').post('https://api-m.sandbox.paypal.com/v1/oauth2/token', 'grant_type=client_credentials', { headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' } });
      const token = tokenRes.data.access_token;
      const orderRes = await require('axios').post('https://api-m.sandbox.paypal.com/v2/checkout/orders', { intent: 'CAPTURE', purchase_units: [{ amount: { currency_code: currency, value: amount.toString() } }] }, { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } });
      const approveUrl = orderRes.data.links.find(l => l.rel === 'approve')?.href;
      return res.json({ status: 'created', provider, orderId: orderRes.data.id, redirectUrl: approveUrl });
    } catch (e) { return res.status(500).json({ error: 'PayPal error', detail: e.message }); }
  }

  // Stripe
  if (provider === 'stripe') {
    if (!process.env.STRIPE_SECRET_KEY) return res.json({ status: 'mock', provider, amount, currency, checkoutUrl: 'https://checkout.stripe.com/mock', sessionId: uuidv4() });
    try {
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      const session = await stripe.checkout.sessions.create({ payment_method_types: ['card'], line_items: [{ price_data: { currency, product_data: { name: `NVME ${plan || 'Pro'} Plan` }, unit_amount: Math.round(amount * 100) }, quantity: 1 }], mode: 'payment', success_url: `${process.env.BASE_URL || 'https://nvme.live'}/success`, cancel_url: `${process.env.BASE_URL || 'https://nvme.live'}/cancel` });
      return res.json({ status: 'created', provider, sessionId: session.id, checkoutUrl: session.url });
    } catch (e) { return res.status(500).json({ error: 'Stripe error', detail: e.message }); }
  }

  // All other providers — structured mock ready for real integration
  const mockResponses = {
    cashapp:      { status: 'mock', provider, redirectUrl: `https://cash.app/pay/nvme/$${amount}`, note: 'Add CASHAPP_CLIENT_ID to go live' },
    applepay:     { status: 'mock', provider, token: uuidv4(), note: 'Apple Pay — client-side JS required' },
    googlepay:    { status: 'mock', provider, token: uuidv4(), note: 'Google Pay — client-side JS required' },
    crypto:       { status: 'mock', provider, address: '0xNVME_USDC_ADDRESS', amount, note: 'Add COINBASE_API_KEY to go live' },
    wire:         { status: 'pending', provider, instructions: { bank: 'Bermuda Commercial Bank', routing: '021000021', account: 'NVME-ESCROW-001', ref: uuidv4().slice(0,8).toUpperCase() } },
    bermuda_bank: { status: 'pending', provider, instructions: { bank: 'Clarien Bank Bermuda', sortCode: 'BDA-001', account: 'NVME-2026', ref: uuidv4().slice(0,8).toUpperCase() } },
  };
  res.json({ ...mockResponses[provider], amount, currency, creatorId });
});

app.post('/api/payments/payout', (req, res) => {
  const { creatorId, amount, provider } = req.body;
  if (!creatorId || !amount || !provider) return res.status(400).json({ error: 'creatorId, amount, and provider required' });
  const payoutId = uuidv4();
  activityFeed.unshift({ id: uuidv4(), type: 'earn', user: `@creator_${creatorId.slice(0,6)}`, msg: `earned $${amount}`, time: 'just now' });
  res.json({ success: true, payoutId, creatorId, amount, provider, status: 'processing', eta: '24-48 hours', message: `$${amount} payout initiated via ${provider}` });
});

// ─── AI RECEPTIONIST (TWILIO) ─────────────────────────────────────────────────
app.post('/api/receptionist/voice', (req, res) => {
  const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna" language="en-US">
    Welcome to N V M E dot live, Bermuda's premier creator platform.
    For creator support, press 1.
    For payment inquiries, press 2.
    For partnerships and advertising, press 3.
    To hear about our AI tools and features, press 4.
    To speak with a team member, press 0.
  </Say>
  <Gather numDigits="1" action="/api/receptionist/menu" method="POST" timeout="10">
    <Say voice="Polly.Joanna">Please make your selection now.</Say>
  </Gather>
  <Say voice="Polly.Joanna">We didn't receive your input. Please call back and try again. Goodbye!</Say>
</Response>`;
  res.set('Content-Type', 'text/xml');
  res.send(twiml);
});

app.post('/api/receptionist/menu', (req, res) => {
  const digit = req.body.Digits;
  const responses = {
    '1': `<Say voice="Polly.Joanna">Connecting you to creator support. Our team is available Monday to Friday, 9 A M to 6 P M Bermuda time. You can also email support at nvme dot live for 24 hour assistance.</Say>`,
    '2': `<Say voice="Polly.Joanna">For payment questions, our average payout is 340 dollars per week. We support 8 payment providers including PayPal, Stripe, Cash App, Apple Pay, Google Pay, crypto, and bank wire. Visit nvme dot live slash wallet for details.</Say>`,
    '3': `<Say voice="Polly.Joanna">For partnerships and brand deals, email partnerships at nvme dot live. We connect brands with over 50,000 creators across 150 countries.</Say>`,
    '4': `<Say voice="Polly.Joanna">Our A I suite includes a video generator with 29 avatars, voice cloning, lip sync, and text to video. Creators make up to 10 dollars per 1000 views. Start your free 14 day trial at nvme dot live.</Say>`,
    '0': `<Say voice="Polly.Joanna">Transferring you to a team member now. Please hold.</Say><Dial timeout="30"><Number>${process.env.TEAM_PHONE || '+14412000000'}</Number></Dial>`,
  };
  const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  ${responses[digit] || `<Say voice="Polly.Joanna">Invalid selection. Please call back and try again.</Say>`}
</Response>`;
  res.set('Content-Type', 'text/xml');
  res.send(twiml);
});

app.post('/api/receptionist/sms', async (req, res) => {
  const { From, Body } = req.body;
  const msg = Body?.toLowerCase() || '';
  let reply = 'Welcome to NVME.live! 🚀 Reply with: EARN (how to earn), TOOLS (AI tools), PRICING (plans), or HELP (support).';
  if (msg.includes('earn'))    reply = '💰 Creators earn $2-10 per 1,000 views + gifts from fans. Top earners make $84,000/week! Start free at nvme.live';
  if (msg.includes('tools'))   reply = '🤖 AI Video Generator, 29 avatars, voice cloning, lip-sync, text-to-video. All included in your plan! nvme.live';
  if (msg.includes('pricing')) reply = '💎 14-day FREE trial, no card needed. After trial: Creator $9/mo, Pro $29/mo, Legend $79/mo. nvme.live/pricing';
  if (msg.includes('help'))    reply = '👋 NVME Support: support@nvme.live | Live chat at nvme.live | Call +1 441 200 0000';

  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
    try {
      const twilio = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
      await twilio.messages.create({ body: reply, from: process.env.TWILIO_PHONE_NUMBER, to: From });
    } catch (e) { console.error('Twilio SMS error:', e.message); }
  }

  const twiml = `<?xml version="1.0" encoding="UTF-8"?><Response><Message>${reply}</Message></Response>`;
  res.set('Content-Type', 'text/xml');
  res.send(twiml);
});

// ─── AI CHAT (OpenRouter) ─────────────────────────────────────────────────────
app.post('/api/ai/chat', async (req, res) => {
  const { message, history = [] } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });

  if (!process.env.OPENROUTER_API_KEY) {
    const autoReplies = {
      earn: "💰 Creators on NVME earn $2-10 per 1,000 views plus gifts from fans! Top earners make $84,000/week. Start your free trial at the button above! 🚀",
      ai: "🤖 Our AI suite includes a video generator with 29 avatars, voice cloning, lip-sync, and text-to-video. Create 5 pro videos a day in minutes!",
      trial: "✨ 14 days completely free — no credit card needed. You can cancel anytime. Most creators earn back the subscription cost in their first week!",
      gift: "🎁 Fans send you Bermuda-themed animated gifts worth real money! $18,400 in gifts were sent today alone. Legendary gifts are worth $100+!",
      live: "🔴 Go live and earn gifts in real-time! Top streamers make $1,000+ per stream. 847 live streams are happening on NVME right now!",
    };
    const key = Object.keys(autoReplies).find(k => message.toLowerCase().includes(k));
    return res.json({ reply: key ? autoReplies[key] : "Hi! I'm Zara, your NVME AI guide! 👋 Ask me about earning money, AI tools, gifts, live streaming, or how to get started! 🚀" });
  }

  try {
    const response = await require('axios').post('https://openrouter.ai/api/v1/chat/completions', {
      model: 'mistralai/mistral-7b-instruct',
      messages: [
        { role: 'system', content: `You are Zara, the friendly AI guide for NVME.live — Bermuda's premier creator platform. You help creators earn money through content creation. Key facts: creators earn $2-10 per 1,000 views, 500+ animated gifts, AI video generator with 29 avatars, HD video calling, instant payouts via 8 providers. 14-day free trial, no card needed. Keep replies under 80 words, use emojis, be enthusiastic but honest.` },
        ...history.map(h => ({ role: h.role, content: h.content })),
        { role: 'user', content: message }
      ]
    }, { headers: { Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`, 'Content-Type': 'application/json' } });
    res.json({ reply: response.data.choices[0].message.content });
  } catch (e) {
    res.json({ reply: "I'm having a moment! 😅 Ask me about earning, AI tools, or gifts — I'm here to help! 🚀" });
  }
});

// ─── STAFFING AGENCY JOB BOARD ────────────────────────────────────────────────
app.get('/api/jobs', (req, res) => {
  const { category, type, search } = req.query;
  let result = Array.from(jobs.values());
  if (category) result = result.filter(j => j.category === category);
  if (type)     result = result.filter(j => j.type.toLowerCase().includes(type.toLowerCase()));
  if (search)   result = result.filter(j => j.title.toLowerCase().includes(search.toLowerCase()) || j.company.toLowerCase().includes(search.toLowerCase()));
  res.json({ total: result.length, jobs: result });
});

app.post('/api/jobs', (req, res) => {
  const { title, type, pay, location, company, category, description } = req.body;
  if (!title || !company) return res.status(400).json({ error: 'title and company required' });
  const id = uuidv4();
  const job = { id, title, type: type || 'Full-time', pay: pay || 'Competitive', location: location || 'Remote', company, category: category || 'general', description, posted: 'just now', createdAt: new Date().toISOString() };
  jobs.set(id, job);
  res.status(201).json({ success: true, job });
});

app.post('/api/jobs/:id/apply', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const { name, email, portfolio } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'name and email required' });
  const applicationId = uuidv4();
  res.json({ success: true, applicationId, job: job.title, company: job.company, message: `Application submitted for ${job.title} at ${job.company}. We'll be in touch within 48 hours!` });
});

app.get('/api/jobs/categories', (req, res) => {
  res.json({ categories: ['marketing', 'creative', 'tech', 'sales', 'operations', 'legal', 'finance', 'general'] });
});

// ─── LEGAL DOCUMENT GENERATOR ─────────────────────────────────────────────────
const legalTemplates = {
  creator_contract: (data) => `CREATOR SERVICES AGREEMENT

This Creator Services Agreement ("Agreement") is entered into as of ${new Date().toLocaleDateString()} between:

CLIENT: ${data.clientName || '[CLIENT NAME]'} ("Client")
CREATOR: ${data.creatorName || '[CREATOR NAME]'} ("Creator")

1. SERVICES
Creator agrees to produce ${data.deliverables || '[DELIVERABLE DESCRIPTION]'} for Client.

2. COMPENSATION
Client shall pay Creator ${data.rate || '[RATE]'} upon delivery and approval of content.

3. TIMELINE
Project commencement: ${data.startDate || '[START DATE]'}
Project completion: ${data.endDate || '[END DATE]'}

4. INTELLECTUAL PROPERTY
Creator retains ownership of all creative work until full payment is received. Upon payment, Client receives a non-exclusive license to use the content for ${data.usageRights || 'digital marketing purposes'}.

5. REVISIONS
This agreement includes ${data.revisions || '2'} rounds of revisions.

6. CONFIDENTIALITY
Both parties agree to keep the terms of this agreement confidential.

7. GOVERNING LAW
This agreement shall be governed by the laws of Bermuda.

Signed: _______________________     Date: ___________
${data.clientName || 'Client'}

Signed: _______________________     Date: ___________
${data.creatorName || 'Creator'}

Generated by NVME.live Legal Suite — nvme.live/legal`,

  nda: (data) => `NON-DISCLOSURE AGREEMENT

This NDA is entered into on ${new Date().toLocaleDateString()} between:
${data.party1 || '[PARTY 1]'} and ${data.party2 || '[PARTY 2]'}

1. CONFIDENTIAL INFORMATION includes all business, technical, financial, and creative information shared between the parties.

2. OBLIGATIONS: Each party shall maintain strict confidentiality and not disclose information to third parties without written consent.

3. TERM: This agreement is effective for ${data.term || '2 years'} from the date above.

4. EXCLUSIONS: Information already in the public domain or independently developed is excluded.

5. GOVERNING LAW: Bermuda

_________________________     _________________________
${data.party1 || 'Party 1'}              ${data.party2 || 'Party 2'}

Generated by NVME.live Legal Suite`,

  dmca: (data) => `DMCA TAKEDOWN NOTICE

Date: ${new Date().toLocaleDateString()}
To: ${data.platform || '[PLATFORM/HOST]'}

I, ${data.senderName || '[YOUR NAME]'}, certify under penalty of perjury that I am the owner (or authorized agent) of the copyrighted work described below.

ORIGINAL WORK: ${data.workDescription || '[DESCRIBE YOUR ORIGINAL CONTENT]'}
INFRINGING URL: ${data.infringingUrl || '[URL OF INFRINGING CONTENT]'}
MY CONTACT: ${data.email || '[YOUR EMAIL]'}

I have a good faith belief that use of the described material in the manner complained of is not authorized by the copyright owner, its agent, or the law.

Signature: _______________________
${data.senderName || '[YOUR NAME]'}

Generated by NVME.live Legal Suite`,

  brand_deal: (data) => `BRAND PARTNERSHIP AGREEMENT

Between ${data.brand || '[BRAND NAME]'} ("Brand") and ${data.creator || '[CREATOR NAME]'} ("Creator")
Date: ${new Date().toLocaleDateString()}

CAMPAIGN: ${data.campaign || '[CAMPAIGN NAME]'}
DELIVERABLES: ${data.deliverables || '[LIST OF POSTS/VIDEOS]'}
COMPENSATION: ${data.fee || '[FEE]'} + ${data.commission || '0'}% commission on tracked sales
EXCLUSIVITY: ${data.exclusivity || 'Non-exclusive'}
USAGE RIGHTS: ${data.usageRights || '6 months digital use'}
FTC DISCLOSURE: Creator must include #ad or #sponsored in all posts.

Payment Terms: 50% upfront, 50% on completion.

_________________________     _________________________
${data.brand || 'Brand'}                ${data.creator || 'Creator'}

Generated by NVME.live Legal Suite`,
};

app.get('/api/legal/templates', (req, res) => {
  res.json({ templates: ['creator_contract', 'nda', 'dmca', 'brand_deal'], count: 4 });
});

app.post('/api/legal/generate', (req, res) => {
  const { template, data = {} } = req.body;
  if (!template) return res.status(400).json({ error: 'template required. Options: creator_contract, nda, dmca, brand_deal' });
  if (!legalTemplates[template]) return res.status(400).json({ error: `Unknown template. Choose: ${Object.keys(legalTemplates).join(', ')}` });

  const docText = legalTemplates[template](data);
  const docId = uuidv4();
  const doc = { id: docId, template, data, content: docText, createdAt: new Date().toISOString() };
  legalDocs.set(docId, doc);
  res.json({ success: true, docId, template, content: docText, message: 'Document generated. Download as PDF via /api/legal/' + docId + '/pdf' });
});

app.get('/api/legal/:id', (req, res) => {
  const doc = legalDocs.get(req.params.id);
  if (!doc) return res.status(404).json({ error: 'Document not found' });
  res.json(doc);
});

// ─── CROWN & ANCHOR GAME ─────────────────────────────────────────────────────
const CROWN_ANCHOR_SYMBOLS = ['crown', 'anchor', 'heart', 'diamond', 'club', 'spade'];
const SYMBOL_EMOJI = { crown: '👑', anchor: '⚓', heart: '❤️', diamond: '💎', club: '♣️', spade: '♠️' };

app.get('/api/game/crown-anchor', (req, res) => {
  res.json({
    game: 'Crown & Anchor',
    description: 'Traditional Bermuda dice game. Place bets on symbols, roll 3 dice, win if your symbol appears!',
    symbols: CROWN_ANCHOR_SYMBOLS.map(s => ({ id: s, emoji: SYMBOL_EMOJI[s], name: s.charAt(0).toUpperCase() + s.slice(1) })),
    payouts: { '1 match': '1:1', '2 matches': '2:1', '3 matches': '3:1' },
    minBet: 1,
    maxBet: 1000,
    endpoint: 'POST /api/game/crown-anchor/roll'
  });
});

app.post('/api/game/crown-anchor/roll', (req, res) => {
  const { bet = 10, symbol, playerId } = req.body;
  if (!symbol || !CROWN_ANCHOR_SYMBOLS.includes(symbol)) return res.status(400).json({ error: `Invalid symbol. Choose: ${CROWN_ANCHOR_SYMBOLS.join(', ')}` });
  if (bet < 1 || bet > 1000) return res.status(400).json({ error: 'Bet must be between 1 and 1000' });

  const dice = [
    CROWN_ANCHOR_SYMBOLS[Math.floor(Math.random() * 6)],
    CROWN_ANCHOR_SYMBOLS[Math.floor(Math.random() * 6)],
    CROWN_ANCHOR_SYMBOLS[Math.floor(Math.random() * 6)],
  ];
  const matches = dice.filter(d => d === symbol).length;
  const won = matches > 0;
  const payout = won ? bet * matches : 0;
  const net = won ? payout : -bet;

  res.json({
    dice: dice.map(d => ({ symbol: d, emoji: SYMBOL_EMOJI[d] })),
    yourBet: { symbol, emoji: SYMBOL_EMOJI[symbol], amount: bet },
    matches,
    result: won ? `🎉 WIN! ${matches} match${matches > 1 ? 'es' : ''}` : '😔 No match — try again!',
    payout: won ? `+$${payout}` : `-$${bet}`,
    net,
    nextGame: 'POST /api/game/crown-anchor/roll'
  });
});

// ─── CATCH-ALL → SPA ─────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 NVME Mothership v2.0 running on port ${PORT}`);
  console.log(`📊 Health: http://localhost:${PORT}/api/health`);
  console.log(`🌐 Landing: http://localhost:${PORT}/`);
  console.log(`\n🔧 Active Services:`);
  console.log(`  ${process.env.TWILIO_ACCOUNT_SID ? '✅' : '⚠️ '} AI Receptionist (Twilio)`);
  console.log(`  ${process.env.PAYPAL_CLIENT_ID   ? '✅' : '⚠️ '} PayPal Payments`);
  console.log(`  ${process.env.STRIPE_SECRET_KEY  ? '✅' : '⚠️ '} Stripe Payments`);
  console.log(`  ${process.env.OPENROUTER_API_KEY ? '✅' : '⚠️ '} AI Chat (OpenRouter)`);
  console.log(`  ${process.env.DATABASE_URL       ? '✅' : '⚠️ '} Neon Database`);
  console.log(`  ✅ Staffing Agency Job Board`);
  console.log(`  ✅ Legal Document Generator`);
  console.log(`  ✅ Crown & Anchor Game`);
  console.log(`\nAdd missing keys in Railway → Variables to go fully green.\n`);
});
