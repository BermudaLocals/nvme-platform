# 🚀 NVME.LIVE — POPULATION CAMPAIGN ENGINE
**Built:** 2026-07-31 | **Owner:** Kush | **Cadence:** 9 posts/day across TikTok, IG Reels, YouTube Shorts, Facebook, X
**Posting times (ADT):** 07:00 · 08:30 · 10:00 · 12:00 · 14:00 · 16:00 · 18:00 · 20:00 · 22:00
**Funnel:** Post → profile link → nvme.live → install PWA → 500 free coins → first gift/tip → retained user

---

## 🎯 CORE HOOKS (rotate these — never repeat same-day)
1. "I got banned from TikTok. So I built my own." (origin story — highest converter)
2. "TikTok keeps 30-70% of your gifts. NVME creators keep 70%."
3. "500 free coins just for joining — today only framing."
4. "Tips go 100% to the creator. Zero platform cut. Show me another app doing that."
5. "Shadowbanned? Your reach dies on their algorithm. Ours shows everything."
6. "Paid series: lock your best content, fans pay to unlock."
7. "No app store. Install from your browser in 10 seconds."
8. "Weekly creator leaderboard — real coin prizes."
9. "Live streaming with zero restriction thresholds."

---

## 📅 DAY 1 — 9 POSTS (ready to fire)

**07:00 (TikTok/Reels/Shorts)** — "POV: TikTok banned you at 50K followers. I built NVME.LIVE so that never happens again. 500 free coins for the first wave 👑 #creatoreconomy #tiktokbanned #nvme"

**08:30 (X + FB)** — "TikTok takes up to 70% of creator gifts. Instagram buries you without ad spend. NVME.LIVE: creators keep 70% of gifts, 100% of tips. First 500 coins free → nvme.live"

**10:00 (TikTok)** — "3 ways creators actually lose money on TikTok (and the app that fixes all 3) 👇 #makemoneyonline #creatortips #nvme"

**12:00 (IG Reels + Shorts)** — "This app pays you coins every 1,000 views automatically. No brand deals needed. nvme.live #sidehustle #creatorlife"

**14:00 (X thread)** — "Why I stopped building on rented land: a thread on creator ownership and the platform that gives it back 🧵 nvme.live"

**16:00 (TikTok)** — "Lock your best videos behind a paid series. Your superfans WILL pay. Here's how it works on NVME 💰 #paidcontent #creatoreconomy"

**18:00 (FB + IG)** — "No app store. No approval. No 30% cut to Apple. NVME.LIVE installs from your browser in 10 seconds. Try it → nvme.live"

**20:00 (TikTok prime)** — "Day 1 of building in public: we're populating NVME.LIVE and every early creator gets leaderboard priority + 500 free coins 👑 #buildinpublic #nvme"

**22:00 (Shorts + X)** — "Your favorite creator only keeps half of what you gift them. On NVME they keep 70% — and tips are 100% theirs. Support creators properly tonight 🌙 nvme.live"

---

## 🤖 FLEET WIRING (what runs this)
- **empire-autopost** (:5141 block) → scheduling queue for the 9 daily slots
- **dm-ig-hunter / dm-tiktok-hunter / dm-twitter-hunter** → find banned/shadowbanned creators complaining (keywords: "banned", "shadowbanned", "demonetized")
- **dm-reply-ai** → auto-replies with Creator Outreach Template 1/2/3 (in NVME_CREATOR_OUTREACH.md)
- **dm-closer + dm-followup-1/2** → convert warm replies into signups
- **viral-intel** → which hook is winning → double down next day
- **kush-reporter** → nightly numbers: posts fired, views, clicks, signups
- **Twilio SMS layer** → re-engagement blasts to captured numbers (King provides confirm on TWILIO_* envs already in vault: SID, AUTH_TOKEN, PHONE, API_KEY_SID/SECRET)

## 📝 CONTENT PIPELINE
Captions: Kimi K3 via NVME AI Studio (`/api/ai/captions`, `/api/ai/scripts` — already live, $0) + captions_bank.json pattern (14 days × 9 = 126 pre-written) → extend to 30 days.
Videos: HeyGen promo script ready (60s talking head) + D-ID/fal avatar clips at ~$1.37 each.

## 💰 REVENUE MODEL PER USER
Signup free (500 coins) → coin purchases (gifts, tips, paid series, subscriptions) → platform keeps 30% of gifts, 0% of tips. ARPU target: $2–12/mo blended.
