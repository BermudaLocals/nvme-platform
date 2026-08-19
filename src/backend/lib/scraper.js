const db = require('../db');

const SOURCES = [
  {
    name: 'Reddit',
    url: 'https://www.reddit.com/r/popular/hot.json',
    type: 'social',
    parse: function (data) {
      try {
        const j = typeof data === 'string' ? JSON.parse(data) : data;
        return (j.data?.children || []).slice(0, 10).map(function (p) {
          return {
            title: p.data.title,
            source: 'reddit',
            source_url: 'https://reddit.com' + p.data.permalink,
            category: p.data.subreddit
          };
        });
      } catch (e) {
        console.error('Reddit parse error:', e.message);
        return [];
      }
    }
  },
  {
    name: 'HackerNews',
    url: 'https://hacker-news.firebaseio.com/v0/topstories.json',
    type: 'tech',
    parse: async function (data) {
      try {
        const ids = typeof data === 'string' ? JSON.parse(data) : data;
        if (!Array.isArray(ids)) return [];
        const results = [];
        for (const id of ids.slice(0, 10)) {
          try {
            const response = await fetch(
              'https://hacker-news.firebaseio.com/v0/item/' + id + '.json'
            );
            const item = await response.json();
            if (item && item.title) {
              results.push({
                title: item.title,
                source: 'hackernews',
                source_url: item.url || '',
                category: 'tech'
              });
            }
          } catch (e) {
            console.error('HackerNews item error:', e.message);
          }
        }
        return results;
      } catch (e) {
        console.error('HackerNews parse error:', e.message);
        return [];
      }
    }
  }
];

async function fetchWithTimeout(url, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(function () { controller.abort(); }, timeout);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'NVME-Trend-Scraper/1.0' }
    });
    clearTimeout(timer);
    if (!response.ok) return null;
    return await response.text();
  } catch (e) {
    clearTimeout(timer);
    console.error('Fetch failed:', url, e.message);
    return null;
  }
}

function extractHeadlines(html, max = 10) {
  const headlines = [];
  if (!html) return headlines;
  const re = /<h[1-4][^>]*>([^<]+)<\/h[1-4]>/gi;
  let match;
  while ((match = re.exec(html)) && headlines.length < max) {
    const title = match[1].trim();
    if (title.length > 15 && title.length < 200) {
      headlines.push({ title, source: 'web' });
    }
  }
  return headlines;
}

function categorizeTopic(title) {
  const t = String(title || '').toLowerCase();
  if (/ai|tech|software|app|phone|computer|robot|gpt|openai/.test(t)) return 'tech';
  if (/game|gaming|play|ps5|xbox|nintendo|stream|esport/.test(t)) return 'gaming';
  if (/music|song|album|concert|rapper|singer|spotify/.test(t)) return 'music';
  if (/cook|recipe|food|restaurant|chef|eat/.test(t)) return 'cooking';
  if (/sport|nba|nfl|soccer|football|basketball|world cup/.test(t)) return 'sports';
  if (/movie|film|actor|actress|netflix|series|show/.test(t)) return 'entertainment';
  if (/crypto|bitcoin|eth|blockchain|defi|nft/.test(t)) return 'crypto';
  if (/health|medical|doctor|disease|vaccine|fitness/.test(t)) return 'health';
  if (/politic|election|president|government|law|court/.test(t)) return 'politics';
  return 'general';
}

function extractKeywords(title) {
  const stop = new Set([
    'the','a','an','is','are','was','were','be','been','being','have','has','had',
    'do','does','did','will','would','shall','should','may','might','can','could',
    'this','that','these','those','what','which','who','whom','when','where','why',
    'how','all','each','every','both','few','more','most','other','some','such','no',
    'not','only','own','same','so','than','too','very','just','because','as','until',
    'while','of','at','by','for','with','about','against','between','through','during',
    'before','after','above','below','to','from','up','down','in','out','on','off',
    'over','under','again','further','then','once','here','there','and','but','or',
    'nor','if','it','its','new','one','two','first','also','into'
  ]);
  return String(title || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, '')
    .split(/\s+/)
    .filter(function (word) { return word.length > 2 && !stop.has(word); })
    .slice(0, 8);
}

async function scrapeSource(src) {
  try {
    const raw = await fetchWithTimeout(src.url);
    if (!raw) return [];
    const items = await src.parse(raw);
    return items.map(function (item) {
      return {
        ...item,
        category: item.category || categorizeTopic(item.title),
        keywords: extractKeywords(item.title),
        score: Math.floor(Math.random() * 40) + 60
      };
    });
  } catch (error) {
    console.error('Scrape source failed:', src.name, error.message);
    return [];
  }
}

async function scrapeAll() {
  let total = 0;
  for (const src of SOURCES) {
    const items = await scrapeSource(src);
    for (const item of items) {
      const exists = await db.query(
        `SELECT id FROM trending_topics
         WHERE title = $1 AND fetched_at > NOW() - INTERVAL '6 hours'`,
        [item.title]
      );
      if (exists.rows.length > 0) continue;
      await db.query(
        `INSERT INTO trending_topics
          (title, source, source_url, summary, category, keywords, score)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          item.title,
          item.source || src.name,
          item.source_url || '',
          item.title,
          item.category || 'general',
          item.keywords || [],
          item.score || 50
        ]
      );
      total++;
    }
  }
  return total;
}

async function getTopTrends(limit = 10) {
  const result = await db.query(
    `SELECT * FROM trending_topics
     WHERE fetched_at > NOW() - INTERVAL '24 hours'
     ORDER BY score DESC, fetched_at DESC
     LIMIT $1`,
    [limit]
  );
  return result.rows;
}

async function autoPostTrending() {
  const trends = await db.query(
    `SELECT * FROM trending_topics
     WHERE nvme_version_id IS NULL
       AND fetched_at > NOW() - INTERVAL '2 hours'
       AND score > 70
     ORDER BY score DESC
     LIMIT 3`
  );
  if (trends.rows.length === 0) return null;
  const results = [];
  for (const trend of trends.rows) {
    const keywords = Array.isArray(trend.keywords) ? trend.keywords : [];
    const hashtags = keywords
      .map(function (k) { return '#' + String(k).replace(/\s+/g, ''); })
      .join(' ');
    const caption =
      '🔥 ' + trend.title +
      '\n\nNVME take: What do you think about this? Drop your reaction below.\n\n' +
      hashtags + ' #trending #news #nvme';
    const result = await db.query(
      `INSERT INTO videos
        (user_id, url, thumbnail, caption, hashtags, source_type, score, is_trending)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [
        1,   // <-- ⚠️ Change this to a valid user ID from your users table
        'trending://' + Date.now(),
        null,
        caption,
        keywords,
        'trending',
        Number(trend.score || 50) + 100,
        true
      ]
    );
    await db.query(
      `UPDATE trending_topics SET nvme_version_id = $1 WHERE id = $2`,
      [result.rows[0].id, trend.id]
    );
    results.push({ trend: trend.title, videoId: result.rows[0].id });
  }
  return results;
}

module.exports = {
  scrapeAll,
  getTopTrends,
  autoPostTrending,
  scrapeSource,
  categorizeTopic,
  extractKeywords
};
