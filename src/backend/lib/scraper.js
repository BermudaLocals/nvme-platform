```javascript
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

            if (!response.ok) continue;

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
            console.error(
              'HackerNews item error:',
              id,
              e.message
            );
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

  const timer = setTimeout(function () {
    controller.abort();
  }, timeout);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'NVME-Trend-Scraper/1.0'
      }
    });

    clearTimeout(timer);

    if (!response.ok) {
      console.error(
        'Fetch returned HTTP',
        response.status,
        'for',
        url
      );
      return null;
    }

    return await response.text();
  } catch (e) {
    clearTimeout(timer);

    console.error(
      'Fetch failed:',
      url,
      e.message
    );

    return null;
  }
}

function extractHeadlines(html, max = 10) {
  const headlines = [];

  if (!html) return headlines;

  const re = /<h[1-4][^>]*>([^<]+)<\/h[1-4]>/gi;

  let match;

  while (
    (match = re.exec(html)) &&
    headlines.length < max
  ) {
    const title = match[1].trim();

    if (title.length > 15 && title.length < 200) {
      headlines.push({
        title,
        source: 'web'
      });
    }
  }

  return headlines;
}

function categorizeTopic(title) {
  const t = String(title || '').toLowerCase();

  if (/ai|tech|software|app|phone|computer|robot|gpt|openai/.test(t)) {
    return 'tech';
  }

  if (/game|gaming|play|ps5|xbox|nintendo|stream|esport/.test(t)) {
    return 'gaming';
  }

  if (/music|song|album|concert|rapper|singer|spotify/.test(t)) {
    return 'music';
  }

  if (/cook|recipe|food|restaurant|chef|eat/.test(t)) {
    return 'cooking';
  }

  if (/sport|nba|nfl|soccer|football|basketball|world cup/.test(t)) {
    return 'sports';
  }

  if (/movie|film|actor|actress|netflix|series|show/.test(t)) {
    return 'entertainment';
  }

  if (/crypto|bitcoin|eth|blockchain|defi|nft/.test(t)) {
    return 'crypto';
  }

  if (/health|medical|doctor|disease|vaccine|fitness/.test(t)) {
    return 'health';
  }

  if (/politic|election|president|government|law|court/.test(t)) {
    return 'politics';
  }

  return 'general';
}

function extractKeywords(title) {
  const stop = new Set([
    'the',
    'a',
    'an',
    'is',
    'are',
    'was',
    'were',
    'be',
    'been',
    'being',
    'have',
    'has',
    'had',
    'do',
    'does',
    'did',
    'will',
    'would',
    'shall',
    'should',
    'may',
    'might',
    'can',
    'could',
    'this',
    'that',
    'these',
    'those',
    'what',
    'which',
    'who',
    'whom',
    'when',
    'where',
    'why',
    'how',
    'all',
    'each',
    'every',
    'both',
    'few',
    'more',
    'most',
    'other',
    'some',
    'such',
    'no',
    'not',
    'only',
    'own',
    'same',
    'so',
    'than',
    'too',
    'very',
    'just',
    'because',
    'as',
    'until',
    'while',
    'of',
    'at',
    'by',
    'for',
    'with',
    'about',
    'against',
    'between',
    'through',
    'during',
    'before',
    'after',
    'above',
    'below',
    'to',
    'from',
    'up',
    'down',
    'in',
    'out',
    'on',
    'off',
    'over',
    'under',
    'again',
    'further',
    'then',
    'once',
    'here',
    'there',
    'and',
    'but',
    'or',
    'nor',
    'if',
    'it',
    'its',
    'new',
    'one',
    'two',
    'first',
    'also',
    'into'
  ]);

  return String(title || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, '')
    .split(/\s+/)
    .filter(function (word) {
      return word.length > 2 && !stop.has(word);
    })
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

        category:
          item.category ||
          categorizeTopic(item.title),

        keywords:
          extractKeywords(item.title),

        score:
          Math.floor(Math.random() * 40) + 60
      };
    });
  } catch (error) {
    console.error(
      'Scrape source failed:',
      src.name,
      error.message
    );

    return [];
  }
}

async function scrapeAll() {
  let total = 0;

  for (const src of SOURCES) {
    const items = await scrapeSource(src);

    for (const item of items) {
      try {
        const exists = await db.query(
          `SELECT id
           FROM trending_topics
           WHERE title = $1
             AND fetched_at > NOW() - INTERVAL '6 hours'
           LIMIT 1`,
          [item.title]
        );

        if (exists.rows.length > 0) {
          continue;
        }

        await db.query(
          `INSERT INTO trending_topics
            (
              title,
              source,
              source_url,
              summary,
              category,
              keywords,
              score
            )
           VALUES
            ($1, $2, $3, $4, $5, $6, $7)`,
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
      } catch (error) {
        console.error(
          'Failed to insert trend:',
          item.title,
          error.message
        );
      }
    }
  }

  console.log(
    '📥 Scraping complete:',
    total,
    'new topics inserted'
  );

  return total;
}

async function getTopTrends(limit = 10) {
  const safeLimit = Math.max(
    1,
    Math.min(Number(limit) || 10, 100)
  );

  const result = await db.query(
    `SELECT *
     FROM trending_topics
     WHERE fetched_at > NOW() - INTERVAL '24 hours'
     ORDER BY score DESC, fetched_at DESC
     LIMIT $1`,
    [safeLimit]
  );

  return result.rows;
}

/**
 * Creates videos from eligible trending topics.
 *
 * IMPORTANT:
 * The current database schema calls the reference
 * "nvme_version_id", but the existing architecture stores
 * the created videos.id in this field.
 *
 * We preserve that behavior here because changing the
 * database relationship would require a separate migration.
 */
async function autoPostTrending(options = {}) {
  const limit = Math.max(
    1,
    Math.min(Number(options.limit) || 3, 50)
  );

  const hours = Math.max(
    1,
    Math.min(Number(options.hours) || 24, 168)
  );

  const minimumScore = Number.isFinite(
    Number(options.minimumScore)
  )
    ? Number(options.minimumScore)
    : 70;

  console.log('📤 Auto-posting trending...');
  console.log(
    `   limit=${limit}, window=${hours}h, minimumScore=${minimumScore}`
  );

  /*
   * Only select topics that:
   *   1. Have not already been converted to a video.
   *   2. Are recent enough to still be useful.
   *   3. Have a score above the minimum threshold.
   *
   * The previous code used a 2-hour window, which caused
   * eligible trends to remain stuck with nvme_version_id=NULL.
   *
   * We use 24 hours by default so the queue can catch up.
   */
  const trends = await db.query(
    `SELECT *
     FROM trending_topics
     WHERE nvme_version_id IS NULL
       AND fetched_at > NOW() - ($1 * INTERVAL '1 hour')
       AND score >= $2
     ORDER BY score DESC, fetched_at DESC
     LIMIT $3`,
    [hours, minimumScore, limit]
  );

  if (trends.rows.length === 0) {
    console.log(
      'ℹ️ No eligible unposted trending topics found.'
    );

    return [];
  }

  console.log(
    `🔥 Found ${trends.rows.length} eligible trends`
  );

  const results = [];

  for (const trend of trends.rows) {
    try {
      console.log(
        `🎬 Processing: "${trend.title}" (score ${trend.score})`
      );

      const keywords =
        Array.isArray(trend.keywords)
          ? trend.keywords
          : [];

      const hashtags = keywords
        .filter(Boolean)
        .map(function (k) {
          return (
            '#' +
            String(k)
              .trim()
              .replace(/\s+/g, '')
              .replace(/[^a-zA-Z0-9_]/g, '')
          );
        })
        .filter(function (tag) {
          return tag.length > 1;
        })
        .join(' ');

      const caption =
        '🔥 ' +
        trend.title +
        '\n\n' +
        'NVME take: What do you think about this? Drop your reaction below.' +
        '\n\n' +
        hashtags +
        ' #trending #news #nvme';

      /*
       * Create the video first.
       *
       * If this INSERT fails, we DO NOT update the trend.
       * That means the trend remains eligible for a later retry.
       */
      const result = await db.query(
        `INSERT INTO videos
          (
            user_id,
            url,
            thumbnail,
            caption,
            hashtags,
            source_type,
            score,
            is_trending
          )
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id`,
        [
          '7389d4f3-90ff-4da6-be6c-72d497ea2025',
          'trending://' + trend.id,
          null,
          caption,
          keywords,
          'trending',
          Number(trend.score || 50) + 100,
          true
        ]
      );

      if (
        !result.rows.length ||
        !result.rows[0].id
      ) {
        throw new Error(
          'Video INSERT returned no video ID'
        );
      }

      const videoId = result.rows[0].id;

      /*
       * Mark the trend as processed ONLY after the
       * video was successfully created.
       */
      const update = await db.query(
        `UPDATE trending_topics
         SET nvme_version_id = $1
         WHERE id = $2
           AND nvme_version_id IS NULL
         RETURNING id, title, nvme_version_id`,
        [videoId, trend.id]
      );

      if (update.rows.length === 0) {
        console.warn(
          `⚠️ Video ${videoId} created, but trend ${trend.id} was already processed.`
        );
      } else {
        console.log(
          `✅ Posted: "${trend.title}" → video ${videoId}`
        );
      }

      results.push({
        trend: trend.title,
        trendId: trend.id,
        videoId: videoId,
        score: trend.score
      });
    } catch (error) {
      /*
       * Do not stop the entire batch if one trend fails.
       * The failed trend remains nvme_version_id=NULL
       * and can be retried on the next run.
       */
      console.error(
        `❌ Failed to post "${trend.title}":`,
        error.message
      );

      results.push({
        trend: trend.title,
        trendId: trend.id,
        error: error.message
      });
    }
  }

  const successful = results.filter(function (item) {
    return item.videoId;
  });

  const failed = results.filter(function (item) {
    return item.error;
  });

  console.log(
    `📊 Auto-post complete: ${successful.length} successful, ${failed.length} failed`
  );

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
```
