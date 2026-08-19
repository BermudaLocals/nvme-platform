const db = require('../db');

const TRENDING_SYSTEM_USER_ID =
  '7389d4f3-90ff-4da6-be6c-72d497ea2025';

const SOURCES = [
  {
    name: 'Reddit',
    url: 'https://www.reddit.com/r/popular/hot.json',
    type: 'social',
    parse(data) {
      try {
        const json =
          typeof data === 'string'
            ? JSON.parse(data)
            : data;

        return (json.data?.children || [])
          .slice(0, 10)
          .map((post) => ({
            title: post.data.title,
            source: 'reddit',
            source_url:
              'https://reddit.com' +
              post.data.permalink,
            category: post.data.subreddit
          }));
      } catch (error) {
        console.error(
          'Reddit parse error:',
          error.message
        );
        return [];
      }
    }
  },

  {
    name: 'HackerNews',
    url: 'https://hacker-news.firebaseio.com/v0/topstories.json',
    type: 'tech',

    async parse(data) {
      try {
        const ids =
          typeof data === 'string'
            ? JSON.parse(data)
            : data;

        if (!Array.isArray(ids)) {
          return [];
        }

        const results = [];

        for (const id of ids.slice(0, 10)) {
          try {
            const response = await fetch(
              `https://hacker-news.firebaseio.com/v0/item/${id}.json`
            );

            if (!response.ok) {
              continue;
            }

            const item = await response.json();

            if (item?.title) {
              results.push({
                title: item.title,
                source: 'hackernews',
                source_url: item.url || '',
                category: 'tech'
              });
            }
          } catch (error) {
            console.error(
              'HackerNews item error:',
              id,
              error.message
            );
          }
        }

        return results;
      } catch (error) {
        console.error(
          'HackerNews parse error:',
          error.message
        );
        return [];
      }
    }
  }
];

async function fetchWithTimeout(
  url,
  timeout = 8000
) {
  const controller = new AbortController();

  const timer = setTimeout(() => {
    controller.abort();
  }, timeout);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent':
          'NVME-Trend-Scraper/1.0'
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
  } catch (error) {
    clearTimeout(timer);

    console.error(
      'Fetch failed:',
      url,
      error.message
    );

    return null;
  }
}

function extractHeadlines(
  html,
  max = 10
) {
  const headlines = [];

  if (!html) {
    return headlines;
  }

  const regex =
    /<h[1-4][^>]*>([^<]+)<\/h[1-4]>/gi;

  let match;

  while (
    (match = regex.exec(html)) &&
    headlines.length < max
  ) {
    const title = match[1].trim();

    if (
      title.length > 15 &&
      title.length < 200
    ) {
      headlines.push({
        title,
        source: 'web'
      });
    }
  }

  return headlines;
}

function categorizeTopic(title) {
  const text = String(title || '').toLowerCase();

  if (
    /ai|tech|software|app|phone|computer|robot|gpt|openai/.test(
      text
    )
  ) {
    return 'tech';
  }

  if (
    /game|gaming|play|ps5|xbox|nintendo|stream|esport/.test(
      text
    )
  ) {
    return 'gaming';
  }

  if (
    /music|song|album|concert|rapper|singer|spotify/.test(
      text
    )
  ) {
    return 'music';
  }

  if (
    /cook|recipe|food|restaurant|chef|eat/.test(
      text
    )
  ) {
    return 'cooking';
  }

  if (
    /sport|nba|nfl|soccer|football|basketball|world cup/.test(
      text
    )
  ) {
    return 'sports';
  }

  if (
    /movie|film|actor|actress|netflix|series|show/.test(
      text
    )
  ) {
    return 'entertainment';
  }

  if (
    /crypto|bitcoin|eth|blockchain|defi|nft/.test(
      text
    )
  ) {
    return 'crypto';
  }

  if (
    /health|medical|doctor|disease|vaccine|fitness/.test(
      text
    )
  ) {
    return 'health';
  }

  if (
    /politic|election|president|government|law|court/.test(
      text
    )
  ) {
    return 'politics';
  }

  return 'general';
}

function extractKeywords(title) {
  const stopWords = new Set([
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
    .filter(
      (word) =>
        word.length > 2 &&
        !stopWords.has(word)
    )
    .slice(0, 8);
}

function calculateTrendScore(item) {
  const base =
    Number.isFinite(Number(item.score))
      ? Number(item.score)
      : 70;

  return Math.max(
    0,
    Math.min(
      Math.round(base),
      100
    )
  );
}

function buildHashtags(keywords) {
  return (Array.isArray(keywords)
    ? keywords
    : []
  )
    .filter(Boolean)
    .map((keyword) =>
      String(keyword)
        .trim()
        .replace(/\s+/g, '')
        .replace(/[^a-zA-Z0-9_]/g, '')
    )
    .filter((keyword) => keyword.length > 0)
    .map((keyword) => `#${keyword}`)
    .slice(0, 8);
}

function buildCaption(trend) {
  const hashtags =
    buildHashtags(trend.keywords);

  const tagLine = [
    ...hashtags,
    '#trending',
    '#news',
    '#nvme'
  ].join(' ');

  return [
    `🔥 ${trend.title}`,
    '',
    'NVME take: What do you think about this? Drop your reaction below.',
    '',
    tagLine
  ].join('\n');
}

async function scrapeSource(source) {
  try {
    const raw = await fetchWithTimeout(
      source.url
    );

    if (!raw) {
      return [];
    }

    const items =
      await source.parse(raw);

    return items.map((item) => ({
      ...item,
      category:
        item.category ||
        categorizeTopic(item.title),
      keywords:
        extractKeywords(item.title),
      score:
        calculateTrendScore(item)
    }));
  } catch (error) {
    console.error(
      'Scrape source failed:',
      source.name,
      error.message
    );

    return [];
  }
}

async function scrapeAll() {
  let total = 0;

  for (const source of SOURCES) {
    const items =
      await scrapeSource(source);

    for (const item of items) {
      try {
        const exists =
          await db.query(
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
            item.source || source.name,
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

async function getTopTrends(
  limit = 10
) {
  const safeLimit = Math.max(
    1,
    Math.min(
      Number(limit) || 10,
      100
    )
  );

  const result =
    await db.query(
      `SELECT *
       FROM trending_topics
       WHERE fetched_at > NOW() - INTERVAL '24 hours'
       ORDER BY score DESC, fetched_at DESC
       LIMIT $1`,
      [safeLimit]
    );

  return result.rows;
}

async function autoPostTrending(
  options = {}
) {
  const limit = Math.max(
    1,
    Math.min(
      Number(options.limit) || 3,
      50
    )
  );

  const hours = Math.max(
    1,
    Math.min(
      Number(options.hours) || 24,
      168
    )
  );

  const minimumScore =
    Number.isFinite(
      Number(options.minimumScore)
    )
      ? Number(options.minimumScore)
      : 70;

  console.log(
    '📤 Auto-posting trending...'
  );

  console.log(
    `   limit=${limit}, window=${hours}h, minimumScore=${minimumScore}`
  );

  const trends =
    await db.query(
      `SELECT *
       FROM trending_topics
       WHERE nvme_version_id IS NULL
         AND fetched_at > NOW() - ($1 * INTERVAL '1 hour')
         AND score >= $2
       ORDER BY score DESC, fetched_at DESC
       LIMIT $3`,
      [
        hours,
        minimumScore,
        limit
      ]
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
    let reservationId = null;

    try {
      console.log(
        `🎬 Processing: "${trend.title}" (score ${trend.score})`
      );

      const claim =
        await db.query(
          `UPDATE trending_topics
           SET nvme_version_id = gen_random_uuid()
           WHERE id = $1
             AND nvme_version_id IS NULL
           RETURNING id, title, nvme_version_id`,
          [trend.id]
        );

      if (claim.rows.length === 0) {
        results.push({
          trend: trend.title,
          trendId: trend.id,
          skipped: true
        });

        continue;
      }

      reservationId =
        claim.rows[0].nvme_version_id;

      const keywords =
        Array.isArray(trend.keywords)
          ? trend.keywords
          : [];

      const hashtags =
        buildHashtags(keywords);

      const caption =
        buildCaption({
          ...trend,
          keywords
        });

      const video =
        await db.query(
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
            TRENDING_SYSTEM_USER_ID,
            `trending://${trend.id}`,
            null,
            caption,
            keywords,
            'trending',
            Number(trend.score || 50) + 100,
            true
          ]
        );

      if (
        !video.rows.length ||
        !video.rows[0].id
      ) {
        throw new Error(
          'Video INSERT returned no video ID'
        );
      }

      const videoId =
        video.rows[0].id;

      const finalized =
        await db.query(
          `UPDATE trending_topics
           SET nvme_version_id = $1
           WHERE id = $2
             AND nvme_version_id = $3
           RETURNING id, title, nvme_version_id`,
          [
            videoId,
            trend.id,
            reservationId
          ]
        );

      if (finalized.rows.length === 0) {
        throw new Error(
          `Trend finalization failed for ${trend.id}`
        );
      }

      console.log(
        `✅ Posted: "${trend.title}" → video ${videoId}`
      );

      results.push({
        trend: trend.title,
        trendId: trend.id,
        videoId,
        score: trend.score,
        hashtags
      });
    } catch (error) {
      if (reservationId) {
        try {
          await db.query(
            `UPDATE trending_topics
             SET nvme_version_id = NULL
             WHERE id = $1
               AND nvme_version_id = $2`,
            [
              trend.id,
              reservationId
            ]
          );
        } catch (releaseError) {
          console.error(
            `❌ Failed releasing trend claim ${trend.id}:`,
            releaseError.message
          );
        }
      }

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

  const successful =
    results.filter(
      (item) => item.videoId
    );

  const failed =
    results.filter(
      (item) => item.error
    );

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
  extractKeywords,
  extractHeadlines
};
