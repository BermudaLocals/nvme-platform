require('dotenv').config({ path: './src/backend/.env' });
const { scrapeAll, getTopTrends, autoPostTrending } = require('./src/backend/lib/scraper');

(async () => {
  try {
    console.log('🔄 Starting scrape...');
    const count = await scrapeAll();
    console.log(`✅ Scraped and inserted ${count} new topics`);

    console.log('📊 Top trends:');
    const trends = await getTopTrends(5);
    console.log(trends);

    console.log('📤 Auto-posting trending...');
    const posts = await autoPostTrending();
    console.log(`✅ Posted ${posts ? posts.length : 0} trends as videos`);
  } catch (err) {
    console.error('❌ Scraper error:', err);
  }
})();
