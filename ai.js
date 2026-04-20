const express = require('express');
const { body, validationResult } = require('express-validator');
const OpenAI = require('openai');
const auth = require('../middleware/auth');
const router = express.Router();

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// AI chat endpoint
router.post('/chat', auth, [
  body('message').isLength({ min: 1, max: 1000 }).withMessage('Message is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { message } = req.body;

    // Predefined responses for common questions
    const quickReplies = {
      earn: '💰 Creators earn $2–10 per 1,000 views PLUS gifts from fans! Top earners made $84,000 last week. Start your free trial above! 🚀',
      ai: '🤖 Our AI suite includes a video generator with 29 avatars, voice cloning, lip-sync, and text-to-video. Create 5 pro videos a day in minutes!',
      gift: '🎁 Fans send you Bermuda-themed animated gifts worth real money! $18,400 in gifts were sent today. Legendary gifts are worth $100+ each!',
      live: '🔴 Go live and earn gifts in real-time! Top streamers make $1,000+ per stream. 847 live streams are happening on NVME right now!',
      trial: '✨ 14 days completely free — no credit card needed. Cancel anytime. Most creators earn back the cost in their first week!',
      price: '💎 Creator $9/mo, Pro $29/mo, Legend $79/mo. All plans include the 14-day free trial! nvme.live/pricing',
      payment: '💳 We support 8 payment methods: PayPal, Cash App, Apple Pay, Google Pay, Crypto, Bermuda Bank, Wire, and more!'
    };

    // Check for quick reply keywords
    const lowerMessage = message.toLowerCase();
    for (const [key, reply] of Object.entries(quickReplies)) {
      if (lowerMessage.includes(key)) {
        return res.json({ reply });
      }
    }

    // If no quick reply matches, use OpenAI
    if (process.env.OPENAI_API_KEY) {
      try {
        const completion = await openai.chat.completions.create({
          model: "gpt-3.5-turbo",
          messages: [
            {
              role: "system",
              content: "You are Zara, an AI guide for NVME.live, a creator platform where creators earn real money. Be helpful, enthusiastic, and keep responses concise."
            },
            {
              role: "user",
              content: message
            }
          ],
          max_tokens: 150,
          temperature: 0.7,
        });

        return res.json({ reply: completion.choices[0].message.content });
      } catch (openaiError) {
        console.error('OpenAI API error:', openaiError);
      }
    }

    // Fallback response
    const fallbackResponse = "I'd love to help! 🚀 Ask me about earning, AI tools, gifts, live streaming, payments, or how to get started on NVME!";
    res.json({ reply: fallbackResponse });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Generate AI video
router.post('/video', auth, [
  body('prompt').isLength({ min: 5, max: 500 }).withMessage('Prompt is required'),
  body('avatar').optional().isIn(['avatar1', 'avatar2', 'avatar3', 'avatar4', 'avatar5'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { prompt, avatar } = req.body;

    // In a real implementation, you would integrate with a video generation API
    // For now, we'll simulate the process
    
    // Simulate processing time
    setTimeout(() => {
      // Return a mock video URL
      res.json({
        videoUrl: `https://nvme.live/generated-videos/${Date.now()}.mp4`,
        thumbnailUrl: `https://nvme.live/generated-videos/${Date.now()}.jpg`,
        processingTime: '15 seconds'
      });
    }, 2000);

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;