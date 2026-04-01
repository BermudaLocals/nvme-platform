// NVME.live Zara AI Chat Assistant

const zaraResponses = {
    'earn': `💰 NVME creators earn through multiple streams:

1️⃣ **Video Views (CPM)** - Earn $2-10 per 1000 views
2️⃣ **Gifts from Fans** - Viewers send virtual gifts worth real money
3️⃣ **Subscriptions** - Monthly recurring revenue from subscribers
4️⃣ **AI Video Commissions** - Create custom AI content for brands

Top creators earn **$500-$5,000/week**! The more you create, the more you earn. Ready to start? 🚀`,

    'how it works': `🎯 It's super simple:

1️⃣ **Create Content** - Use our TikTok-style vertical feed or AI generator
2️⃣ **Get Views** - Our algorithm promotes engaging content
3️⃣ **Earn Money** - Every view, gift, and subscription = 💵

Our AI tools make creation easy. You focus on creativity, we handle the rest!

Want to see the platform? Click the UNLOCK button! ✨`,

    'price': `💎 NVME Pricing:

✅ **Free 14-day trial** - No credit card required!
✅ **Basic features** - Always free forever
✅ **Pro Plan** - $19/month (unlock AI generator, analytics, priority support)
✅ **Creator Pro** - $49/month (advanced monetization, brand deals, 90% revenue share)

Most creators earn back the Pro cost within their first week! 📈`,

    'help': `👋 I can help with:

1️⃣ **Getting Started** - Account setup, profile creation
2️⃣ **Earning Money** - Monetization tips, payment setup
3️⃣ **AI Tools** - Video generator, avatar creation
4️⃣ **Growing Audience** - Tips to get more views and followers

What would you like to know more about? Just ask! 💬`,

    'video': `🎬 Our AI Video Generator is game-changing:

📝 **Text-to-Video** - Just describe your idea, AI creates it
🖼️ **Image-to-Video** - Upload photos, get animated videos
🤖 **AI Avatars** - 29 unique avatars with lip-sync
🎤 **Voice Cloning** - Your voice, cloned with AI

Most videos render in under 60 seconds! ⚡`,

    'gift': `🎁 The Gift System is where the magic happens:

💎 **500+ unique gifts** - From hearts to legendary items
💰 **Real money** - Gifts convert to cash instantly
🏆 **Bermuda-themed** - Pink Sand, Gombey Dancer, Bermuda Dollar
⭐ **Legendary gifts** - Trigger epic screen animations!

Fans love gifting creators. Top earners make $100+/day from gifts alone! 💸`,

    'default': `Hey! I'm Zara, your NVME guide! 👋

I can help you with:
• 💰 How to earn money
• 🎬 AI video creation
• 💎 Pricing & plans
• 🎁 Gift system
• 📈 Growing your audience

Just ask me anything! Or click that big shiny button to get started! ✨🚀`
};

let zaraChatOpen = false;
let hasGreeted = false;

// Toggle Zara chat open/close
function toggleZaraChat() {
    const chat = document.getElementById('zaraChat');
    zaraChatOpen = !zaraChatOpen;
    
    if (zaraChatOpen) {
        chat.classList.add('active');
        if (!hasGreeted) {
            addZaraMessage(getGreeting());
            hasGreeted = true;
        }
    } else {
        chat.classList.remove('active');
    }
}

// Auto-greeting after 3 seconds
function showZaraGreeting() {
    if (!hasGreeted) {
        const avatar = document.querySelector('.zara-avatar');
        if (avatar) {
            // Pulse animation to draw attention
            avatar.style.animation = 'zara-pulse 1s ease-in-out 3';
            
            // Add pulse animation style
            if (!document.getElementById('zara-pulse-style')) {
                const style = document.createElement('style');
                style.id = 'zara-pulse-style';
                style.textContent = `
                    @keyframes zara-pulse {
                        0%, 100% { transform: scale(1); box-shadow: 0 0 20px rgba(124, 58, 237, 0.5); }
                        50% { transform: scale(1.15); box-shadow: 0 0 40px rgba(124, 58, 237, 0.8); }
                    }
                `;
                document.head.appendChild(style);
            }
            
            // Show notification badge
            showNotificationBadge();
        }
    }
}

// Show notification badge
function showNotificationBadge() {
    const avatar = document.querySelector('.zara-avatar');
    if (avatar && !avatar.querySelector('.notification-badge')) {
        const badge = document.createElement('div');
        badge.className = 'notification-badge';
        badge.textContent = '1';
        badge.style.cssText = `
            position: absolute;
            top: -5px;
            right: -5px;
            background: #ff6b9d;
            color: white;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            font-size: 12px;
            font-weight: bold;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: badge-bounce 0.5s ease;
        `;
        avatar.appendChild(badge);
        
        // Add bounce animation
        if (!document.getElementById('badge-bounce-style')) {
            const style = document.createElement('style');
            style.id = 'badge-bounce-style';
            style.textContent = `
                @keyframes badge-bounce {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.3); }
                }
            `;
            document.head.appendChild(style);
        }
    }
}

// Remove notification badge
function removeNotificationBadge() {
    const badge = document.querySelector('.notification-badge');
    if (badge) badge.remove();
}

// Get greeting message
function getGreeting() {
    return `Hi! I'm Zara, your AI guide! 👋✨

I see you're checking out NVME. Want to see how creators like you are earning **$500+/week** creating content?

Ask me anything about earning money, our AI tools, or how to get started! 🚀`;
}

// Add message to chat
function addZaraMessage(text) {
    const messages = document.getElementById('chatMessages');
    if (!messages) return;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message zara';
    
    // Simple markdown-like formatting
    text = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    text = text.replace(/\n/g, '<br>');
    
    messageDiv.innerHTML = text;
    messages.appendChild(messageDiv);
    messages.scrollTop = messages.scrollHeight;
}

// Add user message to chat
function addUserMessage(text) {
    const messages = document.getElementById('chatMessages');
    if (!messages) return;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message user';
    messageDiv.textContent = text;
    messages.appendChild(messageDiv);
    messages.scrollTop = messages.scrollHeight;
}

// Get Zara response based on user input
function getZaraResponse(input) {
    const lowerInput = input.toLowerCase();
    
    if (lowerInput.includes('earn') || lowerInput.includes('money') || lowerInput.includes('income') || lowerInput.includes('payment')) {
        return zaraResponses['earn'];
    }
    if (lowerInput.includes('how') && (lowerInput.includes('work') || lowerInput.includes('start') || lowerInput.includes('begin'))) {
        return zaraResponses['how it works'];
    }
    if (lowerInput.includes('price') || lowerInput.includes('cost') || lowerInput.includes('plan') || lowerInput.includes('subscription') || lowerInput.includes('free')) {
        return zaraResponses['price'];
    }
    if (lowerInput.includes('help') || lowerInput.includes('support') || lowerInput.includes('question')) {
        return zaraResponses['help'];
    }
    if (lowerInput.includes('video') || lowerInput.includes('ai') || lowerInput.includes('generator') || lowerInput.includes('create')) {
        return zaraResponses['video'];
    }
    if (lowerInput.includes('gift') || lowerInput.includes('present') || lowerInput.includes('reward') || lowerInput.includes('tip')) {
        return zaraResponses['gift'];
    }
    if (lowerInput.includes('hi') || lowerInput.includes('hello') || lowerInput.includes('hey')) {
        return `Hey there! 👋 Great to meet you!

I'm here to help you discover how NVME can change your creator journey. What would you like to know about?

💰 Earning money | 🎬 AI tools | 💎 Pricing | 🎁 Gifts`;
    }
    if (lowerInput.includes('thank')) {
        return `You're welcome! 🌟

If you're ready to start earning, just click that big beautiful button above! I'll be here if you have more questions! 💜`;
    }
    
    return zaraResponses['default'];
}

// Send message
function sendMessage() {
    const input = document.getElementById('userInput');
    if (!input) return;
    
    const text = input.value.trim();
    if (!text) return;
    
    addUserMessage(text);
    input.value = '';
    
    // Simulate typing delay
    setTimeout(() => {
        const response = getZaraResponse(text);
        addZaraMessage(response);
    }, 500 + Math.random() * 1000);
}

// Initialize Zara chat
function initZara() {
    const input = document.getElementById('userInput');
    if (input) {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }
    
    // Auto-greet after 3 seconds
    setTimeout(showZaraGreeting, 3000);
    
    // Auto-open chat after 5 seconds if not interacted
    setTimeout(() => {
        if (!zaraChatOpen && !hasGreeted) {
            toggleZaraChat();
        }
    }, 5000);
}

// Run on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initZara);
} else {
    initZara();
}
