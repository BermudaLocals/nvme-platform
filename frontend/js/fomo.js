// NVME.live FOMO Landing Page JavaScript

// Countdown Timer
function initCountdown() {
    // Set countdown to 24 hours from now
    const countdownEnd = new Date();
    countdownEnd.setHours(countdownEnd.getHours() + 24);
    
    function updateCountdown() {
        const now = new Date();
        const diff = countdownEnd - now;
        
        if (diff <= 0) {
            // Reset countdown when it ends
            countdownEnd.setHours(countdownEnd.getHours() + 24);
        }
        
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);
        
        const hoursEl = document.querySelector('.countdown .hours');
        const minutesEl = document.querySelector('.countdown .minutes');
        const secondsEl = document.querySelector('.countdown .seconds');
        
        if (hoursEl) hoursEl.textContent = String(hours).padStart(2, '0');
        if (minutesEl) minutesEl.textContent = String(minutes).padStart(2, '0');
        if (secondsEl) secondsEl.textContent = String(seconds).padStart(2, '0');
    }
    
    updateCountdown();
    setInterval(updateCountdown, 1000);
}

// Animated Stat Counters
function animateCounters() {
    const counters = document.querySelectorAll('.stat-number[data-target]');
    
    const observerOptions = {
        threshold: 0.5
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const counter = entry.target;
                const target = parseInt(counter.dataset.target);
                const duration = 2000;
                const start = 0;
                const startTime = performance.now();
                
                function updateCounter(currentTime) {
                    const elapsed = currentTime - startTime;
                    const progress = Math.min(elapsed / duration, 1);
                    
                    // Easing function for smooth animation
                    const easeOutQuart = 1 - Math.pow(1 - progress, 4);
                    const current = Math.floor(start + (target - start) * easeOutQuart);
                    
                    counter.textContent = formatNumber(current);
                    
                    if (progress < 1) {
                        requestAnimationFrame(updateCounter);
                    }
                }
                
                requestAnimationFrame(updateCounter);
                observer.unobserve(counter);
            }
        });
    }, observerOptions);
    
    counters.forEach(counter => observer.observe(counter));
}

// Format large numbers
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(0) + 'K';
    }
    return num.toLocaleString();
}

// Live Activity Feed
const activityData = [
    { user: '@sarah_creates', action: 'earned', amount: '$125', icon: '💰' },
    { user: '@mike_viral', action: 'joined NVME', amount: '', icon: '🎉' },
    { user: '@jenny_ai', action: 'earned', amount: '$340', icon: '💰' },
    { user: '@alex_studio', action: 'uploaded a video', amount: '', icon: '🎬' },
    { user: '@emma_content', action: 'earned', amount: '$89', icon: '💰' },
    { user: '@david_creator', action: 'received 50 gifts', amount: '', icon: '🎁' },
    { user: '@lisa_viral', action: 'earned', amount: '$512', icon: '💰' },
    { user: '@james_ai', action: 'generated AI video', amount: '', icon: '🤖' },
    { user: '@olivia_live', action: 'went live', amount: '', icon: '📡' },
    { user: '@noah_tiktok', action: 'earned', amount: '$267', icon: '💰' }
];

let activityIndex = 0;

function initLiveActivity() {
    const feed = document.getElementById('activityFeed');
    if (!feed) return;
    
    // Add initial activities
    for (let i = 0; i < 5; i++) {
        addActivity(feed, activityData[i % activityData.length]);
    }
    
    // Add new activity every 3-8 seconds
    function scheduleNext() {
        const delay = 3000 + Math.random() * 5000;
        setTimeout(() => {
            activityIndex = (activityIndex + 1) % activityData.length;
            addActivity(feed, activityData[activityIndex]);
            
            // Remove old activities if too many
            while (feed.children.length > 10) {
                feed.removeChild(feed.lastChild);
            }
            
            scheduleNext();
        }, delay);
    }
    
    scheduleNext();
}

function addActivity(feed, data) {
    const item = document.createElement('div');
    item.className = 'activity-item';
    
    const timeAgo = getRandomTimeAgo();
    
    item.innerHTML = `
        <div class="activity-icon">${data.icon}</div>
        <div class="activity-text">
            <strong>${data.user}</strong> ${data.action} ${data.amount ? `<span style="color: #ffd700">${data.amount}</span>` : ''}
        </div>
        <div class="activity-time">${timeAgo}</div>
    `;
    
    feed.insertBefore(item, feed.firstChild);
}

function getRandomTimeAgo() {
    const options = ['just now', '1m ago', '2m ago', '3m ago', '5m ago'];
    return options[Math.floor(Math.random() * options.length)];
}

// Spots Counter (decreasing)
function initSpotsCounter() {
    let spotsLeft = 247;
    const spotsEl = document.querySelector('.spots-number');
    
    if (!spotsEl) return;
    
    function decreaseSpots() {
        if (spotsLeft > 50) {
            spotsLeft -= Math.floor(Math.random() * 3) + 1;
            spotsEl.textContent = spotsLeft;
        }
    }
    
    // Decrease every 30-60 seconds
    setInterval(decreaseSpots, 30000 + Math.random() * 30000);
}

// Today's Signups Counter
function initSignupsCounter() {
    let signups = 1247;
    const signupsEl = document.getElementById('todaysSignups');
    
    if (!signupsEl) return;
    
    function increaseSignups() {
        signups += Math.floor(Math.random() * 3) + 1;
        signupsEl.textContent = signups.toLocaleString();
    }
    
    // Increase every 20-40 seconds
    setInterval(increaseSignups, 20000 + Math.random() * 20000);
}

// Scroll Animations
function initScrollAnimations() {
    const elements = document.querySelectorAll('.feature-locked, .testimonial-card, .final-cta');
    
    elements.forEach(el => el.classList.add('fade-in'));
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, { threshold: 0.1 });
    
    elements.forEach(el => observer.observe(el));
}

// Ripple Effect on Button Click
function initRippleEffect() {
    const buttons = document.querySelectorAll('.access-btn');
    
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            const ripple = document.createElement('span');
            ripple.style.cssText = `
                position: absolute;
                background: rgba(255, 255, 255, 0.4);
                border-radius: 50%;
                transform: scale(0);
                animation: ripple 0.6s linear;
                pointer-events: none;
            `;
            
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = (e.clientX - rect.left - size / 2) + 'px';
            ripple.style.top = (e.clientY - rect.top - size / 2) + 'px';
            
            this.style.position = 'relative';
            this.style.overflow = 'hidden';
            this.appendChild(ripple);
            
            setTimeout(() => ripple.remove(), 600);
            
            // Redirect to signup
            setTimeout(() => {
                window.location.href = 'signup.html';
            }, 300);
        });
    });
    
    // Add ripple animation to CSS
    if (!document.getElementById('ripple-style')) {
        const style = document.createElement('style');
        style.id = 'ripple-style';
        style.textContent = `
            @keyframes ripple {
                to {
                    transform: scale(4);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }
}

// Initialize all FOMO features
function initFOMO() {
    initCountdown();
    animateCounters();
    initLiveActivity();
    initSpotsCounter();
    initSignupsCounter();
    initScrollAnimations();
    initRippleEffect();
}

// Run on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFOMO);
} else {
    initFOMO();
}
