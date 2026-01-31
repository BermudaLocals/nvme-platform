// NVME Platform - Main JavaScript Application

const NVME = {
  // API Configuration
  config: {
    apiUrl: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'http://localhost:3000/api'
      : '/api',
    tokenKey: 'nvme_token',
    userKey: 'nvme_user'
  },

  // Current user state
  currentUser: null,

  // API Methods
  api: {
    async request(endpoint, options = {}) {
      const url = `${NVME.config.apiUrl}${endpoint}`;
      const headers = {
        'Content-Type': 'application/json',
        ...options.headers
      };

      // Add auth token if available
      const token = localStorage.getItem(NVME.config.tokenKey);
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      try {
        const response = await fetch(url, {
          ...options,
          headers,
          credentials: 'include'
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.error || data.message || 'Request failed');
        }

        return data;
      } catch (error) {
        console.error('API Error:', error);
        throw error;
      }
    },

    get(endpoint) {
      return this.request(endpoint, { method: 'GET' });
    },

    post(endpoint, data) {
      return this.request(endpoint, {
        method: 'POST',
        body: JSON.stringify(data)
      });
    },

    put(endpoint, data) {
      return this.request(endpoint, {
        method: 'PUT',
        body: JSON.stringify(data)
      });
    },

    delete(endpoint) {
      return this.request(endpoint, { method: 'DELETE' });
    },

    // Upload file
    async upload(endpoint, formData) {
      const url = `${NVME.config.apiUrl}${endpoint}`;
      const token = localStorage.getItem(NVME.config.tokenKey);
      const headers = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: formData,
        credentials: 'include'
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Upload failed');
      }
      return data;
    }
  },

  // Authentication
  auth: {
    async login(email, password) {
      const data = await NVME.api.post('/auth/login', { email, password });
      if (data.token) {
        localStorage.setItem(NVME.config.tokenKey, data.token);
        localStorage.setItem(NVME.config.userKey, JSON.stringify(data.user));
        NVME.currentUser = data.user;
      }
      return data;
    },

    async signup(userData) {
      const data = await NVME.api.post('/auth/signup', userData);
      if (data.token) {
        localStorage.setItem(NVME.config.tokenKey, data.token);
        localStorage.setItem(NVME.config.userKey, JSON.stringify(data.user));
        NVME.currentUser = data.user;
      }
      return data;
    },

    async logout() {
      try {
        await NVME.api.post('/auth/logout');
      } catch (e) {
        // Ignore errors
      }
      localStorage.removeItem(NVME.config.tokenKey);
      localStorage.removeItem(NVME.config.userKey);
      NVME.currentUser = null;
      window.location.href = '/login.html';
    },

    async checkAuth() {
      const token = localStorage.getItem(NVME.config.tokenKey);
      const userStr = localStorage.getItem(NVME.config.userKey);

      if (!token || !userStr) {
        return false;
      }

      try {
        NVME.currentUser = JSON.parse(userStr);
        // Verify token is still valid
        const data = await NVME.api.get('/auth/me');
        NVME.currentUser = data.user;
        localStorage.setItem(NVME.config.userKey, JSON.stringify(data.user));
        NVME.updateUserUI();
        return true;
      } catch (error) {
        // Token invalid, clear storage
        localStorage.removeItem(NVME.config.tokenKey);
        localStorage.removeItem(NVME.config.userKey);
        NVME.currentUser = null;
        return false;
      }
    },

    getUser() {
      if (NVME.currentUser) return NVME.currentUser;
      const userStr = localStorage.getItem(NVME.config.userKey);
      if (userStr) {
        NVME.currentUser = JSON.parse(userStr);
        return NVME.currentUser;
      }
      return null;
    },

    isLoggedIn() {
      return !!localStorage.getItem(NVME.config.tokenKey);
    }
  },

  // Update user UI elements
  updateUserUI() {
    const user = NVME.currentUser;
    if (!user) return;

    // Update user menu visibility
    document.querySelectorAll('.user-menu').forEach(el => {
      el.classList.remove('hidden');
    });
    document.querySelectorAll('.auth-buttons').forEach(el => {
      el.classList.add('hidden');
    });

    // Update user info
    document.querySelectorAll('.user-name').forEach(el => {
      el.textContent = user.display_name || user.username || 'User';
    });
    document.querySelectorAll('.user-avatar').forEach(el => {
      el.src = user.avatar_url || '/img/default-avatar.png';
    });
    document.querySelectorAll('.user-coins').forEach(el => {
      el.textContent = NVME.formatNumber(user.coins || 0);
    });
  },

  // Toast Notifications
  toast: {
    container: null,

    init() {
      if (!this.container) {
        this.container = document.createElement('div');
        this.container.className = 'toast-container';
        document.body.appendChild(this.container);
      }
    },

    show(message, type = 'info', duration = 4000) {
      this.init();

      const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
      };

      const toast = document.createElement('div');
      toast.className = `toast ${type}`;
      toast.innerHTML = `
        <span class="toast-icon">${icons[type]}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
      `;

      this.container.appendChild(toast);

      // Auto remove
      setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
      }, duration);
    },

    success(message) { this.show(message, 'success'); },
    error(message) { this.show(message, 'error'); },
    warning(message) { this.show(message, 'warning'); },
    info(message) { this.show(message, 'info'); }
  },

  // Modal Management
  modal: {
    show(id) {
      const modal = document.getElementById(id);
      if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
      }
    },

    hide(id) {
      const modal = document.getElementById(id);
      if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
      }
    },

    hideAll() {
      document.querySelectorAll('.modal-overlay').forEach(modal => {
        modal.classList.remove('active');
      });
      document.body.style.overflow = '';
    }
  },

  // Loading State
  loading: {
    show(message = 'Loading...') {
      let overlay = document.getElementById('loadingOverlay');
      if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loadingOverlay';
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
          <div class="spinner spinner-lg"></div>
          <div class="loading-text">${message}</div>
        `;
        document.body.appendChild(overlay);
      } else {
        overlay.querySelector('.loading-text').textContent = message;
        overlay.style.display = 'flex';
      }
    },

    hide() {
      const overlay = document.getElementById('loadingOverlay');
      if (overlay) {
        overlay.style.display = 'none';
      }
    }
  },

  // Utility Functions
  formatNumber(num) {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
  },

  formatDate(date) {
    const d = new Date(date);
    return d.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  },

  formatTime(date) {
    const d = new Date(date);
    return d.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit'
    });
  },

  formatRelativeTime(date) {
    const now = new Date();
    const d = new Date(date);
    const diff = now - d;
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (seconds < 60) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return NVME.formatDate(date);
  },

  formatDuration(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  },

  // Debounce function
  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  },

  // Throttle function
  throttle(func, limit) {
    let inThrottle;
    return function(...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  },

  // Copy to clipboard
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      NVME.toast.success('Copied to clipboard!');
      return true;
    } catch (err) {
      NVME.toast.error('Failed to copy');
      return false;
    }
  },

  // Share functionality
  async share(data) {
    if (navigator.share) {
      try {
        await navigator.share(data);
        return true;
      } catch (err) {
        if (err.name !== 'AbortError') {
          console.error('Share failed:', err);
        }
      }
    }
    // Fallback to copy link
    if (data.url) {
      return NVME.copyToClipboard(data.url);
    }
    return false;
  },

  // Generate unique ID
  generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  },

  // Escape HTML
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  // Parse hashtags from text
  parseHashtags(text) {
    const regex = /#(\w+)/g;
    const hashtags = [];
    let match;
    while ((match = regex.exec(text)) !== null) {
      hashtags.push(match[1]);
    }
    return hashtags;
  },

  // Parse mentions from text
  parseMentions(text) {
    const regex = /@(\w+)/g;
    const mentions = [];
    let match;
    while ((match = regex.exec(text)) !== null) {
      mentions.push(match[1]);
    }
    return mentions;
  },

  // Linkify text (hashtags and mentions)
  linkifyText(text) {
    return text
      .replace(/#(\w+)/g, '<a href="/search.html?q=%23$1" class="hashtag">#$1</a>')
      .replace(/@(\w+)/g, '<a href="/profile.html?user=$1" class="mention">@$1</a>');
  },

  // Validate email
  isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  },

  // Validate phone
  isValidPhone(phone) {
    return /^[+]?[\d\s()-]{10,}$/.test(phone);
  },

  // Get URL parameters
  getUrlParams() {
    return Object.fromEntries(new URLSearchParams(window.location.search));
  },

  // Set URL parameter
  setUrlParam(key, value) {
    const url = new URL(window.location);
    url.searchParams.set(key, value);
    window.history.pushState({}, '', url);
  },

  // Local storage helpers
  storage: {
    get(key, defaultValue = null) {
      try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : defaultValue;
      } catch {
        return defaultValue;
      }
    },

    set(key, value) {
      try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
      } catch {
        return false;
      }
    },

    remove(key) {
      localStorage.removeItem(key);
    }
  }
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  // Initialize toast container
  NVME.toast.init();

  // Close modals on overlay click
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.classList.remove('active');
        document.body.style.overflow = '';
      }
    });
  });

  // Close modals on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      NVME.modal.hideAll();
    }
  });

  // Setup logout buttons
  document.querySelectorAll('.logout-btn').forEach(btn => {
    btn.addEventListener('click', () => NVME.auth.logout());
  });

  // Setup dropdown toggles
  document.querySelectorAll('.dropdown-toggle').forEach(toggle => {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const dropdown = toggle.closest('.dropdown');
      dropdown.classList.toggle('active');
    });
  });

  // Close dropdowns on outside click
  document.addEventListener('click', () => {
    document.querySelectorAll('.dropdown.active').forEach(dropdown => {
      dropdown.classList.remove('active');
    });
  });

  // Check auth status and update UI
  if (NVME.auth.isLoggedIn()) {
    NVME.auth.checkAuth();
  }
});

// Export for use in other scripts
window.NVME = NVME;
