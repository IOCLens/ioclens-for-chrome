/**
 * Persistent Rate Limiter - Token Bucket Implementation
 *
 * IMPORTANT: This rate limiter persists state in chrome.storage.local
 * to prevent quota exhaustion across Service Worker restarts.
 *
 * Chrome Manifest V3 Service Workers can be terminated at any time,
 * causing in-memory rate limiters to lose their state. This implementation
 * solves that problem by storing the bucket state persistently.
 *
 * Algorithm: Token Bucket
 * - Tokens refill continuously over time
 * - Each API call consumes 1 token
 * - Requests are blocked if no tokens available
 *
 * Target: ip-api.com free tier (45 requests/minute)
 * Safe limit: 40 requests/minute (with 5 req/min buffer)
 */

const RateLimiter = {
  // Configuration
  MAX_TOKENS: 40,                    // Maximum bucket capacity
  REFILL_RATE: 40 / 60,             // Tokens per second (40 per minute)
  STORAGE_KEY: 'rateLimiterState',  // Storage key for persistence

  /**
   * Load rate limiter state from storage
   * @returns {Promise<Object>} Rate limiter state
   */
  async loadState() {
    try {
      const result = await chrome.storage.local.get([this.STORAGE_KEY]);

      if (result[this.STORAGE_KEY]) {
        return result[this.STORAGE_KEY];
      }

      // Initialize new state
      const newState = {
        tokens: this.MAX_TOKENS,
        lastRefill: Date.now()
      };

      await this.saveState(newState);
      return newState;

    } catch (error) {
      console.error('[RateLimiter] Failed to load state:', error);
      // Return fresh state on error
      return {
        tokens: this.MAX_TOKENS,
        lastRefill: Date.now()
      };
    }
  },

  /**
   * Save rate limiter state to storage
   * @param {Object} state - State to save
   */
  async saveState(state) {
    try {
      await chrome.storage.local.set({
        [this.STORAGE_KEY]: state
      });
    } catch (error) {
      console.error('[RateLimiter] Failed to save state:', error);
    }
  },

  /**
   * Refill tokens based on time elapsed
   * @param {Object} state - Current state
   * @returns {Object} Updated state
   */
  refill(state) {
    const now = Date.now();
    const timePassed = (now - state.lastRefill) / 1000; // Convert to seconds
    const tokensToAdd = timePassed * this.REFILL_RATE;

    return {
      tokens: Math.min(this.MAX_TOKENS, state.tokens + tokensToAdd),
      lastRefill: now
    };
  },

  /**
   * Attempt to consume a token
   * @returns {Promise<{allowed: boolean, status: Object}>}
   */
  async consumeToken() {
    let state = await this.loadState();

    // Refill tokens based on time elapsed
    state = this.refill(state);

    if (state.tokens >= 1) {
      // Token available - consume it
      state.tokens -= 1;
      await this.saveState(state);

      return {
        allowed: true,
        status: this.getStatus(state)
      };
    } else {
      // No tokens available - rate limit exceeded
      await this.saveState(state);

      return {
        allowed: false,
        status: this.getStatus(state)
      };
    }
  },

  /**
   * Get current rate limiter status
   * @param {Object} state - Current state (optional, will load if not provided)
   * @returns {Promise<Object>} Status object
   */
  async getStatus(state = null) {
    if (!state) {
      state = await this.loadState();
      state = this.refill(state);
    }

    return {
      available: Math.floor(state.tokens),
      max: this.MAX_TOKENS,
      percentage: Math.floor((state.tokens / this.MAX_TOKENS) * 100)
    };
  },

  /**
   * Reset rate limiter (admin function)
   * @returns {Promise<void>}
   */
  async reset() {
    const newState = {
      tokens: this.MAX_TOKENS,
      lastRefill: Date.now()
    };
    await this.saveState(newState);
  }
};

// Export for use in Service Worker
if (typeof self !== 'undefined') {
  self.RateLimiter = RateLimiter;
}
