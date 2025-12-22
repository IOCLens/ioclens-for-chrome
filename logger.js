/**
 * Centralized Debug Logger
 * Logs all API calls, responses, errors, and UI updates to chrome.storage
 */

const Logger = {
  LOG_STORAGE_KEY: 'debug_logs',
  MAX_LOG_ENTRIES: 500,
  enabled: true,

  /**
   * Initialize logger and clear old logs if needed
   */
  async init() {
    const result = await chrome.storage.local.get([this.LOG_STORAGE_KEY]);
    if (!result[this.LOG_STORAGE_KEY]) {
      await this._saveLogs([]);
    }
    await this.log('SYSTEM', 'Logger initialized');
  },

  /**
   * Main logging function
   */
  async log(category, message, data = null) {
    if (!this.enabled) return;

    // Check debug mode setting
    const debugMode = await this._isDebugModeEnabled();
    if (!debugMode) return;

    // Check if chrome.storage is available
    if (!chrome?.storage?.local) {
      console.warn('[Logger] Chrome storage not available, skipping log');
      return;
    }

    // SECURITY: Sanitize BEFORE logging to console to prevent API key leakage
    const sanitizedData = data ? this._sanitizeData(data) : null;

    const entry = {
      timestamp: new Date().toISOString(),
      time: Date.now(),
      category: category.toUpperCase(),
      message,
      data: sanitizedData
    };

    // Log sanitized data to console (API keys already redacted)
    console.log(`[${entry.category}] ${message}`, sanitizedData || '');

    try {
      const logs = await this._getLogs();
      logs.push(entry);

      // Keep only last MAX_LOG_ENTRIES
      while (logs.length > this.MAX_LOG_ENTRIES) {
        logs.shift();
      }

      await this._saveLogs(logs);
    } catch (error) {
      console.error('[Logger] Failed to save log:', error);
    }
  },

  async logAPIRequest(apiName, url, options = {}) {
    await this.log('API_REQUEST', `${apiName} - Starting request`, {
      api: apiName, url, method: options.method || 'GET',
      headers: this._sanitizeHeaders(options.headers),
      body: options.body?.substring(0, 200) ?? null
    });
  },

  async logAPIResponse(apiName, success, data, duration = null) {
    await this.log(
      success ? 'API_RESPONSE' : 'API_ERROR',
      `${apiName} - ${success ? 'Success' : 'Failed'}${duration ? ` (${duration}ms)` : ''}`,
      { api: apiName, success, dataPreview: this._truncateData(data), duration }
    );
  },

  async logAPIError(apiName, error, context = null) {
    await this.log('API_ERROR', `${apiName} - Error: ${error.message}`, {
      api: apiName, error: error.message, stack: error.stack, context
    });
  },

  async logCache(action, key, hit = null) {
    await this.log('CACHE', `${action} - ${key}`, { action, key, hit });
  },

  async logUI(action, details = null) {
    await this.log('UI', action, details);
  },

  async logIOC(action, ioc, result = null) {
    await this.log('IOC', action, { ioc, result });
  },

  async logEnrichment(phase, details = null) {
    await this.log('ENRICHMENT', phase, details);
  },

  async getLogs() {
    return await this._getLogs();
  },

  async clearLogs() {
    await this._saveLogs([]);
    await this.log('SYSTEM', 'Logs cleared by user');
  },

  /**
   * Export logs as JSON file
   */
  async exportLogs() {
    const logs = await this._getLogs();

    // SECURITY: Deep sanitize all logs before export to prevent API key leakage
    const sanitizedLogs = logs.map(entry => ({
      ...entry,
      data: this._deepSanitize(entry.data)
    }));

    const blob = new Blob([JSON.stringify(sanitizedLogs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-intel-logs-${timestamp}.json`;
    a.click();

    URL.revokeObjectURL(url);
    await this.log('SYSTEM', 'Logs exported (sanitized)');
  },

  /**
   * Export logs as readable text file
   */
  async exportLogsText() {
    const logs = await this._getLogs();

    // SECURITY: Deep sanitize all logs before export
    const text = logs.map(entry => {
      const sanitizedData = this._deepSanitize(entry.data);
      let line = `[${entry.timestamp}] [${entry.category}] ${entry.message}`;
      if (sanitizedData) {
        line += '\n  Data: ' + JSON.stringify(sanitizedData, null, 2).split('\n').join('\n  ');
      }
      return line;
    }).join('\n\n');

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-intel-logs-${timestamp}.txt`;
    a.click();

    URL.revokeObjectURL(url);
    await this.log('SYSTEM', 'Logs exported as text (sanitized)');
  },

  async getLogsByCategory(category) {
    return (await this._getLogs()).filter(e => e.category === category.toUpperCase());
  },

  async getRecentLogs(count = 50) {
    return (await this._getLogs()).slice(-count);
  },

  async getLogsByTimeRange(startTime, endTime) {
    return (await this._getLogs()).filter(e => e.time >= startTime && e.time <= endTime);
  },

  // ============================================================================
  // PRIVATE METHODS
  // ============================================================================

  async _getLogs() {
    if (!chrome?.storage?.local) {
      console.warn('[Logger] Chrome storage not available');
      return [];
    }
    try {
      const result = await chrome.storage.local.get([this.LOG_STORAGE_KEY]);
      return result[this.LOG_STORAGE_KEY] || [];
    } catch (error) {
      console.error('[Logger] Failed to get logs:', error);
      return [];
    }
  },

  async _saveLogs(logs) {
    if (!chrome?.storage?.local) {
      console.warn('[Logger] Chrome storage not available');
      return;
    }
    try {
      await chrome.storage.local.set({ [this.LOG_STORAGE_KEY]: logs });
    } catch (error) {
      console.error('[Logger] Failed to save logs:', error);
    }
  },

  async _isDebugModeEnabled() {
    try {
      const { apiConfig } = await chrome.storage.local.get(['apiConfig']);
      return apiConfig?.debugMode || false;
    } catch (error) {
      return false; // Default to disabled if error
    }
  },

  _sanitizeData(data) {
    if (!data) return null;

    // Clone data to avoid modifying original
    const cloned = JSON.parse(JSON.stringify(data));

    // Remove sensitive keys
    if (cloned.headers) {
      this._sanitizeHeaders(cloned.headers);
    }

    return cloned;
  },

  _sanitizeHeaders(headers) {
    if (!headers) return headers;
    const sanitized = { ...headers };
    const sensitiveKeys = ['x-apikey', 'key', 'authorization', 'api-key', 'x-otx-api-key', 'API-KEY', 'auth-key'];
    sensitiveKeys.forEach(key => {
      [key, key.toLowerCase()].forEach(k => {
        if (sanitized[k]) sanitized[k] = '***REDACTED***';
      });
    });
    return sanitized;
  },

  /**
   * Deep sanitize recursively removes all sensitive data from objects
   * Used for exports to prevent API key leakage in error messages, URLs, bodies, etc.
   */
  _deepSanitize(obj) {
    if (!obj) return null;

    // Clone to avoid modifying original
    const cloned = JSON.parse(JSON.stringify(obj));

    // Patterns that identify sensitive data
    const sensitivePatterns = [
      /api[_-]?key/i,
      /x-apikey/i,
      /authorization/i,
      /bearer/i,
      /token/i,
      /secret/i,
      /password/i,
      /key=/i,  // URL params like ?key=
      /apikey=/i
    ];

    const redact = (o) => {
      if (typeof o === 'string') {
        // Redact sensitive data in strings (URLs, bodies, error messages)
        let result = o;
        sensitivePatterns.forEach(pattern => {
          // Match patterns like "key=value", "apikey: value", "token=abc123"
          result = result.replace(
            new RegExp(`(${pattern.source})([=:\\s]+)([^&\\s,}"']+)`, 'gi'),
            '$1$2***REDACTED***'
          );
        });
        return result;
      }

      if (Array.isArray(o)) {
        return o.map(redact);
      }

      if (typeof o === 'object' && o !== null) {
        for (const [key, value] of Object.entries(o)) {
          // Redact entire value if key matches sensitive pattern
          if (sensitivePatterns.some(p => p.test(key))) {
            o[key] = '***REDACTED***';
          } else {
            // Recursively sanitize nested objects
            o[key] = redact(value);
          }
        }
      }

      return o;
    };

    return redact(cloned);
  },

  _truncateData(data, maxLength = 500) {
    if (!data) return null;

    const str = typeof data === 'string' ? data : JSON.stringify(data);
    if (str.length <= maxLength) return data;

    return {
      _truncated: true,
      preview: str.substring(0, maxLength) + '...',
      originalLength: str.length
    };
  }
};

// Auto-initialize on load
if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
  Logger.init().catch(err => console.error('[Logger] Init failed:', err));
} else {
  console.warn('[Logger] Chrome storage API not available yet, will initialize on first use');
}
