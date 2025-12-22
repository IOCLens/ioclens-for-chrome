/**
 * Background Service Worker (Manifest V3)
 */

// Import logger - available globally via importScripts in service worker
importScripts('logger.js');

// Rate limiting: Token bucket implementation
const RATE_LIMITER = {
  maxTokens: 40, // Below ip-api.com limit of 45 req/min
  tokens: 40,
  refillRate: 40 / 60, // tokens per second (40 per minute)
  lastRefill: Date.now(),

  async consumeToken() {
    this.refill();

    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }

    await Logger.log('RATE_LIMIT', 'Rate limit reached, request blocked', {
      tokensAvailable: this.tokens,
      maxTokens: this.maxTokens
    });
    return false;
  },

  refill() {
    const now = Date.now();
    const timePassed = (now - this.lastRefill) / 1000; // in seconds
    const tokensToAdd = timePassed * this.refillRate;

    this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd);
    this.lastRefill = now;
  },

  getStatus() {
    this.refill();
    return {
      available: Math.floor(this.tokens),
      max: this.maxTokens,
      percentage: Math.floor((this.tokens / this.maxTokens) * 100)
    };
  }
};

// IOC validation patterns - hardened against ReDoS
// Max input length to prevent catastrophic backtracking
const MAX_IOC_LENGTH = 500;

const IOC_PATTERNS = {
  // IPv4: Simple pattern without nested quantifiers
  // No anchors - allows extraction from larger text
  ipv4: /(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/,

  // URL: Simplified pattern with bounded quantifiers
  url: /(?:https?|ftp):\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,10}\.[a-z]{2,}(?::[0-9]{1,5})?(?:\/[^\s]{0,2048})?/i,

  // Domain: Simplified with explicit limits (max 10 subdomains to prevent catastrophic backtracking)
  domain: /[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,10}\.(?:[a-z]{2,}|onion)/i,

  // SHA256 hash: 64 hexadecimal characters
  sha256: /^[a-f0-9]{64}$/i,

  // Defanged patterns with bounded repetitions
  defangedUrl: /h[xX]{2}p[s]?(?:\[:\]|:)\/\/[^\s]{1,500}/,
  defangedDomain: /[a-z0-9-]{1,63}(?:\[\.\]|\.)[a-z0-9-]{1,63}(?:\[\.\]|\.)(?:[a-z]{2,}|onion)/i
};

const PRIVATE_IP_RANGES = [
  { min: [127, 0, 0, 0], max: [127, 255, 255, 255], name: 'Loopback' },
  { min: [10, 0, 0, 0], max: [10, 255, 255, 255], name: 'RFC1918 Class A' },
  { min: [172, 16, 0, 0], max: [172, 31, 255, 255], name: 'RFC1918 Class B' },
  { min: [192, 168, 0, 0], max: [192, 168, 255, 255], name: 'RFC1918 Class C' },
  { min: [169, 254, 0, 0], max: [169, 254, 255, 255], name: 'Link-local' },
  { min: [224, 0, 0, 0], max: [239, 255, 255, 255], name: 'Multicast' },
  { min: [240, 0, 0, 0], max: [255, 255, 255, 254], name: 'Reserved' }
];

const DEFANG_REPLACEMENTS = [[/h[xX]{2}p/g, 'http'], [/\[:\]/g, ':'], [/\[\.\]/g, '.'], [/\[dot\]/g, '.']];

const isPrivateIP = (ip) => {
  if (ip === '255.255.255.255') return true;
  const parts = ip.split('.').map(Number);
  return PRIVATE_IP_RANGES.some(range => parts.every((p, i) => p >= range.min[i] && p <= range.max[i]));
};

const refangIOC = (text) => DEFANG_REPLACEMENTS.reduce((acc, [pattern, repl]) => acc.replace(pattern, repl), text.toLowerCase());

const extractDomainFromURL = (url) => {
  try {
    return new URL(refangIOC(url)).hostname;
  } catch {
    return url.match(/(?:https?|ftp):\/\/([^/:?\s]+)/i)?.[1] ?? null;
  }
};

function validateIOC(text) {
  if (!text) return { valid: false, reason: 'empty' };
  let cleaned = text.trim();

  // SECURITY: Prevent ReDoS by limiting input length
  if (cleaned.length > MAX_IOC_LENGTH) {
    console.warn('[SOC Extension] Input too long, rejecting to prevent ReDoS:', cleaned.length);
    Logger.logIOC('Input rejected - too long', { length: cleaned.length, maxLength: MAX_IOC_LENGTH });
    return { valid: false, reason: 'too_long', text: cleaned };
  }

  if (IOC_PATTERNS.defangedUrl.test(cleaned) || IOC_PATTERNS.defangedDomain.test(cleaned)) {
    console.log('[SOC Extension] Defanged IOC detected, automatic cleaning');
    Logger.logIOC('Defanged IOC detected, refanging', { original: text, cleaned });
    cleaned = refangIOC(cleaned);
  }

  // IPv4 validation
  const ipMatch = cleaned.match(IOC_PATTERNS.ipv4);
  if (ipMatch) {
    const ip = ipMatch[0];
    if (isPrivateIP(ip)) {
      console.warn('[SOC Extension] Private/reserved IP detected and rejected:', ip);
      Logger.logIOC('Private IP rejected', { ip, original: text });
      return { valid: false, reason: 'private_ip', text: ip };
    }
    Logger.logIOC('IPv4 validated', { ip, original: text });
    return { valid: true, type: 'ipv4', value: ip };
  }

  // URL validation
  const urlMatch = cleaned.match(IOC_PATTERNS.url);
  if (urlMatch) {
    const url = urlMatch[0];
    const domain = extractDomainFromURL(url);
    if (domain) {
      console.log('[SOC Extension] URL detected, extracting domain:', domain);
      Logger.logIOC('URL validated, domain extracted', { url, domain, original: text });
      return { valid: true, type: 'url', value: url, domain };
    }
  }

  // Domain validation
  const domainMatch = cleaned.match(IOC_PATTERNS.domain);
  if (domainMatch) {
    const domain = domainMatch[0];
    console.log('[SOC Extension] Domain extracted:', domain);
    Logger.logIOC('Domain validated', { domain, original: text });
    return { valid: true, type: 'domain', value: domain };
  }

  // SHA256 hash validation
  const sha256Match = cleaned.match(IOC_PATTERNS.sha256);
  if (sha256Match) {
    const hash = sha256Match[0].toLowerCase();
    console.log('[SOC Extension] SHA256 hash detected:', hash);
    Logger.logIOC('SHA256 validated', { hash, original: text });
    return { valid: true, type: 'sha256', value: hash };
  }

  Logger.logIOC('Validation failed - not a valid IOC', { text });
  return { valid: false, reason: 'invalid_format', text: cleaned };
}

// Version tracking
const CURRENT_VERSION = chrome.runtime.getManifest().version;

chrome.runtime.onInstalled.addListener(async (details) => {
  chrome.contextMenus.create({ id: 'enrichIOC', title: 'Enrich IOC: "%s"', contexts: ['selection'] });

  const handlers = {
    install: async () => {
      // New installation - record version
      const installData = {
        installDate: Date.now(),
        version: CURRENT_VERSION,
        installType: 'fresh_install'
      };
      await chrome.storage.local.set({ installData });
      console.log('[SOC Extension] New installation registered:', installData);
      await Logger.log('SYSTEM', 'Extension installed', installData);
    },
    update: async () => {
      const { installData } = await chrome.storage.local.get(['installData']);

      if (!installData) {
        // User updating from older version - create install data
        const data = {
          installDate: Date.now(),
          version: CURRENT_VERSION,
          installType: 'update_from_legacy'
        };
        await chrome.storage.local.set({ installData: data });
        console.log('[SOC Extension] Extension updated - install data created:', data);
        await Logger.log('SYSTEM', 'Extension updated - install data created', data);
      } else {
        // User already has installData, just update version
        installData.version = CURRENT_VERSION;
        await chrome.storage.local.set({ installData });
        console.log('[SOC Extension] Extension updated from', details.previousVersion, 'to', CURRENT_VERSION);
        await Logger.log('SYSTEM', 'Extension updated', { from: details.previousVersion, to: CURRENT_VERSION });
      }
    }
  };

  await handlers[details.reason]?.();
  console.log('[SOC Extension] Extension installed and context menu created');
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'enrichIOC') {
    const selectedText = info.selectionText;
    await Logger.log('CONTEXT_MENU', 'User selected text for enrichment', { selectedText });

    const validation = validateIOC(selectedText);

    if (!validation.valid) {
      console.error('[SOC Extension] Selected text is not a valid IOC:', selectedText);
      await Logger.log('ERROR', 'Invalid IOC selected', { selectedText, reason: validation.reason });

      // Prepare notification message based on rejection reason
      const truncatedText = (validation.text || selectedText).length > 50
        ? (validation.text || selectedText).substring(0, 50) + '...'
        : (validation.text || selectedText);

      let title = '❌ Invalid IOC';
      let message = '';

      switch (validation.reason) {
        case 'private_ip':
          title = '⚠️ Private IP Address';
          message = `"${truncatedText}" is a private/reserved IP address.\n\nPrivate IPs cannot be enriched with threat intelligence.\n\nExamples of private IPs:\n• 10.x.x.x\n• 172.16-31.x.x\n• 192.168.x.x\n• 127.x.x.x (localhost)`;
          break;
        case 'too_long':
          title = '❌ Text Too Long';
          message = `Selected text is too long (max ${MAX_IOC_LENGTH} characters).\n\nPlease select only the IOC itself.`;
          break;
        default:
          message = `"${truncatedText}" is not a valid IOC.\n\nSupported types:\n• Public IPv4 addresses (e.g., 8.8.8.8)\n• Domains (e.g., example.com)\n• URLs (e.g., https://example.com)\n• SHA256 hashes (64 hex characters)`;
      }

      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: title,
        message: message,
        priority: 1
      });

      return;
    }

    // Extract IOC data from validation result
    const ioc = {
      type: validation.type,
      value: validation.value,
      domain: validation.domain
    };

    console.log('[SOC Extension] IOC detected:', ioc);
    await Logger.log('CONTEXT_MENU', 'IOC validated, opening popup', { ioc });

    // CRITICAL: Await storage write to prevent race condition
    // The popup can open before IOC data is saved, causing "No IOC selected" error
    await chrome.storage.local.set({
      currentIOC: ioc,
      timestamp: Date.now()
    });

    // Open popup only after data is persisted
    chrome.action.openPopup();
  }
});

// Helper function for async rate limit check
async function handleAsyncRateLimit(sendResponse) {
  try {
    const allowed = await RATE_LIMITER.consumeToken();
    const status = RATE_LIMITER.getStatus();
    sendResponse({ allowed, status });
  } catch (error) {
    console.error('[Rate Limit] Error:', error);
    await Logger.log('ERROR', 'Rate limit check failed', { error: error.message });
    sendResponse({ allowed: false, error: error.message });
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // SECURITY: Only accept messages from extension pages, not external sources
  // This prevents malicious webpages or other extensions from:
  // - Spamming rate limit checks (DoS attack)
  // - Enumerating extension functionality
  // - Fingerprinting extension presence
  if (!sender.id || sender.id !== chrome.runtime.id) {
    console.warn('[Security] Rejected message from untrusted sender:', sender);
    sendResponse({ error: 'Unauthorized - messages only accepted from extension pages' });
    return false;
  }

  if (request.action === 'validateIOC') {
    const validation = validateIOC(request.text);
    if (validation.valid) {
      const ioc = {
        type: validation.type,
        value: validation.value,
        domain: validation.domain
      };
      sendResponse({ valid: true, ioc: ioc });
    } else {
      sendResponse({ valid: false, ioc: null, reason: validation.reason });
    }
    return false;
  } else if (request.action === 'checkRateLimit') {
    handleAsyncRateLimit(sendResponse);
    return true;
  } else if (request.action === 'getRateLimitStatus') {
    sendResponse({ status: RATE_LIMITER.getStatus() });
    return false;
  }

  return false;
});
