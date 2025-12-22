/**
 * Background Service Worker (Manifest V3) - PRODUCTION VERSION
 *
 * IOCLens - Threat Intelligence Enrichment Extension
 *
 * PRIVACY NOTICE:
 * - All API requests are made directly from your browser to threat intelligence providers
 * - No user data, browsing history, or IOCs are sent to IOCLens servers
 * - API keys are stored encrypted in chrome.storage.local (never synced to Google servers)
 * - License verification only happens when you explicitly activate/deactivate your license
 *
 * SECURITY FEATURES:
 * - ReDoS protection with input length limits
 * - Persistent rate limiting to prevent API quota exhaustion
 * - Message origin validation to prevent malicious webpage exploitation
 * - Private IP blocking to prevent internal network scanning
 * - Encrypted API key storage
 */

// Import required modules (loaded via importScripts in service worker context)
importScripts('rate-limiter.js');

// IOC validation patterns - Hardened against ReDoS
const MAX_IOC_LENGTH = 500; // SECURITY: Prevent ReDoS attacks

const IOC_PATTERNS = {
  // IPv4: Simple pattern without nested quantifiers
  ipv4: /(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/,

  // URL: Simplified pattern with bounded quantifiers
  url: /(?:https?|ftp):\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,10}\.[a-z]{2,}(?::[0-9]{1,5})?(?:\/[^\s]{0,2048})?/i,

  // Domain: Simplified with explicit limits
  domain: /[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,10}\.(?:[a-z]{2,}|onion)/i,

  // SHA256 hash: 64 hexadecimal characters
  sha256: /^[a-f0-9]{64}$/i,

  // Defanged patterns
  defangedUrl: /h[xX]{2}p[s]?(?:\[:\]|:)\/\/[^\s]{1,500}/,
  defangedDomain: /[a-z0-9-]{1,63}(?:\[\.\]|\.)[a-z0-9-]{1,63}(?:\[\.\]|\.)(?:[a-z]{2,}|onion)/i
};

// Private IP ranges (RFC1918 + special use)
const PRIVATE_IP_RANGES = [
  { min: [127, 0, 0, 0], max: [127, 255, 255, 255], name: 'Loopback' },
  { min: [10, 0, 0, 0], max: [10, 255, 255, 255], name: 'RFC1918 Class A' },
  { min: [172, 16, 0, 0], max: [172, 31, 255, 255], name: 'RFC1918 Class B' },
  { min: [192, 168, 0, 0], max: [192, 168, 255, 255], name: 'RFC1918 Class C' },
  { min: [169, 254, 0, 0], max: [169, 254, 255, 255], name: 'Link-local' },
  { min: [224, 0, 0, 0], max: [239, 255, 255, 255], name: 'Multicast' },
  { min: [240, 0, 0, 0], max: [255, 255, 255, 254], name: 'Reserved' }
];

// Defanging replacements
const DEFANG_REPLACEMENTS = [
  [/h[xX]{2}p/g, 'http'],
  [/\\[:\\]/g, ':'],
  [/\\[\\.\\]/g, '.'],
  [/\\[dot\\]/g, '.']
];

/**
 * Check if IP is in private/reserved range
 * SECURITY: Prevent internal network scanning via IOC enrichment
 */
const isPrivateIP = (ip) => {
  if (ip === '255.255.255.255') return true;
  const parts = ip.split('.').map(Number);
  return PRIVATE_IP_RANGES.some(range =>
    parts.every((p, i) => p >= range.min[i] && p <= range.max[i])
  );
};

/**
 * Refang (un-defang) IOC for processing
 */
const refangIOC = (text) =>
  DEFANG_REPLACEMENTS.reduce((acc, [pattern, repl]) =>
    acc.replace(pattern, repl), text.toLowerCase()
  );

/**
 * Extract domain from URL
 */
const extractDomainFromURL = (url) => {
  try {
    return new URL(refangIOC(url)).hostname;
  } catch {
    return url.match(/(?:https?|ftp):\\/\\/([^/:?\\s]+)/i)?.[1] ?? null;
  }
};

/**
 * Validate IOC format and type
 * SECURITY: Input validation to prevent injection attacks
 *
 * @param {string} text - User-selected text to validate
 * @returns {Object} Validation result {valid, type, value, domain, reason}
 */
function validateIOC(text) {
  if (!text) return { valid: false, reason: 'empty' };
  let cleaned = text.trim();

  // SECURITY: Prevent ReDoS by limiting input length
  if (cleaned.length > MAX_IOC_LENGTH) {
    return { valid: false, reason: 'too_long', text: cleaned };
  }

  // Auto-refang defanged IOCs
  if (IOC_PATTERNS.defangedUrl.test(cleaned) || IOC_PATTERNS.defangedDomain.test(cleaned)) {
    cleaned = refangIOC(cleaned);
  }

  // IPv4 validation
  const ipMatch = cleaned.match(IOC_PATTERNS.ipv4);
  if (ipMatch) {
    const ip = ipMatch[0];
    if (isPrivateIP(ip)) {
      return { valid: false, reason: 'private_ip', text: ip };
    }
    return { valid: true, type: 'ipv4', value: ip };
  }

  // URL validation
  const urlMatch = cleaned.match(IOC_PATTERNS.url);
  if (urlMatch) {
    const url = urlMatch[0];
    const domain = extractDomainFromURL(url);
    if (domain) {
      return { valid: true, type: 'url', value: url, domain };
    }
  }

  // Domain validation
  const domainMatch = cleaned.match(IOC_PATTERNS.domain);
  if (domainMatch) {
    const domain = domainMatch[0];
    return { valid: true, type: 'domain', value: domain };
  }

  // SHA256 hash validation
  const sha256Match = cleaned.match(IOC_PATTERNS.sha256);
  if (sha256Match) {
    const hash = sha256Match[0].toLowerCase();
    return { valid: true, type: 'sha256', value: hash };
  }

  return { valid: false, reason: 'invalid_format', text: cleaned };
}

// Version tracking
const CURRENT_VERSION = chrome.runtime.getManifest().version;

/**
 * Extension installation/update handler
 */
chrome.runtime.onInstalled.addListener(async (details) => {
  // Create context menu
  chrome.contextMenus.create({
    id: 'enrichIOC',
    title: 'Enrich IOC: "%s"',
    contexts: ['selection']
  });

  const handlers = {
    install: async () => {
      const installData = {
        installDate: Date.now(),
        version: CURRENT_VERSION,
        installType: 'fresh_install'
      };
      await chrome.storage.local.set({ installData });
    },
    update: async () => {
      const { installData } = await chrome.storage.local.get(['installData']);

      if (!installData) {
        // Updating from legacy version
        const data = {
          installDate: Date.now(),
          version: CURRENT_VERSION,
          installType: 'update_from_legacy'
        };
        await chrome.storage.local.set({ installData: data });
      } else {
        // Update version number
        installData.version = CURRENT_VERSION;
        await chrome.storage.local.set({ installData });
      }
    }
  };

  await handlers[details.reason]?.();
});

/**
 * Context menu click handler
 */
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'enrichIOC') {
    const selectedText = info.selectionText;
    const validation = validateIOC(selectedText);

    if (!validation.valid) {
      // Show error notification
      const truncatedText = (validation.text || selectedText).length > 50
        ? (validation.text || selectedText).substring(0, 50) + '...'
        : (validation.text || selectedText);

      let title = '❌ Invalid IOC';
      let message = '';

      switch (validation.reason) {
        case 'private_ip':
          title = '⚠️ Private IP Address';
          message = `"${truncatedText}" is a private/reserved IP address.\\n\\nPrivate IPs cannot be enriched with threat intelligence.`;
          break;
        case 'too_long':
          title = '❌ Text Too Long';
          message = `Selected text is too long (max ${MAX_IOC_LENGTH} characters).\\n\\nPlease select only the IOC itself.`;
          break;
        default:
          message = `"${truncatedText}" is not a valid IOC.\\n\\nSupported types:\\n• Public IPv4 addresses\\n• Domains\\n• URLs\\n• SHA256 hashes`;
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

    // Extract IOC data
    const ioc = {
      type: validation.type,
      value: validation.value,
      domain: validation.domain
    };

    // CRITICAL: Await storage write to prevent race condition
    await chrome.storage.local.set({
      currentIOC: ioc,
      timestamp: Date.now()
    });

    // Open popup after data is persisted
    chrome.action.openPopup();
  }
});

/**
 * Message handler for popup/options communication
 * SECURITY: Only accept messages from extension pages
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // SECURITY: Validate message origin
  if (!sender.id || sender.id !== chrome.runtime.id) {
    sendResponse({ error: 'Unauthorized - messages only accepted from extension pages' });
    return false;
  }

  // Handle different message types
  switch (request.action) {
    case 'validateIOC':
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

    case 'checkRateLimit':
      // Async rate limit check
      RateLimiter.consumeToken().then(result => {
        sendResponse(result);
      }).catch(error => {
        sendResponse({ allowed: false, error: error.message });
      });
      return true; // Keep channel open for async response

    case 'getRateLimitStatus':
      RateLimiter.getStatus().then(status => {
        sendResponse({ status });
      }).catch(error => {
        sendResponse({ error: error.message });
      });
      return true;

    default:
      sendResponse({ error: 'Unknown action' });
      return false;
  }
});
