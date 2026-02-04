/**
 * Popup Script V2 - Refactored for maintainability
 */

// Import logger (loaded via script tag in HTML)
// Logger is available globally

// Global configuration loaded from chrome.storage
let API_CONFIG = null;

// ============================================================================
// API CONFIGURATION - Data-driven approach
// ============================================================================

const API_REGISTRY = {
  ipapi: {
    name: 'ip-api.com',
    icon: '🌐',
    supports: ['ipv4'],
    requiresKey: false,
    weight: 0, // Geolocation only, no reputation
    buildUrl: (ioc, key) => {
      // With API key: use HTTPS pro endpoint, without key: use HTTP free endpoint
      const protocol = key ? 'https' : 'http';
      const keyParam = key ? `&key=${key}` : '';
      return `${protocol}://ip-api.com/json/${ioc}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query${keyParam}`;
    },
    buildWebUrl: (ioc) => `https://ip-api.com/#${ioc}`,
    timeout: 8000 // Increased from 5000 - ip-api.com can be slow
  },
  internetdb: {
    name: 'InternetDB',
    icon: '🔎',
    supports: ['ipv4'],
    requiresKey: false, // Completely free, no API key needed
    weight: 1.0,
    buildUrl: (ioc) => `https://internetdb.shodan.io/${ioc}`,
    buildWebUrl: (ioc) => `https://www.shodan.io/host/${ioc}`,
    timeout: 5000
  },
  virustotal: {
    name: 'VirusTotal',
    icon: '🦠',
    supports: ['ipv4', 'domain', 'url', 'sha256'],
    requiresKey: true,
    weight: 2.0,
    // buildUrl receives (iocValue, apiKey, iocType, iocObject) from callAPI
    // For URLs, we need to query the domain, not the full URL
    buildUrl: (iocValue, apiKey, type, iocObj) => {
      if (type === 'ipv4') {
        return `https://www.virustotal.com/api/v3/ip_addresses/${iocValue}`;
      } else if (type === 'sha256') {
        return `https://www.virustotal.com/api/v3/files/${iocValue}`;
      } else if (type === 'url' && iocObj?.domain) {
        // For URLs, query the domain
        return `https://www.virustotal.com/api/v3/domains/${iocObj.domain}`;
      } else {
        // For domains, query directly
        return `https://www.virustotal.com/api/v3/domains/${iocValue}`;
      }
    },
    buildWebUrl: (ioc, type) => {
      if (type === 'ipv4') {
        return `https://www.virustotal.com/gui/ip-address/${ioc}`;
      } else if (type === 'sha256') {
        return `https://www.virustotal.com/gui/file/${ioc}`;
      } else {
        return `https://www.virustotal.com/gui/domain/${ioc}`;
      }
    },
    headers: (key) => ({ 'x-apikey': key }),
    timeout: 8000,
    parseResponse: (data) => data.data
  },
  abuseipdb: {
    name: 'AbuseIPDB',
    icon: '⚠️',
    supports: ['ipv4'],
    requiresKey: true,
    weight: 1.5,
    buildUrl: (ioc) => `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90&verbose`,
    buildWebUrl: (ioc) => `https://www.abuseipdb.com/check/${ioc}`,
    headers: (key) => ({ 'Key': key, 'Accept': 'application/json' }),
    timeout: 5000,
    parseResponse: (data) => data.data
  },
  shodan: {
    name: 'Shodan',
    icon: '🔎',
    supports: ['ipv4'],
    requiresKey: true,
    weight: 1.0,
    buildUrl: (ioc, key) => `https://api.shodan.io/shodan/host/${ioc}?key=${key}`,
    buildWebUrl: (ioc) => `https://www.shodan.io/host/${ioc}`,
    timeout: 8000
  },
  greynoise: {
    name: 'GreyNoise',
    icon: '📡',
    supports: ['ipv4'],
    requiresKey: false, // Community API works without key (50 req/week)
    weight: 1.5,
    buildUrl: (ioc) => `https://api.greynoise.io/v3/community/${ioc}`,
    buildWebUrl: (ioc) => `https://viz.greynoise.io/ip/${ioc}`,
    headers: (key) => key ? { 'key': key } : {},
    timeout: 5000
  },
  urlhaus: {
    name: 'URLhaus',
    icon: '🔗',
    supports: ['domain', 'url', 'sha256'],
    requiresKey: true,
    weight: 2.0,
    buildUrl: (iocValue, apiKey, type) => {
      if (type === 'sha256') {
        return 'https://urlhaus-api.abuse.ch/v1/payload/';
      }
      return 'https://urlhaus-api.abuse.ch/v1/host/';
    },
    buildWebUrl: (ioc) => `https://urlhaus.abuse.ch/browse.php?search=${ioc}`,
    method: 'POST',
    headers: (key) => ({
      'Content-Type': 'application/x-www-form-urlencoded',
      'Auth-Key': key
    }),
    buildBody: (iocValue, apiKey, type, iocObj) => {
      if (type === 'sha256') {
        return `sha256_hash=${encodeURIComponent(iocValue)}`;
      }
      const host = type === 'url' && iocObj?.domain ? iocObj.domain : iocValue;
      return `host=${encodeURIComponent(host)}`;
    },
    timeout: 5000
  },
  threatfox: {
    name: 'ThreatFox',
    icon: '🦊',
    supports: ['ipv4', 'domain', 'url', 'sha256'],
    requiresKey: true,
    weight: 2.0, // abuse.ch curated blacklist - high confidence like URLhaus
    buildUrl: () => 'https://threatfox-api.abuse.ch/api/v1/',
    buildWebUrl: (ioc) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${ioc}`,
    method: 'POST',
    headers: (key) => ({
      'Content-Type': 'application/json',
      'Auth-Key': key
    }),
    buildBody: (ioc) => JSON.stringify({ query: 'search_ioc', search_term: ioc }),
    timeout: 5000
  },
  otx: {
    name: 'AlienVault OTX',
    icon: '👽',
    supports: ['domain', 'ipv4', 'sha256'],
    requiresKey: true,
    weight: 1.2,
    buildUrl: (ioc, key, type) => {
      let indicator;
      if (type === 'ipv4') {
        indicator = 'IPv4';
      } else if (type === 'sha256') {
        indicator = 'file';
      } else {
        indicator = 'domain';
      }
      return `https://otx.alienvault.com/api/v1/indicators/${indicator}/${ioc}/general`;
    },
    buildWebUrl: (ioc, type) => {
      let indicator;
      if (type === 'ipv4') {
        indicator = 'IPv4';
      } else if (type === 'sha256') {
        indicator = 'file';
      } else {
        indicator = 'domain';
      }
      return `https://otx.alienvault.com/indicator/${indicator}/${ioc}`;
    },
    headers: (key) => ({ 'X-OTX-API-KEY': key }),
    timeout: 8000
  }
};

const VERDICT_RULES = {
  virustotal: (data) => {
    const stats = data.attributes?.last_analysis_stats;
    if (!stats) return { verdict: 'unknown', score: 0, detail: 'No analysis data' };

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = malicious + suspicious + (stats.undetected || 0) + (stats.harmless || 0);

    if (malicious > 5) return { verdict: 'malicious', score: 100, detail: `${malicious}/${total} vendors` };
    if (malicious > 0 || suspicious > 3) return { verdict: 'suspicious', score: 50, detail: `${malicious}/${total} malicious, ${suspicious}/${total} suspicious` };
    return { verdict: 'clean', score: 0, detail: `0/${total} detections` };
  },

  abuseipdb: (data) => {
    const score = data.abuseConfidenceScore || 0;
    const reports = data.totalReports || 0;

    if (score > 75) return { verdict: 'malicious', score, detail: `${score}% confidence, ${reports} reports` };
    if (score > 25) return { verdict: 'suspicious', score, detail: `${score}% confidence, ${reports} reports` };
    return { verdict: 'clean', score, detail: reports > 0 ? `${reports} reports, ${score}% confidence` : 'No abuse reports' };
  },

  greynoise: (data) => {
    const classMap = {
      malicious: { verdict: 'malicious', score: 100, detail: data.name || 'Malicious activity' },
      benign: { verdict: 'clean', score: 0, detail: 'Benign scanner' },
      unknown: { verdict: 'clean', score: 0, detail: `Actor: ${data.actor || 'unknown'} - Not classified as threat` }
    };
    return classMap[data.classification] || { verdict: 'clean', score: 0, detail: 'Not seen' };
  },

  internetdb: (data) => {
    // InternetDB returns: ports, cpes, vulns (CVEs), tags, hostnames
    const vulns = Array.isArray(data.vulns) ? data.vulns.length : 0;
    const ports = Array.isArray(data.ports) ? data.ports.length : 0;
    const tags = Array.isArray(data.tags) ? data.tags : [];

    // Check for malicious tags
    const maliciousTags = ['malware', 'compromised', 'botnet', 'ransomware', 'backdoor'];
    const hasMaliciousTags = tags.some(tag => maliciousTags.some(mal => tag.toLowerCase().includes(mal)));

    if (hasMaliciousTags) {
      return { verdict: 'malicious', score: 90, detail: `Tagged: ${tags.join(', ')}` };
    }

    if (vulns > 10) {
      return { verdict: 'suspicious', score: 70, detail: `${vulns} CVEs, ${ports} ports, tags: ${tags.join(', ') || 'none'}` };
    }
    if (vulns > 0) {
      return { verdict: 'suspicious', score: 40, detail: `${vulns} CVE(s), ${ports} ports` };
    }

    if (ports > 0) {
      const details = [`${ports} port(s)`];
      if (tags.length > 0) details.push(`tags: ${tags.join(', ')}`);
      return { verdict: 'clean', score: 0, detail: details.join(', ') };
    }

    return { verdict: 'unknown', score: 0, detail: 'No data available' };
  },

  urlhaus: (data) => {
    // URLhaus is a blacklist only - "not found" doesn't mean clean, it means unknown
    if (data.query_status === 'ok') {
      // For hosts: check urlhaus_reference, for payloads: check sha256_hash or urls
      if (data.urlhaus_reference || data.sha256_hash || (data.urls && data.urls.length > 0)) {
        return { verdict: 'malicious', score: 100, detail: 'Listed in malware database' };
      }
    }
    return { verdict: 'unknown', score: 0, detail: 'Not in database (blacklist only)' };
  },

  shodan: (data) => {
    const vulns = data.vulns ? Object.keys(data.vulns).length : 0;
    const ports = Array.isArray(data.ports) ? data.ports.length : 0;
    const services = Array.isArray(data.data) ? data.data.length : 0;

    if (vulns > 5) return { verdict: 'suspicious', score: 70, detail: `${vulns} known CVEs, ${ports} open ports` };
    if (vulns > 0) return { verdict: 'suspicious', score: 40, detail: `${vulns} known CVE(s), ${ports} open ports` };

    // If we have data about the host (ports/services), it means Shodan found it
    if (ports > 0 || services > 0) {
      const details = [];
      if (ports > 0) details.push(`${ports} open port(s)`);
      if (data.org) details.push(`Org: ${data.org}`);
      if (data.os) details.push(`OS: ${data.os}`);
      return { verdict: 'clean', score: 0, detail: details.join(', ') || 'Host found, no vulnerabilities' };
    }

    return { verdict: 'unknown', score: 0, detail: 'No data available' };
  },

  threatfox: (data) => {
    // ThreatFox returns { query_status: "ok", data: [...] } or { query_status: "no_result" }
    // Check if we have valid data array with results
    if (data && data.data && Array.isArray(data.data) && data.data.length > 0) {
      const iocCount = data.data.length;
      // Get confidence level from first IOC if available
      const firstIoc = data.data[0];
      const confidenceLevel = firstIoc?.confidence_level || 'unknown';
      return { verdict: 'malicious', score: 100, detail: `${iocCount} IOC(s) - ${confidenceLevel} confidence` };
    }
    // Check for explicit "ok" status with no data
    if (data && data.query_status === 'ok') {
      return { verdict: 'unknown', score: 0, detail: 'Found but no IOCs' };
    }
    // "no_result" or no data
    return { verdict: 'unknown', score: 0, detail: 'Not in database (blacklist only)' };
  },

  otx: (data) => {
    // AlienVault OTX general endpoint returns pulse_info with count
    const pulseCount = data.pulse_info?.count || 0;
    if (pulseCount > 10) return { verdict: 'malicious', score: 90, detail: `Found in ${pulseCount} threat reports` };
    if (pulseCount > 3) return { verdict: 'suspicious', score: 60, detail: `Found in ${pulseCount} threat reports` };
    if (pulseCount > 0) return { verdict: 'suspicious', score: 30, detail: `Found in ${pulseCount} threat report(s)` };
    return { verdict: 'clean', score: 0, detail: 'Not in threat reports' };
  }
};

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  console.log('[Popup] Initialisation...');
  await Logger.logUI('Popup opened');

  // Load theme preference
  await loadTheme();

  await loadAPIConfig();

  // Check and display PRO status
  const isProUser = await checkProStatus();
  updateUIForProStatus(isProUser);

  const data = await safeStorageGet(['currentIOC']);

  if (data.currentIOC) {
    console.log('[Popup] IOC trouvé:', data.currentIOC);
    await Logger.logIOC('IOC loaded from storage', data.currentIOC);
    displayIOC(data.currentIOC);
    await enrichIOC(data.currentIOC);
  } else {
    await Logger.logUI('No IOC selected', { error: 'User needs to select text' });
    showError('No IOC selected. Right-click on an IP address or domain to analyze it.');
  }

  document.getElementById('copy-json').addEventListener('click', copyJSON);
  document.getElementById('export-json').addEventListener('click', exportJSON);
  document.getElementById('refresh').addEventListener('click', refreshData);
  document.getElementById('theme-toggle').addEventListener('click', toggleTheme);
  document.getElementById('settings-btn').addEventListener('click', openSettings);

  // License management event listeners
  document.getElementById('gumroad-purchase').addEventListener('click', openGumroadPurchase);
  document.getElementById('activate-license').addEventListener('click', activateLicenseKey);

  // Show license input when clicking on pro banner
  const proBanner = document.querySelector('.pro-banner');
  if (proBanner && !isProUser) {
    proBanner.addEventListener('dblclick', () => {
      document.getElementById('license-section').classList.toggle('hidden');
    });
  }
});

async function loadAPIConfig() {
  try {
    const result = await safeStorageGet(['apiConfig', 'proLicenseKey']);
    const isProUser = !!result.proLicenseKey;

    // Default config: Free users get VirusTotal, ipapi, InternetDB, and GreyNoise
    const DEFAULT_CONFIG = {
      modules: {
        ipapi: { enabled: true, key: '' }, // FREE - geolocation (45 req/min)
        internetdb: { enabled: true, key: '' }, // FREE - Shodan InternetDB (no limits)
        virustotal: { enabled: true, key: '' }, // FREE - Always enabled
        abuseipdb: { enabled: isProUser, key: '' },
        shodan: { enabled: isProUser, key: '' },
        urlhaus: { enabled: isProUser, key: '' },
        threatfox: { enabled: isProUser, key: '' },
        otx: { enabled: isProUser, key: '' },
        greynoise: { enabled: true, key: '' } // FREE - Community API (50 req/week)
      }
    };

    if (result.apiConfig) {
      // SECURITY: Decrypt API keys before use
      // Keys are stored encrypted in chrome.storage.local to prevent theft
      let decryptedConfig = await CryptoUtils.decryptConfig(result.apiConfig);

      // BUG FIX: Merge with DEFAULT_CONFIG to ensure all modules exist
      // This handles cases where new APIs are added but user has old saved config
      API_CONFIG = {
        ...DEFAULT_CONFIG,
        ...decryptedConfig,
        modules: {
          ...DEFAULT_CONFIG.modules,
          ...(decryptedConfig.modules || {})
        }
      };

      console.log('[Config] Configuration chargée, décryptée et fusionnée avec les défauts');
    } else {
      API_CONFIG = DEFAULT_CONFIG;
      console.log('[Config] Using default config (PRO:', isProUser, ')');
    }

    // Enforce free tier limitations
    if (!isProUser) {
      console.log('[Config] Applying FREE tier restrictions');
      // Free tier: VirusTotal, ipapi, InternetDB, and GreyNoise (all have free APIs)
      const freeAPIs = ['virustotal', 'ipapi', 'internetdb', 'greynoise'];
      for (const [apiName, config] of Object.entries(API_CONFIG.modules)) {
        if (!freeAPIs.includes(apiName)) {
          config.enabled = false;
        }
      }
    }
  } catch (error) {
    console.error('[Config] Load error:', error);
    // Fallback to free tier config on error
    API_CONFIG = {
      modules: {
        ipapi: { enabled: true, key: '' }, // FREE - geolocation (45 req/min)
        internetdb: { enabled: true, key: '' }, // FREE - Shodan InternetDB (no limits)
        virustotal: { enabled: true, key: '' }, // FREE - Always enabled
        abuseipdb: { enabled: false, key: '' },
        shodan: { enabled: false, key: '' },
        urlhaus: { enabled: false, key: '' },
        threatfox: { enabled: false, key: '' },
        otx: { enabled: false, key: '' },
        greynoise: { enabled: true, key: '' } // FREE - Community API (50 req/week)
      }
    };
  }
}

// ============================================================================
// CORE API CLIENT
// ============================================================================

async function callAPI(apiName, ioc) {
  const spec = API_REGISTRY[apiName];
  if (!spec) throw new Error(`Unknown API: ${apiName}`);

  const iocValue = ioc.value;
  const iocType = ioc.type;

  const config = API_CONFIG.modules[apiName];
  if (!config.enabled) return null;
  if (!spec.supports.includes(iocType)) return null;

  // Check rate limit before making API call
  try {
    const rateLimitCheck = await chrome.runtime.sendMessage({ action: 'checkRateLimit' });
    if (rateLimitCheck && !rateLimitCheck.allowed) {
      throw new Error(`Rate limit exceeded (${rateLimitCheck.status.available}/${rateLimitCheck.status.max} tokens). Please wait before retrying.`);
    }
  } catch (rateLimitError) {
    // If rate limiting fails, log but continue (fail open for now)
    console.warn('[Rate Limit] Check failed, continuing anyway:', rateLimitError);
  }

  // Pass iocValue, apiKey, iocType, and full ioc object to buildUrl
  const url = spec.buildUrl(iocValue, config.key, iocType, ioc);
  const method = spec.method || 'GET';

  // Build headers - handle both required and optional API keys
  let headers = {};
  if (spec.headers) {
    if (spec.requiresKey && config.key) {
      // API requires key and we have one
      headers = spec.headers(config.key);
    } else if (!spec.requiresKey) {
      // API has optional key - pass it if available
      headers = spec.headers(config.key);
    }
  }

  const body = spec.buildBody ? spec.buildBody(iocValue, config.key, iocType, ioc) : undefined;

  const startTime = Date.now();

  // Log the API request
  await Logger.logAPIRequest(apiName, url, { method, headers, body });

  try {
    const response = await fetchWithTimeout(url, {
      method,
      headers,
      body,
      timeout: spec.timeout
    });

    const duration = Date.now() - startTime;

    if (!response.ok) {
      // 404 means no data found, not an error - this is normal for threat intel APIs
      // Return empty object so it still shows in verdicts as "No information available"
      if (response.status === 404) {
        await Logger.logAPIResponse(apiName, true, { noData: true, reason: 'No information available', status: 404 }, duration);
        return {};  // Empty object will trigger "No data available" verdict
      }

      // Try to get error message from response body for other errors
      let errorMessage = null;
      try {
        const errorData = await response.json();
        // Check for various error message formats (error, detail, message)
        // Handle both string and object formats
        if (errorData.error) {
          errorMessage = typeof errorData.error === 'string' ? errorData.error : errorData.error.message || JSON.stringify(errorData.error);
        } else if (errorData.detail) {
          errorMessage = typeof errorData.detail === 'string' ? errorData.detail : errorData.detail.message || JSON.stringify(errorData.detail);
        } else if (errorData.message) {
          errorMessage = typeof errorData.message === 'string' ? errorData.message : JSON.stringify(errorData.message);
        }
      } catch (e) {
        // JSON parsing failed, use generic error
      }

      const error = errorMessage ? new Error(errorMessage) : createAPIError(response.status, apiName);
      // Don't log normal API responses like rate limits (429) or permission errors (403) as errors
      // These are expected responses that we handle gracefully in the UI
      const isExpectedError = response.status === 429 || response.status === 403;
      if (!isExpectedError && error) {
        await Logger.logAPIError(apiName, error, { status: response.status, duration });
      }
      throw error;
    }

    const data = await response.json();

    // Debug log for InternetDB
    if (apiName === 'internetdb') {
      console.log('[InternetDB] Raw response:', data);
    }

    // Only reject if it's an actual error (not just "no results found")
    if (data.status === 'fail') {
      const error = new Error(data.message || 'API request failed');
      // Don't log rate limit errors as they are expected and displayed in UI
      const isRateLimitError = data.message && data.message.toLowerCase().includes('rate limit');
      if (!isRateLimitError) {
        await Logger.logAPIError(apiName, error, { responseData: data, duration });
      }
      throw error;
    }
    if (data.error && data.query_status !== 'no_result') {
      const error = new Error(data.reason || data.error || 'API error');
      // Don't log expected API limitations (rate limits, membership requirements, etc.)
      const errorMsg = error.message.toLowerCase();
      const isExpectedError = errorMsg.includes('rate limit') ||
                              errorMsg.includes('membership') ||
                              errorMsg.includes('upgrade') ||
                              errorMsg.includes('quota');
      if (!isExpectedError) {
        await Logger.logAPIError(apiName, error, { responseData: data, duration });
      }
      throw error;
    }

    const result = spec.parseResponse ? spec.parseResponse(data) : data;
    await Logger.logAPIResponse(apiName, true, result, duration);

    return result;
  } catch (error) {
    const duration = Date.now() - startTime;
    // Don't log "API key not configured" as an error for optional APIs
    const isKeyError = error.message === 'API key not configured';
    const shouldLogError = !isKeyError || spec.requiresKey;

    if (shouldLogError) {
      await Logger.logAPIError(apiName, error, { duration });
    }
    throw error;
  }
}

function createAPIError(status, apiName) {
  // 404 means no data found, not an error - this is normal
  if (status === 404) {
    return null; // Not an error, just no information available
  }

  // Special handling for ip-api.com which uses 403 for rate limiting
  if (apiName === 'ipapi' && status === 403) {
    return new Error('Rate limit exceeded (45 req/min)');
  }

  if (status === 401 || status === 403) return new Error('Invalid or missing API key');
  if (status === 422) return new Error('Invalid input format');
  if (status === 429) return new Error('Rate limit exceeded');
  if (status >= 500) return new Error(`${apiName} service temporarily unavailable`);
  return new Error(`API error (HTTP ${status})`);
}

// ============================================================================
// ENRICHMENT ORCHESTRATION
// ============================================================================

async function enrichIOC(ioc) {
  showLoading();
  hideError();
  hideResults();

  await Logger.logEnrichment('Starting enrichment', { ioc });

  try {
    // SECURITY: Use SHA-256 hash for cache key to prevent collisions
    // Normalize IOC value and use explicit namespace
    const normalizedValue = ioc.value.toLowerCase().trim();
    const hash = await generateSHA256(normalizedValue);
    const cacheKey = `enrichment_${ioc.type}_${hash}`;
    const cached = await getCachedData(cacheKey);

    if (cached) {
      console.log('[Popup] Using cache for:', cacheKey);
      await Logger.logCache('Cache hit', cacheKey, true);
      displayResults(cached);
      return;
    }

    await Logger.logCache('Cache miss', cacheKey, false);

    // Use the actual IOC type (ipv4, domain, or url) and pass full IOC object for URLs
    const enrichedData = await enrichByType(ioc);

    enrichedData.ioc = ioc;
    enrichedData.timestamp = new Date().toISOString();

    await cacheData(cacheKey, enrichedData);
    await Logger.logEnrichment('Enrichment completed', {
      sources: enrichedData.sources,
      reputation: enrichedData.reputation?.status,
      threatsCount: enrichedData.threats?.length || 0
    });
    displayResults(enrichedData);

  } catch (error) {
    console.error('[Popup] Enrichment error:', error);
    await Logger.log('ERROR', 'Enrichment failed', { error: error.message, stack: error.stack });
    showError(`Error: ${error.message}`);
  } finally {
    hideLoading();
  }
}

async function enrichByType(ioc) {
  const iocValue = ioc.value;
  const iocType = ioc.type;

  console.log(`[Enrichment v2.0] Starting enrichment for ${iocType}:`, iocValue);
  await Logger.log('ENRICHMENT', `[v2.0] Starting enrichment for ${iocType}`, { iocValue, iocType });

  const results = {
    type: iocType,
    value: iocValue,
    sources: [],
    apiResults: {},
    apiErrors: [],
    reputation: null,
    threats: [],
    tags: {
      malwareFamilies: [],
      threatTypes: [],
      categories: [],
      cves: [],
      generalTags: [],
      attackIds: []
    },
    technical: {},
    externalLinks: []
  };

  if (iocType === 'ipv4') {
    results.geolocation = null;
  }

  const promises = buildAPICalls(ioc);
  const apiResults = await Promise.allSettled(promises);

  processAPIResults(apiResults, results, iocValue, iocType);
  consolidateResults(results, iocValue, iocType, ioc);

  console.log('[Enrichment] Résultats consolidés:', results);
  return results;
}

function buildAPICalls(ioc) {
  const iocValue = ioc.value;
  const iocType = ioc.type;
  const promises = [];

  console.log(`[buildAPICalls v2.0] Building calls for ${iocType}: ${iocValue}`);
  Logger.log('ENRICHMENT', `[v2.0] buildAPICalls started`, { iocType, iocValue });

  for (const [apiName, spec] of Object.entries(API_REGISTRY)) {
    // Log why API is skipped for better debugging
    if (!spec.supports.includes(iocType)) {
      console.log(`[Enrichment v2.0] Skipping ${apiName} - does not support ${iocType} (supports: ${spec.supports.join(', ')})`);
      Logger.log('ENRICHMENT', `[v2.0] Skipping ${apiName} - unsupported IOC type`, { api: apiName, iocType, supports: spec.supports });
      continue;
    }

    if (!API_CONFIG.modules[apiName]?.enabled) {
      console.log(`[Enrichment v2.0] Skipping ${apiName} - disabled in config`);
      Logger.log('ENRICHMENT', `[v2.0] Skipping ${apiName} - disabled`, { api: apiName });
      continue;
    }

    // Skip APIs that require a key but don't have one configured
    const config = API_CONFIG.modules[apiName];
    if (spec.requiresKey && !config.key) {
      console.log(`[Enrichment v2.0] Skipping ${apiName} - API key required but not configured`);
      Logger.log('ENRICHMENT', `[v2.0] Skipping ${apiName} - no API key`, { api: apiName, requiresKey: true });
      continue;
    }

    console.log(`[Enrichment v2.0] Calling ${apiName} for ${iocType}: ${iocValue}`);
    Logger.log('ENRICHMENT', `[v2.0] Calling ${apiName}`, { api: apiName, iocType, iocValue });

    promises.push(
      callAPI(apiName, ioc)
        .then(data => ({ status: 'success', api: apiName, data }))
        .catch(error => ({ status: 'error', api: apiName, error }))
    );
  }

  console.log(`[Enrichment] Built ${promises.length} API calls for ${iocType}`);
  Logger.log('ENRICHMENT', `Built API calls`, { count: promises.length, iocType });

  return promises;
}

function processAPIResults(apiResults, results, iocValue, iocType) {
  apiResults.forEach(promiseResult => {
    if (promiseResult.status === 'fulfilled') {
      const result = promiseResult.value;

      if (result.status === 'success') {
        const { api, data } = result;
        const spec = API_REGISTRY[api];

        // Add external link for all APIs that were called
        results.externalLinks.push({
          name: spec.name,
          url: spec.buildWebUrl(iocValue, iocType),
          icon: spec.icon
        });

        // Only process data if we got some (data can be null for "no information available")
        if (data) {
          results.apiResults[api] = data;
          results.sources.push(spec.name);
        }
      } else if (result.status === 'error') {
        const { api, error } = result;
        const spec = API_REGISTRY[api];

        // Add external link even for failed APIs
        if (spec) {
          results.externalLinks.push({
            name: spec.name,
            url: spec.buildWebUrl(iocValue, iocType),
            icon: spec.icon
          });
        }

        // Check if this is an expected error (API limitations, rate limits, etc.)
        const errorMsg = error.message?.toLowerCase() || '';
        const isExpectedError = errorMsg.includes('api key') ||
                                errorMsg.includes('rate limit') ||
                                errorMsg.includes('membership') ||
                                errorMsg.includes('upgrade') ||
                                errorMsg.includes('quota');

        // Only log unexpected errors to console (expected errors are still added to apiErrors for UI display)
        if (!isExpectedError) {
          console.error(`[${api}] Error:`, error);
        }

        // Always add to apiErrors for UI display
        results.apiErrors.push({
          api: api,
          error: error.message || 'Unexpected error'
        });
      }
    }
  });
}

function consolidateResults(results, iocValue, iocType, ioc) {
  if (iocType === 'ipv4') {
    results.geolocation = extractGeolocation(results.apiResults);
  }

  results.technical = extractTechnical(results.apiResults, iocType);
  results.reputation = calculateReputation(results.apiResults, iocType, results.apiErrors);
  results.threats = extractThreats(results.apiResults);
  results.tags = extractTags(results.apiResults);
}

// ============================================================================
// DATA EXTRACTION
// ============================================================================

const extractGeolocation = (apiResults) => {
  const geo = {};

  if (apiResults.ipapi) {
    const d = apiResults.ipapi;
    Object.assign(geo, {
      country: d.country, countryCode: d.countryCode, region: d.regionName || d.region,
      city: d.city, coordinates: `${d.lat}, ${d.lon}`, timezone: d.timezone,
      isp: d.isp, org: d.org, asn: d.as, asnName: d.asname
    });
  }

  return Object.keys(geo).length > 0 ? geo : null;
};

const extractTechnical = (apiResults, iocType) => {
  const tech = { firstSeen: null, firstSeenSource: null };

  const dates = [];

  // Collect dates from various APIs
  if (apiResults.virustotal?.attributes?.first_submission_date) {
    dates.push({
      timestamp: apiResults.virustotal.attributes.first_submission_date * 1000,
      source: 'VirusTotal'
    });
  }
  if (apiResults.abuseipdb?.lastReportedAt) {
    dates.push({
      timestamp: new Date(apiResults.abuseipdb.lastReportedAt).getTime(),
      source: 'AbuseIPDB'
    });
  }
  if (apiResults.urlhaus?.firstseen) {
    dates.push({
      timestamp: new Date(apiResults.urlhaus.firstseen).getTime(),
      source: 'URLhaus'
    });
  }
  if (apiResults.urlhaus?.firstseen_utc) {
    dates.push({
      timestamp: new Date(apiResults.urlhaus.firstseen_utc).getTime(),
      source: 'URLhaus'
    });
  }
  if (apiResults.threatfox?.data && Array.isArray(apiResults.threatfox.data) && apiResults.threatfox.data.length > 0) {
    apiResults.threatfox.data.forEach(ioc => {
      if (ioc.first_seen) {
        dates.push({
          timestamp: new Date(ioc.first_seen).getTime(),
          source: 'ThreatFox'
        });
      }
    });
  }

  // Get oldest date
  if (dates.length > 0) {
    const oldest = dates.reduce((min, curr) => curr.timestamp < min.timestamp ? curr : min);
    tech.firstSeen = new Date(oldest.timestamp);
    tech.firstSeenSource = oldest.source;
  }

  // Add IPv4-specific data
  if (iocType === 'ipv4') {
    if (apiResults.ipapi) {
      const { proxy, hosting, mobile, reverse } = apiResults.ipapi;
      Object.assign(tech, { proxy: proxy || false, hosting: hosting || false, mobile: mobile || false, reverse });
    }
    if (apiResults.internetdb) {
      const { ports, hostnames, cpes } = apiResults.internetdb;
      if (ports && ports.length > 0) tech.ports = ports;
      if (hostnames && hostnames.length > 0) tech.hostnames = hostnames;
      if (cpes && cpes.length > 0) tech.cpes = cpes;
    }
    if (apiResults.shodan) {
      const { ports, hostnames, os } = apiResults.shodan;
      Object.assign(tech, { ports, hostnames, os });
    }
  }

  return tech;
};

const extractThreats = (apiResults) => {
  const threats = [];

  if (apiResults.virustotal?.attributes?.last_analysis_stats?.malicious > 0) {
    const stats = apiResults.virustotal.attributes.last_analysis_stats;
    const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0);
    threats.push({ type: 'Malware Detection', description: `${stats.malicious}/${total} security vendors flagged as malicious`, severity: 'critical', source: 'VirusTotal' });
  }

  if (apiResults.abuseipdb?.abuseConfidenceScore > 75) {
    const { abuseConfidenceScore, totalReports } = apiResults.abuseipdb;
    threats.push({ type: 'High Abuse Score', description: `Confidence: ${abuseConfidenceScore}% - ${totalReports} reports`, severity: 'high', source: 'AbuseIPDB' });
  }

  if (apiResults.greynoise?.classification === 'malicious') {
    threats.push({ type: 'Malicious Scanner', description: apiResults.greynoise.name || 'Classified as malicious by GreyNoise', severity: 'high', source: 'GreyNoise' });
  }

  if (apiResults.internetdb?.vulns && Array.isArray(apiResults.internetdb.vulns)) {
    const vulnCount = apiResults.internetdb.vulns.length;
    if (vulnCount > 0) {
      const vulnList = apiResults.internetdb.vulns.slice(0, 5).join(', ');
      const moreText = vulnCount > 5 ? ` (+${vulnCount - 5} more)` : '';
      threats.push({
        type: 'Known Vulnerabilities',
        description: `${vulnCount} CVE(s): ${vulnList}${moreText}`,
        severity: vulnCount > 10 ? 'critical' : 'high',
        source: 'InternetDB'
      });
    }
  }

  if (apiResults.shodan?.vulns) {
    const vulnCount = Object.keys(apiResults.shodan.vulns).length;
    if (vulnCount > 0) threats.push({ type: 'Known Vulnerabilities', description: `${vulnCount} CVEs detected`, severity: 'high', source: 'Shodan' });
  }

  if (apiResults.urlhaus?.query_status === 'ok') {
    if (apiResults.urlhaus.urlhaus_reference) {
      threats.push({ type: 'Malware Distribution', description: 'Domain listed in URLhaus malware URL database', severity: 'critical', source: 'URLhaus' });
    } else if (apiResults.urlhaus.sha256_hash) {
      const signature = apiResults.urlhaus.signature || 'Unknown malware';
      threats.push({ type: 'Malicious File', description: `File hash found in URLhaus database: ${signature}`, severity: 'critical', source: 'URLhaus' });
    }
  }

  return threats;
};

function extractTags(apiResults) {
  const tags = {
    malwareFamilies: new Set(),
    threatTypes: new Set(),
    categories: new Set(),
    generalTags: new Set(),
    attackIds: new Set()
  };

  // VirusTotal tags only (categories are verdicts, not attack categories)
  if (apiResults.virustotal?.attributes) {
    const vt = apiResults.virustotal.attributes;
    if (vt.tags && Array.isArray(vt.tags)) {
      vt.tags.forEach(tag => tags.generalTags.add(tag));
    }
  }

  // AbuseIPDB categories
  if (apiResults.abuseipdb?.reports && Array.isArray(apiResults.abuseipdb.reports)) {
    const categoryMap = {
      1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders',
      4: 'DDoS Attack', 5: 'FTP Brute-Force', 6: 'Ping of Death',
      7: 'Phishing', 8: 'Fraud VoIP', 9: 'Open Proxy',
      10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
      13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking',
      16: 'SQL Injection', 17: 'Spoofing', 18: 'Brute-Force',
      19: 'Bad Web Bot', 20: 'Exploited Host', 21: 'Web App Attack',
      22: 'SSH', 23: 'IoT Targeted'
    };
    apiResults.abuseipdb.reports.forEach(report => {
      if (report.categories && Array.isArray(report.categories)) {
        report.categories.forEach(catId => {
          if (categoryMap[catId]) {
            tags.categories.add(categoryMap[catId]);
          }
        });
      }
    });
  }

  // GreyNoise tags
  if (apiResults.greynoise?.tags && Array.isArray(apiResults.greynoise.tags)) {
    apiResults.greynoise.tags.forEach(tag => tags.generalTags.add(tag));
  }

  // InternetDB tags and CVEs
  if (apiResults.internetdb) {
    if (apiResults.internetdb.tags && Array.isArray(apiResults.internetdb.tags)) {
      apiResults.internetdb.tags.forEach(tag => tags.generalTags.add(tag));
    }
    // CVEs are treated as vulnerabilities, not tags (handled in extractThreats)
  }

  // Shodan tags
  if (apiResults.shodan) {
    if (apiResults.shodan.tags && Array.isArray(apiResults.shodan.tags)) {
      apiResults.shodan.tags.forEach(tag => tags.generalTags.add(tag));
    }
  }

  // URLhaus tags, threat, and malware families
  if (apiResults.urlhaus?.urls && Array.isArray(apiResults.urlhaus.urls)) {
    apiResults.urlhaus.urls.forEach(url => {
      if (url.tags && Array.isArray(url.tags)) {
        url.tags.forEach(tag => tags.generalTags.add(tag));
      }
      if (url.threat) {
        tags.threatTypes.add(url.threat);
      }
      if (url.payloads && Array.isArray(url.payloads)) {
        url.payloads.forEach(payload => {
          if (payload.malware_family) {
            tags.malwareFamilies.add(payload.malware_family);
          }
        });
      }
    });
  }

  // ThreatFox malware families, threat types, and tags
  if (apiResults.threatfox?.data && Array.isArray(apiResults.threatfox.data)) {
    apiResults.threatfox.data.forEach(ioc => {
      if (ioc.malware_printable) {
        tags.malwareFamilies.add(ioc.malware_printable);
      }
      if (ioc.malware_alias && typeof ioc.malware_alias === 'string') {
        // Split comma-separated aliases
        ioc.malware_alias.split(',').forEach(alias => {
          if (alias.trim()) tags.malwareFamilies.add(alias.trim());
        });
      }
      if (ioc.threat_type_desc) {
        tags.threatTypes.add(ioc.threat_type_desc);
      }
      if (ioc.tags && Array.isArray(ioc.tags)) {
        ioc.tags.forEach(tag => tags.generalTags.add(tag));
      }
    });
  }

  // AlienVault OTX tags, malware families, and MITRE ATT&CK
  if (apiResults.otx?.pulse_info?.pulses && Array.isArray(apiResults.otx.pulse_info.pulses)) {
    apiResults.otx.pulse_info.pulses.forEach(pulse => {
      if (pulse.tags && Array.isArray(pulse.tags)) {
        pulse.tags.forEach(tag => tags.generalTags.add(tag));
      }
      if (pulse.malware_families && Array.isArray(pulse.malware_families)) {
        pulse.malware_families.forEach(family => {
          // malware_families can be objects with display_name or strings
          if (typeof family === 'object' && family !== null) {
            const familyName = family.display_name || family.name || JSON.stringify(family);
            if (familyName) tags.malwareFamilies.add(familyName);
          } else if (typeof family === 'string') {
            tags.malwareFamilies.add(family);
          }
        });
      }
      if (pulse.attack_ids && Array.isArray(pulse.attack_ids)) {
        pulse.attack_ids.forEach(id => {
          // attack_ids can be objects with id and name properties or strings
          if (typeof id === 'object' && id !== null) {
            // Format: "T1234: Technique Name" or just "T1234" if no name
            const attackId = id.id || id.attack_id;
            const attackName = id.name || id.display_name;
            if (attackId && attackName) {
              tags.attackIds.add(`${attackId}: ${attackName}`);
            } else if (attackId) {
              tags.attackIds.add(attackId);
            }
          } else if (typeof id === 'string') {
            tags.attackIds.add(id);
          }
        });
      }
    });
  }

  // Convert Sets to sorted arrays
  return {
    malwareFamilies: Array.from(tags.malwareFamilies).sort(),
    threatTypes: Array.from(tags.threatTypes).sort(),
    categories: Array.from(tags.categories).sort(),
    generalTags: Array.from(tags.generalTags).sort(),
    attackIds: Array.from(tags.attackIds).sort()
  };
}

function calculateReputation(apiResults, iocType, apiErrors = []) {
  const verdicts = [];
  const evidence = { malicious: [], suspicious: [], clean: [], unknown: [] };

  // APIs that only provide geolocation/metadata, not reputation
  const geoOnlyAPIs = ['ipapi'];

  // Collecter les verdicts de toutes les APIs activées et compatibles
  for (const [apiName, spec] of Object.entries(API_REGISTRY)) {
    // Skip geolocation-only APIs
    if (geoOnlyAPIs.includes(apiName)) {
      continue;
    }

    // Skip APIs that don't support this IOC type
    if (!spec.supports.includes(iocType)) {
      continue;
    }

    // Skip APIs that are not enabled
    const config = API_CONFIG.modules[apiName];
    if (!config?.enabled) {
      continue;
    }

    // Skip APIs that require a key but don't have one
    if (spec.requiresKey && !config.key) {
      continue;
    }

    // Get API data (will be undefined if API call failed or returned no data)
    const apiData = apiResults[apiName];

    // Skip APIs that failed or returned no data - they shouldn't contribute to reputation
    if (!apiData) {
      continue;
    }

    const verdict = analyzeVerdict(apiName, apiData);
    verdicts.push({ api: apiName, ...verdict });

    const weight = spec.weight || 1.0;
    const confidence = weight >= 2.0 ? 'HIGH' : weight >= 1.5 ? 'MEDIUM' : 'LOW';

    evidence[verdict.verdict].push({
      api: apiName,
      weight,
      confidence,
      detail: verdict.detail,
      score: verdict.score
    });
  }

  // Accumulation d'évidence Bayésienne
  const maliciousWeight = evidence.malicious.reduce((sum, e) => sum + e.weight, 0);
  const suspiciousWeight = evidence.suspicious.reduce((sum, e) => sum + e.weight, 0);
  const cleanWeight = evidence.clean.reduce((sum, e) => sum + e.weight, 0);

  const totalWeight = maliciousWeight + suspiciousWeight + cleanWeight || 1;

  // Calcul de la probabilité de malveillance
  const maliciousProbability = maliciousWeight / totalWeight;
  const suspiciousProbability = suspiciousWeight / totalWeight;

  // Détermination du verdict final basé sur probabilité
  let status, globalScore, confidence, message;

  // RÈGLE 1: Source hautement fiable dit "malicious" ET probabilité > 50%
  const highConfidenceMalicious = evidence.malicious.some(e => e.weight >= 2.0);
  if (highConfidenceMalicious && maliciousProbability > 0.5) {
    status = 'malicious';
    globalScore = 100;
    confidence = 'HIGH';
    message = `High-confidence malicious verdict`;
  }
  // RÈGLE 2: 2+ sources disent "malicious" OU probabilité malveillante > 70%
  else if (evidence.malicious.length >= 2 || maliciousProbability > 0.7) {
    status = 'malicious';
    globalScore = Math.round(70 + (maliciousProbability * 30));
    confidence = 'MEDIUM';
    message = `${evidence.malicious.length} source(s) flagged as malicious`;
  }
  // RÈGLE 3: Probabilité malveillante entre 40% et 70%
  else if (maliciousProbability >= 0.4) {
    status = 'suspicious';
    globalScore = Math.round(maliciousProbability * 100);
    confidence = 'MEDIUM';
    message = `Potential threat detected (${Math.round(maliciousProbability * 100)}% confidence)`;
  }
  // RÈGLE 4: Probabilité suspecte élevée mais pas de malicious confirmé
  else if (suspiciousProbability > 0.5 && evidence.malicious.length === 0) {
    status = 'suspicious';
    globalScore = Math.round(suspiciousProbability * 60);
    confidence = 'LOW';
    message = `${evidence.suspicious.length} source(s) indicate potential threat`;
  }
  // RÈGLE 5: Preuves contradictoires (certaines clean, certaines malicious, mais mal. < 40%)
  else if (evidence.clean.length >= 2 && evidence.malicious.length >= 1 && maliciousProbability >= 0.25) {
    status = 'suspicious';
    globalScore = 50;
    confidence = 'LOW';
    message = `Conflicting evidence detected`;
  }
  // RÈGLE 6: Majoritairement clean
  else if (evidence.clean.length >= 2 && maliciousProbability < 0.2) {
    status = 'safe';
    globalScore = Math.round((1 - maliciousProbability) * 10);
    confidence = evidence.clean.length >= 3 ? 'HIGH' : 'MEDIUM';
    message = `${evidence.clean.length} source(s) indicate clean`;
  }
  // RÈGLE 7: Au moins 1 clean, aucun malicious/suspicious
  else if (evidence.clean.length >= 1 && evidence.malicious.length === 0 && evidence.suspicious.length === 0) {
    status = 'safe';
    globalScore = 0;
    confidence = 'LOW';
    message = `No threats detected`;
  }
  // RÈGLE 8: Données insuffisantes
  else {
    status = 'unknown';
    globalScore = 50;
    confidence = 'LOW';
    message = 'Insufficient data for verdict';
  }

  // Add failed APIs to verdicts list with "error" status for display purposes
  apiErrors.forEach(error => {
    verdicts.push({
      api: error.api,
      verdict: 'error',
      score: 0,
      detail: error.error.replace(/\s+/g, ' ').trim()  // Normalize whitespace (remove newlines)
    });
  });

  return { score: globalScore, status, message, confidence, verdicts, evidence };
}

function analyzeVerdict(apiName, apiData) {
  if (!apiData) return { verdict: 'unknown', score: 0, detail: 'No data' };

  const analyzer = VERDICT_RULES[apiName];
  return analyzer ? analyzer(apiData) : { verdict: 'unknown', score: 0, detail: 'No verdict available' };
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

function displayIOC(ioc) {
  document.getElementById('ioc-text').textContent = ioc.value;
  document.getElementById('ioc-type').textContent = ioc.type;
}

async function displayResults(data) {
  console.log('[Display] Affichage des résultats:', data);
  Logger.logUI('Displaying results', {
    sources: data.sources,
    apiErrorsCount: data.apiErrors?.length || 0,
    threatsCount: data.threats?.length || 0,
    reputation: data.reputation?.status
  });

  showResults();

  // Load display sections settings
  const { apiConfig } = await chrome.storage.local.get(['apiConfig']);
  const displaySections = apiConfig?.displaySections || {
    reputation: true,
    individualVerdicts: true,
    geolocation: true,
    threats: true,
    tags: true,
    technicalDetails: true
  };

  // Display sections based on settings
  if (data.reputation && displaySections.reputation) {
    displayReputation(data.reputation, displaySections);
    document.getElementById('reputation-section')?.classList.remove('hidden');
  } else {
    document.getElementById('reputation-section')?.classList.add('hidden');
  }

  // Display individual verdicts even if reputation section is hidden
  if (data.reputation?.verdicts?.length > 0 && displaySections.individualVerdicts) {
    displayAPIVerdicts(data.reputation.verdicts);
  } else if (!displaySections.individualVerdicts) {
    document.getElementById('api-verdicts')?.classList.add('hidden');
  }

  if (data.geolocation && data.ioc.type === 'ipv4' && displaySections.geolocation) {
    displayGeolocation(data.geolocation);
  } else {
    document.getElementById('geo-section')?.classList.add('hidden');
  }

  if (data.threats?.length > 0 && displaySections.threats) {
    displayThreats(data.threats);
  } else {
    document.getElementById('threats-section')?.classList.add('hidden');
  }

  if (data.tags && displaySections.tags) {
    displayTags(data.tags);
  } else {
    document.getElementById('tags-section')?.classList.add('hidden');
  }

  if (displaySections.technicalDetails) {
    displayTechnicalDetails(data.technical, data.ioc);
  } else {
    document.querySelector('.section:has(#technical-details)')?.classList.add('hidden');
  }

  displayExternalLinks(data.externalLinks || []);

  const sourcesList = document.getElementById('sources-list');
  sourcesList.textContent = data.sources?.length > 0 ? data.sources.join(', ') : 'None';

  const timestamp = data.timestamp ? new Date(data.timestamp).toLocaleString() : 'now';
  document.getElementById('last-updated').textContent = timestamp;

  window.currentEnrichmentData = data;
}

function displayAPIWarnings(apiErrors) {
  const warningsDiv = document.getElementById('api-warnings');
  const warningsList = document.getElementById('api-warnings-list');

  warningsList.innerHTML = apiErrors.map(err =>
    `<div class="warning-item"><strong>${escapeHtml(err.api.toUpperCase())}</strong>: ${escapeHtml(err.error)}</div>`
  ).join('');

  warningsDiv.classList.remove('hidden');
}

function displayReputation(reputation, displaySections) {
  const indicator = document.getElementById('reputation-indicator');
  const text = document.getElementById('reputation-text');

  indicator.className = 'indicator';

  // Icon mapping for each status
  const statusIcons = {
    malicious: '🔴',
    suspicious: '🟡',
    safe: '🟢',
    unknown: '⚪'
  };

  if (!reputation) {
    indicator.classList.add('unknown');
    indicator.innerHTML = `<div class="status-icon">${statusIcons.unknown}</div>`;
    text.innerHTML = '<strong>UNKNOWN</strong>';
    return;
  }

  indicator.classList.add(reputation.status);
  const icon = statusIcons[reputation.status] || statusIcons.unknown;

  indicator.innerHTML = `<div class="status-icon">${icon}</div>`;

  text.innerHTML = `
    <strong>${reputation.status.toUpperCase()}</strong>
    <div class="reputation-message">
      ${escapeHtml(reputation.message)}
    </div>
  `;

  // Don't call displayAPIVerdicts here - it's called separately in displayResults
}

function displayAPIVerdicts(verdicts) {
  const verdictsSection = document.getElementById('api-verdicts');
  const verdictsList = document.getElementById('api-verdicts-list');

  const verdictIcons = {
    malicious: '✗',
    suspicious: '⚠',
    clean: '✓',
    unknown: '?',
    error: '✗'
  };

  verdictsList.innerHTML = verdicts.map(v => `<div class="api-verdict-item ${escapeHtml(v.verdict)}" role="listitem" aria-label="${escapeHtml(API_REGISTRY[v.api]?.name || v.api)}: ${escapeHtml(v.verdict)}"><div class="api-verdict-name">${escapeHtml(API_REGISTRY[v.api]?.name || v.api)}</div><div class="api-verdict-score"><span class="api-verdict-detail">${escapeHtml(v.detail)}</span><span class="api-verdict-badge ${escapeHtml(v.verdict)}" aria-label="${escapeHtml(v.verdict)} verdict">${verdictIcons[v.verdict]} ${escapeHtml(v.verdict)}</span></div></div>`).join('');

  verdictsSection.classList.remove('hidden');
}

function displayGeolocation(geo) {
  const section = document.getElementById('geo-section');
  section.classList.remove('hidden');

  document.getElementById('geo-country').textContent = geo.country ? `${geo.country} (${geo.countryCode})` : '-';
  document.getElementById('geo-city').textContent = geo.city || '-';
  document.getElementById('geo-region').textContent = geo.region || '-';
  document.getElementById('geo-isp').textContent = geo.isp || '-';
  document.getElementById('geo-asn').textContent = geo.asn || '-';
  document.getElementById('geo-org').textContent = geo.org || '-';
}

function displayThreats(threats) {
  const section = document.getElementById('threats-section');
  const list = document.getElementById('threats-list');

  section.classList.remove('hidden');
  list.innerHTML = threats.map(threat => `
    <div class="threat-item">
      <strong>${escapeHtml(threat.type)}</strong>
      ${escapeHtml(threat.description)}
      <div class="threat-meta">
        Severity: ${escapeHtml(threat.severity)} | Source: ${escapeHtml(threat.source)}
      </div>
    </div>
  `).join('');
}

function displayTags(tags) {
  const section = document.getElementById('tags-section');
  const tagsData = [
    { containerId: 'malware-families-container', listId: 'malware-families-list', data: tags.malwareFamilies, cssClass: 'tag-malware' },
    { containerId: 'threat-types-container', listId: 'threat-types-list', data: tags.threatTypes, cssClass: 'tag-threat' },
    { containerId: 'categories-container', listId: 'categories-list', data: tags.categories, cssClass: 'tag-category-item' },
    { containerId: 'attack-ids-container', listId: 'attack-ids-list', data: tags.attackIds, cssClass: 'tag-attack' },
    { containerId: 'general-tags-container', listId: 'general-tags-list', data: tags.generalTags, cssClass: 'tag-general' }
  ];

  let hasAnyTags = false;

  tagsData.forEach(({ containerId, listId, data, cssClass }) => {
    const container = document.getElementById(containerId);
    const list = document.getElementById(listId);

    if (data && data.length > 0) {
      hasAnyTags = true;
      container.classList.remove('hidden');

      // SECURITY: Use escapeHtml to prevent XSS
      list.innerHTML = data.map(item =>
        `<span class="tag ${escapeHtml(cssClass)}">${escapeHtml(item)}</span>`
      ).join('');
    } else {
      container.classList.add('hidden');
    }
  });

  if (hasAnyTags) {
    section.classList.remove('hidden');
  } else {
    section.classList.add('hidden');
  }
}

function displayTechnicalDetails(technical, ioc) {
  if (technical?.firstSeen && technical?.firstSeenSource) {
    // Handle both Date objects and date strings (from cache)
    let dateStr;
    if (technical.firstSeen instanceof Date) {
      dateStr = technical.firstSeen.toLocaleString();
    } else if (typeof technical.firstSeen === 'string' || typeof technical.firstSeen === 'number') {
      // Date was serialized to string/number in cache, convert back
      dateStr = new Date(technical.firstSeen).toLocaleString();
    } else {
      dateStr = String(technical.firstSeen);
    }
    document.getElementById('tech-first-seen').textContent = `${dateStr} (${technical.firstSeenSource})`;
  } else {
    document.getElementById('tech-first-seen').textContent = '-';
  }
}

function displayExternalLinks(links) {
  let linksSection = document.getElementById('external-links-section');

  if (!linksSection) {
    linksSection = document.createElement('div');
    linksSection.id = 'external-links-section';
    linksSection.className = 'section';
    linksSection.innerHTML = `
      <div class="section-header-with-action">
        <h2>🔗 External Resources</h2>
        <button id="open-all-links" class="btn-open-all hidden">🚀 Open All</button>
      </div>
      <div id="external-links-list" class="external-links"></div>
    `;

    const actionsDiv = document.querySelector('.actions');
    actionsDiv.parentNode.insertBefore(linksSection, actionsDiv);
  }

  const linksList = document.getElementById('external-links-list');
  const openAllBtn = document.getElementById('open-all-links');

  if (!links || links.length === 0) {
    linksSection.classList.add('hidden');
    return;
  }

  linksList.innerHTML = '';

  links.forEach(link => {
    const linkBtn = document.createElement('a');
    linkBtn.href = link.url;
    linkBtn.className = 'external-link-btn';
    linkBtn.rel = 'noopener noreferrer';
    linkBtn.textContent = `${link.icon} ${link.name}`;
    linkBtn.addEventListener('click', (e) => {
      e.preventDefault();
      chrome.tabs.create({ url: link.url, active: false });
    });
    linksList.appendChild(linkBtn);
  });

  // Show "Open All" button and attach event listener
  if (openAllBtn) {
    openAllBtn.classList.remove('hidden');
    // Remove any existing listeners to avoid duplicates
    const newBtn = openAllBtn.cloneNode(true);
    openAllBtn.parentNode.replaceChild(newBtn, openAllBtn);

    newBtn.addEventListener('click', () => {
      links.forEach(link => {
        chrome.tabs.create({ url: link.url, active: false });
      });
    });
  }

  linksSection.classList.remove('hidden');
}

// ============================================================================
// UTILITIES
// ============================================================================

async function generateSHA256(text) {
  // Use Web Crypto API to generate SHA-256 hash
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

// Storage operations with timeout protection
async function safeStorageGet(keys, timeoutMs = 5000) {
  let timeoutHandle;
  try {
    return await Promise.race([
      chrome.storage.local.get(keys),
      new Promise((_, reject) => {
        timeoutHandle = setTimeout(() => {
          reject(new Error(`Storage get operation timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  }
}

async function safeStorageSet(data, timeoutMs = 5000) {
  if (!data || typeof data !== 'object') {
    throw new Error('Invalid data provided to safeStorageSet');
  }

  // SECURITY: Validate data size before storage to prevent DoS via storage exhaustion
  // Chrome's chrome.storage.local has ~10MB quota (depends on browser)
  // We limit individual items to 5MB to be conservative
  const dataSize = new Blob([JSON.stringify(data)]).size;
  const MAX_STORAGE_SIZE = 5 * 1024 * 1024; // 5MB per item

  if (dataSize > MAX_STORAGE_SIZE) {
    const sizeMB = (dataSize / 1024 / 1024).toFixed(2);
    throw new Error(`Data too large for storage: ${sizeMB}MB (max: 5MB). This could indicate malicious API response or memory exhaustion attack.`);
  }

  let timeoutHandle;
  try {
    return await Promise.race([
      chrome.storage.local.set(data),
      new Promise((_, reject) => {
        timeoutHandle = setTimeout(() => {
          reject(new Error(`Storage set operation timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  }
}

async function safeStorageRemove(keys, timeoutMs = 5000) {
  if (!keys || (Array.isArray(keys) && keys.length === 0)) {
    throw new Error('No keys provided to safeStorageRemove');
  }
  let timeoutHandle;
  try {
    return await Promise.race([
      chrome.storage.local.remove(keys),
      new Promise((_, reject) => {
        timeoutHandle = setTimeout(() => {
          reject(new Error(`Storage remove operation timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  }
}

async function copyJSON() {
  if (!window.currentEnrichmentData) {
    showError('No data to copy');
    return;
  }

  try {
    const json = JSON.stringify(window.currentEnrichmentData, null, 2);
    await navigator.clipboard.writeText(json);

    const btn = document.getElementById('copy-json');
    const originalText = btn.textContent;
    btn.textContent = '✓ Copied!';
    btn.style.background = '#00aa00';

    setTimeout(() => {
      btn.textContent = originalText;
      btn.style.background = '';
    }, 2000);

  } catch (error) {
    console.error('[Copy] Error:', error);
    showError('Failed to copy data');
  }
}

async function exportJSON() {
  if (!window.currentEnrichmentData) {
    showError('No data to export');
    return;
  }

  try {
    const json = JSON.stringify(window.currentEnrichmentData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    // Generate filename with IOC value and timestamp
    const iocValue = window.currentEnrichmentData.ioc?.value || 'unknown';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const sanitizedIOC = iocValue.replace(/[^a-zA-Z0-9.-]/g, '_');
    const filename = `ioclens_${sanitizedIOC}_${timestamp}.json`;

    // Create temporary link and trigger download
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    // Visual feedback
    const btn = document.getElementById('export-json');
    const originalText = btn.textContent;
    btn.textContent = '✓ Exported!';
    btn.style.background = '#00aa00';

    setTimeout(() => {
      btn.textContent = originalText;
      btn.style.background = '';
    }, 2000);

    await Logger.logUI('JSON exported', { filename, iocValue });

  } catch (error) {
    console.error('[Export] Error:', error);
    showError('Failed to export data');
  }
}

async function refreshData() {
  try {
    console.log('[Refresh] Starting refresh - clearing cache...');
    const data = await safeStorageGet(['currentIOC']);

    if (!data.currentIOC) {
      throw new Error('No IOC data available to refresh');
    }

    // Validate IOC data BEFORE accessing properties
    if (!data.currentIOC.value || !data.currentIOC.type) {
      throw new Error('Invalid IOC data - missing value or type');
    }

    const normalizedValue = data.currentIOC.value.toLowerCase().trim();
    const hash = await generateSHA256(normalizedValue);
    const cacheKey = `enrichment_${data.currentIOC.type}_${hash}`;
    console.log('[Refresh] Removing cache:', cacheKey);
    await safeStorageRemove([cacheKey]);
    console.log('[Refresh] Cache cleared, restarting enrichment...');
    await enrichIOC(data.currentIOC);
  } catch (error) {
    console.error('[Refresh] Error during refresh:', error);
    await Logger.log('ERROR', 'Refresh failed', { error: error.message, stack: error.stack });
    showError('Failed to refresh data. Please try again.');
  }
}

async function getCachedData(key) {
  // Use the key as-is (already namespaced from enrichIOC)
  const result = await safeStorageGet([key]);

  if (result[key]) {
    const cached = result[key];
    const age = Date.now() - cached.timestamp;

    if (age < 5 * 60 * 1000) return cached.data;
  }

  return null;
}

async function cacheData(key, data) {
  // Use the key as-is (already namespaced from enrichIOC)
  await safeStorageSet({
    [key]: { data, timestamp: Date.now() }
  });

  cleanupExpiredCache();
}

async function cleanupExpiredCache() {
  try {
    const allData = await safeStorageGet(null);
    const now = Date.now();
    const CACHE_TTL = 5 * 60 * 1000;
    const MAX_CACHE_ENTRIES = 50;

    const cacheEntries = [];
    const keysToRemove = [];

    for (const [key, value] of Object.entries(allData)) {
      // Updated to match new cache key format: enrichment_*
      if (key.startsWith('enrichment_')) {
        if (value.timestamp && (now - value.timestamp) > CACHE_TTL) {
          keysToRemove.push(key);
        } else if (value.timestamp) {
          cacheEntries.push({ key, timestamp: value.timestamp });
        }
      }
    }

    if (cacheEntries.length > MAX_CACHE_ENTRIES) {
      cacheEntries.sort((a, b) => a.timestamp - b.timestamp);
      const toRemove = cacheEntries.slice(0, cacheEntries.length - MAX_CACHE_ENTRIES);
      keysToRemove.push(...toRemove.map(e => e.key));
    }

    if (keysToRemove.length > 0) {
      await safeStorageRemove(keysToRemove);
      console.log(`[Cache] Cleanup: ${keysToRemove.length} entries removed`);
    }
  } catch (error) {
    console.error('[Cache] Cleanup error:', error);
  }
}

async function fetchWithTimeout(url, options = {}) {
  const { timeout = 5000 } = options;

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    if (error.name === 'AbortError') throw new Error('Request timeout');
    throw error;
  }
}

const escapeHtml = (text) => {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
};

const setVisibility = (id, visible, message = null) => {
  const el = document.getElementById(id);
  el.classList[visible ? 'remove' : 'add']('hidden');
  if (message && id === 'error') document.getElementById('error-message').textContent = message;
};

const showLoading = () => setVisibility('loading', true);
const hideLoading = () => setVisibility('loading', false);
const showError = (msg) => setVisibility('error', true, msg);
const hideError = () => setVisibility('error', false);
const showResults = () => setVisibility('results', true);
const hideResults = () => setVisibility('results', false);

/**
 * Check if user has PRO access (valid license key)
 * @returns {Promise<boolean>} true if user has PRO access
 */
async function checkProStatus() {
  try {
    const result = await safeStorageGet(['proLicenseKey']);
    return !!result.proLicenseKey;
  } catch (error) {
    console.error('[PRO] Failed to check status:', error);
    return false;
  }
}

/**
 * Update UI based on PRO status
 */
function updateUIForProStatus(isProUser) {
  const proBanner = document.querySelector('.pro-banner');
  const proStatusBadge = document.getElementById('pro-status');

  if (isProUser) {
    // Hide upgrade banner for PRO users
    if (proBanner) proBanner.classList.add('hidden');
    // Show PRO badge
    if (proStatusBadge) {
      proStatusBadge.textContent = '✨ PRO';
      proStatusBadge.classList.remove('hidden');
    }
    console.log('[Popup] User has PRO access');
  } else {
    // Show upgrade banner for free users
    if (proBanner) proBanner.classList.remove('hidden');
    // Hide PRO badge
    if (proStatusBadge) proStatusBadge.classList.add('hidden');
    console.log('[Popup] User on FREE tier (VirusTotal only)');
  }
}

/**
 * Open Gumroad purchase page (placeholder URL)
 */
function openGumroadPurchase() {
  const gumroadURL = 'https://ioclens.gumroad.com/l/dworo';
  chrome.tabs.create({ url: gumroadURL, active: true });
  Logger.logUI('Gumroad purchase clicked', { url: gumroadURL });
}

/**
 * Activate license key entered by user
 */
async function activateLicenseKey() {
  const input = document.getElementById('license-key-input');
  const statusDiv = document.getElementById('license-status');
  const licenseKey = input.value.trim();

  if (!licenseKey) {
    statusDiv.textContent = '❌ Please enter a license key';
    statusDiv.className = 'license-status error';
    return;
  }

  try {
    statusDiv.textContent = '⏳ Verifying license...';
    statusDiv.className = 'license-status loading';

    // Verify license with Gumroad API
    const isValid = await verifyLicenseWithGumroad(licenseKey);

    if (isValid) {
      // Store license key
      await safeStorageSet({ proLicenseKey: licenseKey });

      statusDiv.textContent = '✅ PRO activated! Reloading...';
      statusDiv.className = 'license-status success';

      await Logger.logUI('PRO license activated', { success: true });

      // Reload extension to apply PRO features
      setTimeout(() => {
        location.reload();
      }, 1500);
    } else {
      statusDiv.textContent = '❌ Invalid license key';
      statusDiv.className = 'license-status error';
      await Logger.logUI('PRO license activation failed', { success: false, reason: 'invalid key' });
    }
  } catch (error) {
    console.error('[License] Activation error:', error);
    statusDiv.textContent = `❌ ${error.message}`;
    statusDiv.className = 'license-status error';
    await Logger.logUI('PRO license activation error', { success: false, error: error.message });
  }
}

/**
 * Verify license key with Gumroad API (via Vercel endpoint)
 * @param {string} licenseKey - The license key to verify
 * @returns {Promise<boolean>} true if valid
 */
async function verifyLicenseWithGumroad(licenseKey) {
  try {
    const result = await LicenseManager.verifyLicense(licenseKey);
    return result.valid;
  } catch (error) {
    console.error('[License] Verification failed:', error);
    throw new Error('License verification failed. Please check your connection and try again.');
  }
}

// ============================================================================
// THEME MANAGEMENT
// ============================================================================

async function loadTheme() {
  try {
    const result = await safeStorageGet(['theme']);
    const theme = result.theme || 'dark'; // Default to dark theme
    applyTheme(theme);
  } catch (error) {
    console.error('[Theme] Failed to load theme:', error);
    applyTheme('dark'); // Fallback to dark
  }
}

async function toggleTheme() {
  try {
    const currentTheme = document.body.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    applyTheme(newTheme);
    await safeStorageSet({ theme: newTheme });
    await Logger.logUI('Theme changed', { from: currentTheme, to: newTheme });
  } catch (error) {
    console.error('[Theme] Failed to toggle theme:', error);
  }
}

function openSettings() {
  chrome.runtime.openOptionsPage();
}

function applyTheme(theme) {
  document.body.setAttribute('data-theme', theme);

  const themeIcon = document.querySelector('.theme-icon');
  if (themeIcon) {
    themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
  }

  const themeToggleBtn = document.getElementById('theme-toggle');
  if (themeToggleBtn) {
    themeToggleBtn.setAttribute('aria-label',
      theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
    );
  }
}

// Cache bust: 1765636763
