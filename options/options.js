/**
 * Options Page Script - Gestion de la configuration des APIs
 */

// Load crypto utilities (loaded via script tag in HTML)
// CryptoUtils is available globally

// Configuration par défaut
const DEFAULT_CONFIG = {
  modules: {
    ipapi: { enabled: true, key: '' },  // Enabled by default (free geolocation)
    ipapiCo: { enabled: false, key: '' },
    virustotal: { enabled: false, key: '' },
    abuseipdb: { enabled: false, key: '' },
    shodan: { enabled: false, key: '' },
    urlhaus: { enabled: false, key: '' }, // Requires API key
    threatfox: { enabled: false, key: '' }, // Requires API key
    otx: { enabled: false, key: '' },
    greynoise: { enabled: true, key: '' }  // Community API enabled by default (no key needed)
  },
  displaySections: {
    reputation: true,
    individualVerdicts: true,
    geolocation: true,
    threats: true,
    tags: true,
    technicalDetails: true
  },
  debugMode: false  // Debug logging disabled by default
};

/**
 * Toggle password visibility for API key inputs
 * @param {string} inputId - ID of the input element
 */
function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  const button = input.nextElementSibling; // Get the button next to input

  if (input.type === 'password') {
    input.type = 'text';
    if (button) button.textContent = '🙈'; // Change icon to "hide"
  } else {
    input.type = 'password';
    if (button) button.textContent = '👁️'; // Change icon to "show"
  }
}

/**
 * Initialisation de la page
 */
document.addEventListener('DOMContentLoaded', async () => {
  console.log('[Options] Initialisation...');

  // Charger la configuration sauvegardée
  await loadSettings();

  // Load and display PRO status
  await loadProStatus();

  // Event listeners pour les boutons principaux
  document.getElementById('save-btn').addEventListener('click', saveSettings);
  document.getElementById('reset-btn').addEventListener('click', resetSettings);
  document.getElementById('test-btn').addEventListener('click', testAPIs);
  document.getElementById('logs-btn').addEventListener('click', openLogsPage);

  // PRO license event listeners
  document.getElementById('get-pro-btn').addEventListener('click', openGumroadPurchase);
  document.getElementById('activate-pro-btn').addEventListener('click', activateProLicense);
  document.getElementById('deactivate-pro-btn').addEventListener('click', deactivateProLicense);
  document.getElementById('show-pro-key-btn').addEventListener('click', toggleProKeyVisibility);

  // Event listeners pour les boutons de visibilité (remplace onclick inline)
  document.querySelectorAll('.btn-show-key').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const inputId = e.target.previousElementSibling.id;
      togglePasswordVisibility(inputId);
    });
  });

  // Event listener pour fermer les résultats de test (modal overlay)
  const closeBtn = document.getElementById('close-test-results');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      document.getElementById('test-results-overlay').classList.add('hidden');
    });
  }

  // Fermer le modal en cliquant sur l'overlay
  const overlay = document.getElementById('test-results-overlay');
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.classList.add('hidden');
      }
    });
  }
});

/**
 * Charge les paramètres depuis chrome.storage
 * SECURITY: Utilise storage.local au lieu de storage.sync pour éviter
 * que les clés API ne soient envoyées aux serveurs Google
 * SECURITY: Décrypte automatiquement les clés API chiffrées
 */
async function loadSettings() {
  try {
    const result = await chrome.storage.local.get(['apiConfig']);
    let config = result.apiConfig || DEFAULT_CONFIG;

    // SECURITY: Migrate plaintext keys to encrypted format if needed
    config = await CryptoUtils.migrateToEncrypted(config);

    // SECURITY: Decrypt API keys for display
    const decryptedConfig = await CryptoUtils.decryptConfig(config);

    console.log('[Options] Configuration chargée (clés décryptées)');

    // Appliquer les valeurs aux inputs
    for (const [module, settings] of Object.entries(decryptedConfig.modules)) {
      const enableCheckbox = document.getElementById(`enable-${module}`);
      const keyInput = document.getElementById(`key-${module}`);

      if (enableCheckbox) {
        enableCheckbox.checked = settings.enabled;
      }

      if (keyInput && settings.key) {
        keyInput.value = settings.key;
      }
    }

    // Load display sections settings
    const displaySections = decryptedConfig.displaySections || DEFAULT_CONFIG.displaySections;
    for (const [section, enabled] of Object.entries(displaySections)) {
      const checkbox = document.getElementById(`display-${section}`);
      if (checkbox) {
        checkbox.checked = enabled;
      }
    }

    // Load debug mode setting
    const debugMode = decryptedConfig.debugMode !== undefined ? decryptedConfig.debugMode : DEFAULT_CONFIG.debugMode;
    const debugCheckbox = document.getElementById('debug-mode');
    if (debugCheckbox) {
      debugCheckbox.checked = debugMode;
    }

    showStatus('✅ Settings loaded successfully', 'success');

  } catch (error) {
    console.error('[Options] Config load error:', error);
    showStatus('❌ Error loading settings', 'error');
  }
}

/**
 * Validation des formats de clés API
 * @param {string} apiName - Nom de l'API
 * @param {string} key - Clé API à valider
 * @returns {Object} {valid: boolean, error?: string}
 */
function validateAPIKeyFormat(apiName, key) {
  if (!key || key.length === 0) {
    return { valid: true }; // Empty key is OK (will be disabled)
  }

  const validations = {
    virustotal: {
      pattern: /^[a-f0-9]{64}$/i,
      error: 'VirusTotal API keys are 64 hexadecimal characters'
    },
    abuseipdb: {
      pattern: /^[a-zA-Z0-9]{80}$/,
      error: 'AbuseIPDB API keys are 80 alphanumeric characters'
    },
    shodan: {
      pattern: /^[A-Za-z0-9]{32}$/,
      error: 'Shodan API keys are 32 alphanumeric characters'
    },
    greynoise: {
      pattern: /^[a-z0-9-]{36,}$/i,
      error: 'GreyNoise API keys should be at least 36 characters'
    },
    otx: {
      pattern: /^[a-f0-9]{64}$/i,
      error: 'AlienVault OTX API keys are 64 hexadecimal characters'
    }
  };

  const validation = validations[apiName];
  if (!validation) {
    return { valid: true }; // No validation rule for this API
  }

  if (!validation.pattern.test(key)) {
    return { valid: false, error: validation.error };
  }

  return { valid: true };
}

/**
 * Sauvegarde les paramètres dans chrome.storage
 * SECURITY: Utilise storage.local au lieu de storage.sync pour éviter
 * que les clés API ne soient envoyées aux serveurs Google
 * SECURITY: Chiffre automatiquement les clés API avant sauvegarde
 */
async function saveSettings() {
  try {
    const config = { modules: {} };

    // Collecter tous les modules
    const modules = [
      'ipapi', 'ipapiCo', 'virustotal', 'abuseipdb',
      'shodan', 'urlhaus', 'threatfox', 'otx', 'greynoise'
    ];

    // Validation errors
    const errors = [];

    for (const module of modules) {
      const enableCheckbox = document.getElementById(`enable-${module}`);
      const keyInput = document.getElementById(`key-${module}`);
      const key = keyInput ? keyInput.value.trim() : '';

      // SECURITY: Validate API key format
      if (key.length > 0) {
        const validation = validateAPIKeyFormat(module, key);
        if (!validation.valid) {
          errors.push(`${module}: ${validation.error}`);
          continue;
        }
      }

      // SECURITY: Encrypt API key if provided
      let encryptedKey = '';
      if (key.length > 0) {
        encryptedKey = await CryptoUtils.encrypt(key);
        console.log(`[Options] Clé ${module} chiffrée`);
      }

      config.modules[module] = {
        enabled: enableCheckbox ? enableCheckbox.checked : false,
        key: encryptedKey
      };
    }

    // Show validation errors
    if (errors.length > 0) {
      showStatus('❌ Invalid API keys:\n' + errors.join('\n'), 'error');
      return;
    }

    // Collect display sections settings
    const displaySections = {};
    const sections = ['reputation', 'individualVerdicts', 'geolocation', 'threats', 'tags', 'technicalDetails'];
    for (const section of sections) {
      const checkbox = document.getElementById(`display-${section}`);
      displaySections[section] = checkbox ? checkbox.checked : true;
    }
    config.displaySections = displaySections;

    // Collect debug mode setting
    const debugCheckbox = document.getElementById('debug-mode');
    config.debugMode = debugCheckbox ? debugCheckbox.checked : false;

    // Sauvegarder dans chrome.storage.local (PAS sync pour la sécurité)
    await chrome.storage.local.set({ apiConfig: config });

    console.log('[Options] Configuration sauvegardée (clés chiffrées)');
    showStatus('✅ Settings saved successfully! (API keys encrypted)', 'success');

    // Notifier le background script du changement
    chrome.runtime.sendMessage({
      action: 'configUpdated',
      config: config
    });

  } catch (error) {
    console.error('[Options] Save error:', error);
    showStatus('❌ Error saving settings: ' + error.message, 'error');
  }
}

/**
 * Réinitialise les paramètres par défaut
 */
async function resetSettings() {
  if (!confirm('Reset all settings to defaults? This will clear all API keys.')) {
    return;
  }

  try {
    await chrome.storage.local.set({ apiConfig: DEFAULT_CONFIG });

    console.log('[Options] Configuration reset');

    // Reload page to display default values
    window.location.reload();

  } catch (error) {
    console.error('[Options] Reset error:', error);
    showStatus('Error resetting settings', 'error');
  }
}

/**
 * Test les APIs configurées
 */
async function testAPIs() {
  showStatus('🧪 Testing APIs... (using test IP 8.8.8.8)', 'success');

  const testIP = '8.8.8.8';
  const config = await getConfig();
  const results = [];

  // APIs that require keys (greynoise community API works without key)
  const requiresKey = ['virustotal', 'abuseipdb', 'shodan', 'urlhaus', 'threatfox', 'otx'];

  // Tester chaque module activé
  for (const [module, settings] of Object.entries(config.modules)) {
    if (!settings.enabled) continue;

    try {
      let result = null;

      // Check if API requires a key but doesn't have one configured
      if (requiresKey.includes(module) && !settings.key) {
        result = { error: 'API key required but not configured' };
      } else {
        // Perform actual API test
        switch (module) {
          case 'ipapi':
            result = await testIPApi(testIP, settings.key);
            break;
          case 'ipapiCo':
            result = await testIPApiCo(testIP, settings.key);
            break;
          case 'virustotal':
            result = await testVirusTotal(testIP, settings.key);
            break;
          case 'abuseipdb':
            result = await testAbuseIPDB(testIP, settings.key);
            break;
          case 'shodan':
            result = await testShodan(testIP, settings.key);
            break;
          case 'greynoise':
            result = await testGreyNoise(testIP, settings.key);
            break;
          case 'urlhaus':
            result = await testURLhaus('google.com', settings.key); // URLhaus requires domain
            break;
          case 'threatfox':
            result = await testThreatFox(testIP, settings.key);
            break;
          case 'otx':
            result = await testOTX('google.com', settings.key); // OTX requires domain
            break;
          default:
            result = { error: 'Unknown API module' };
        }
      }

      results.push({
        module,
        success: !result?.error,
        message: result?.error || result?.success || 'OK'
      });

    } catch (error) {
      results.push({
        module,
        success: false,
        message: error.message
      });
    }
  }

  // Afficher les résultats dans un modal overlay au centre de l'écran
  const overlay = document.getElementById('test-results-overlay');
  const contentDiv = document.getElementById('test-results-content');

  contentDiv.innerHTML = results.map(r => `
    <div class="test-result-item ${r.success ? 'success' : 'error'}">
      <span class="test-icon">${r.success ? '✅' : '❌'}</span>
      <span class="test-api">${r.module}</span>
      <span class="test-message">${r.message}</span>
    </div>
  `).join('');

  overlay.classList.remove('hidden');
  showStatus('✅ Test completed', 'success');
}

// Generic API tester
const testAPI = async (url, headers = {}) => {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    // Try to get actual error message from response body
    let errorMessage = `HTTP ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData.error) {
        errorMessage = errorData.error;
      } else if (errorData.message) {
        errorMessage = errorData.message;
      } else if (errorData.reason) {
        errorMessage = errorData.reason;
      }
    } catch (e) {
      // JSON parsing failed, use HTTP status
    }
    return { error: errorMessage };
  }
  const data = await response.json();
  // ip-api.com returns HTTP 200 but with status: "fail" for errors
  if (data.status === 'fail') {
    return { error: data.message || 'API error' };
  }
  return data.error ? { error: data.reason || data.message } : {};
};

const testIPApi = (ip, key) => {
  const protocol = key ? 'https' : 'http';
  const keyParam = key ? `key=${key}` : '';
  return testAPI(`${protocol}://ip-api.com/json/${ip}${keyParam ? '?' + keyParam : ''}`);
};
const testIPApiCo = (ip, key) => {
  const keyParam = key ? `?key=${key}` : '';
  return testAPI(`https://ipapi.co/${ip}/json/${keyParam}`);
};
const testVirusTotal = (ip, key) => testAPI(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { 'x-apikey': key });
const testAbuseIPDB = (ip, key) => testAPI(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, { 'Key': key, 'Accept': 'application/json' });
const testShodan = (ip, key) => testAPI(`https://api.shodan.io/shodan/host/${ip}?key=${key}`);
const testGreyNoise = (ip, key) => testAPI(`https://api.greynoise.io/v3/community/${ip}`, key ? { 'key': key } : {});
const testURLhaus = async (domain, key) => {
  const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Auth-Key': key
    },
    body: `host=${encodeURIComponent(domain)}`
  });
  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData.error) errorMessage = errorData.error;
      else if (errorData.message) errorMessage = errorData.message;
    } catch (e) { }
    return { error: errorMessage };
  }
  const data = await response.json();
  // Both 'ok' and 'no_results' mean API is working correctly
  if (data.query_status === 'ok' || data.query_status === 'no_results') {
    return {}; // Success (empty object = no error)
  }
  return { error: data.query_status };
};
const testThreatFox = async (ip, key) => {
  const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Auth-Key': key
    },
    body: JSON.stringify({ query: 'search_ioc', search_term: ip })
  });
  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData.error) errorMessage = errorData.error;
      else if (errorData.message) errorMessage = errorData.message;
    } catch (e) { }
    return { error: errorMessage };
  }
  const data = await response.json();
  // Both 'ok' and 'no_result' mean API is working correctly
  if (data.query_status === 'ok' || data.query_status === 'no_result') {
    return {}; // Success (empty object = no error)
  }
  return { error: data.query_status };
};
const testOTX = (domain, key) => testAPI(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`, { 'X-OTX-API-KEY': key });

const getConfig = async () => {
  const { apiConfig } = await chrome.storage.local.get(['apiConfig']);
  if (!apiConfig) return DEFAULT_CONFIG;

  // SECURITY: Decrypt API keys before use (same as popup.js)
  try {
    const decryptedConfig = await CryptoUtils.decryptConfig(apiConfig);
    return decryptedConfig;
  } catch (error) {
    console.error('[Options] Failed to decrypt config:', error);
    return DEFAULT_CONFIG;
  }
};

const showStatus = (message, type) => {
  const statusDiv = document.getElementById('status-message');
  statusDiv.textContent = message;
  statusDiv.className = `status-message ${type}`;
  statusDiv.classList.remove('hidden');
  setTimeout(() => statusDiv.classList.add('hidden'), 3000);
};

const openLogsPage = () => chrome.tabs.create({ url: chrome.runtime.getURL('logs/logs.html') });

// ============================================================================
// PRO LICENSE MANAGEMENT
// ============================================================================

// Store the actual license key for toggle visibility
let actualLicenseKey = '';

/**
 * Load and display PRO status
 */
async function loadProStatus() {
  try {
    const result = await chrome.storage.local.get(['proLicenseKey']);
    const isProUser = !!result.proLicenseKey;

    const statusIndicator = document.getElementById('pro-status-indicator');
    const statusText = document.getElementById('pro-status-text');
    const freeTierInfo = document.getElementById('free-tier-info');
    const proTierInfo = document.getElementById('pro-tier-info');
    const currentLicenseKey = document.getElementById('current-license-key');

    if (isProUser) {
      // PRO user
      statusIndicator.classList.add('pro-active');
      statusIndicator.classList.remove('free-tier');
      statusText.textContent = 'PRO';
      freeTierInfo.classList.add('hidden');
      proTierInfo.classList.remove('hidden');

      // Store actual key and show masked version
      actualLicenseKey = result.proLicenseKey;
      currentLicenseKey.textContent = '***************';
      currentLicenseKey.setAttribute('data-masked', 'true');
    } else {
      // Free user
      statusIndicator.classList.add('free-tier');
      statusIndicator.classList.remove('pro-active');
      statusText.textContent = 'FREE';
      freeTierInfo.classList.remove('hidden');
      proTierInfo.classList.add('hidden');
      actualLicenseKey = '';
    }
  } catch (error) {
    console.error('[PRO] Failed to load status:', error);
  }
}

/**
 * Toggle PRO key visibility
 */
function toggleProKeyVisibility() {
  const keyElement = document.getElementById('current-license-key');
  const toggleBtn = document.getElementById('show-pro-key-btn');
  const isMasked = keyElement.getAttribute('data-masked') === 'true';

  if (isMasked) {
    // Show actual key
    keyElement.textContent = actualLicenseKey;
    keyElement.setAttribute('data-masked', 'false');
    toggleBtn.textContent = '🙈';
  } else {
    // Hide key
    keyElement.textContent = '***************';
    keyElement.setAttribute('data-masked', 'true');
    toggleBtn.textContent = '👁️';
  }
}

/**
 * Open Gumroad purchase page (placeholder)
 */
function openGumroadPurchase() {
  const gumroadURL = 'https://ioclens.gumroad.com/l/dworo';
  window.open(gumroadURL, '_blank');
}

/**
 * Activate PRO license
 */
async function activateProLicense() {
  const input = document.getElementById('pro-license-input');
  const statusDiv = document.getElementById('license-activation-status');
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
      await chrome.storage.local.set({ proLicenseKey: licenseKey });

      statusDiv.textContent = '✅ PRO activated successfully!';
      statusDiv.className = 'license-status success';

      // Update UI
      await loadProStatus();

      // Clear input
      input.value = '';

      showStatus('✅ PRO license activated successfully!', 'success');
    } else {
      statusDiv.textContent = '❌ Invalid license key';
      statusDiv.className = 'license-status error';
      showStatus('❌ Invalid license key', 'error');
    }
  } catch (error) {
    console.error('[License] Activation error:', error);
    statusDiv.textContent = `❌ ${error.message}`;
    statusDiv.className = 'license-status error';
    showStatus('❌ License verification failed', 'error');
  }
}

/**
 * Deactivate PRO license
 */
async function deactivateProLicense() {
  if (!confirm('Are you sure you want to deactivate your PRO license? You will lose access to advanced threat intelligence sources.')) {
    return;
  }

  try {
    await chrome.storage.local.remove(['proLicenseKey']);
    await loadProStatus();
    showStatus('PRO license deactivated', 'success');
  } catch (error) {
    console.error('[PRO] Deactivation error:', error);
    showStatus('❌ Failed to deactivate license', 'error');
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
