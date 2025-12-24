/**
 * Debug Logs Viewer
 */

let allLogs = [];
let filteredLogs = [];
let autoRefreshInterval = null;

// DOM Elements
const logsContainer = document.getElementById('logs-container');
const categoryFilter = document.getElementById('category-filter');
const logLimit = document.getElementById('log-limit');
const searchInput = document.getElementById('search-input');
const refreshBtn = document.getElementById('refresh-btn');
const exportJsonBtn = document.getElementById('export-json-btn');
const exportTextBtn = document.getElementById('export-text-btn');
const clearCacheBtn = document.getElementById('clear-cache-btn');
const clearBtn = document.getElementById('clear-btn');
const totalCount = document.getElementById('total-count');
const filteredCount = document.getElementById('filtered-count');
const errorCount = document.getElementById('error-count');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  // Check if chrome.storage is available
  if (!chrome?.storage?.local) {
    showError('Chrome storage API not available. Please make sure this page is opened as a Chrome extension page.');
    return;
  }

  await loadLogs();

  // Event listeners
  categoryFilter.addEventListener('change', applyFilters);
  logLimit.addEventListener('change', applyFilters);
  searchInput.addEventListener('input', debounce(applyFilters, 300));
  refreshBtn.addEventListener('click', loadLogs);
  exportJsonBtn.addEventListener('click', exportJSON);
  exportTextBtn.addEventListener('click', exportText);
  clearCacheBtn.addEventListener('click', clearCache);
  clearBtn.addEventListener('click', clearLogs);

  // Auto-refresh every 5 seconds
  autoRefreshInterval = setInterval(loadLogs, 5000);

  // Cleanup interval on page unload to prevent memory leak
  window.addEventListener('beforeunload', () => {
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
    }
  });
});

async function loadLogs() {
  try {
    allLogs = await Logger.getLogs();
    updateStats();
    applyFilters();
  } catch (error) {
    console.error('Failed to load logs:', error);
    showError('Failed to load logs: ' + error.message);
  }
}

function applyFilters() {
  const category = categoryFilter.value;
  const limit = parseInt(logLimit.value);
  const searchTerm = searchInput.value.toLowerCase().trim();

  // Filter by category
  let logs = category === 'all'
    ? [...allLogs]
    : allLogs.filter(log => log.category === category);

  // Filter by search term
  if (searchTerm) {
    logs = logs.filter(log => {
      const messageMatch = log.message.toLowerCase().includes(searchTerm);
      const dataMatch = log.data ? JSON.stringify(log.data).toLowerCase().includes(searchTerm) : false;
      return messageMatch || dataMatch;
    });
  }

  // Apply limit (take last N entries)
  filteredLogs = logs.slice(-limit);

  updateStats();
  renderLogs();
}

function renderLogs() {
  if (filteredLogs.length === 0) {
    logsContainer.innerHTML = `
      <div class="empty-state">
        <p>No logs match your filters.</p>
      </div>
    `;
    return;
  }

  const searchTerm = searchInput.value.toLowerCase().trim();

  // Render in reverse order (newest first)
  const html = filteredLogs.reverse().map((log, index) => {
    const hasData = log.data && Object.keys(log.data).length > 0;
    const dataId = `data-${index}`;

    return `
      <div class="log-entry ${log.category}">
        <div class="log-header">
          <span class="log-timestamp">${formatTimestamp(log.timestamp)}</span>
          <span class="log-category ${log.category}">${log.category}</span>
        </div>
        <div class="log-message">${highlightText(escapeHtml(log.message), searchTerm)}</div>
        ${hasData ? `
          <button class="log-data-toggle" onclick="toggleData('${dataId}')">
            📋 Show Data
          </button>
          <div id="${dataId}" class="log-data collapsed">
${highlightText(escapeHtml(JSON.stringify(log.data, null, 2)), searchTerm)}
          </div>
        ` : ''}
      </div>
    `;
  }).join('');

  // SECURITY: Use innerHTML safely - all user data is escaped via escapeHtml() before insertion
  logsContainer.innerHTML = html;
}

function updateStats() {
  totalCount.textContent = allLogs.length;
  filteredCount.textContent = filteredLogs.length;

  const errors = allLogs.filter(log =>
    log.category === 'API_ERROR' || log.category === 'ERROR'
  ).length;
  errorCount.textContent = errors;
}

const toggleData = (dataId) => {
  const element = document.getElementById(dataId);
  const button = element.previousElementSibling;
  const collapsed = element.classList.toggle('collapsed');
  button.textContent = collapsed ? '📋 Show Data' : '📋 Hide Data';
};

const exportJSON = async () => {
  try {
    await Logger.exportLogs();
  } catch (error) {
    console.error('Export failed:', error);
    alert('Failed to export logs: ' + error.message);
  }
};

const exportText = async () => {
  try {
    await Logger.exportLogsText();
  } catch (error) {
    console.error('Export failed:', error);
    alert('Failed to export logs: ' + error.message);
  }
};

async function clearCache() {
  if (!confirm('Are you sure you want to clear all cached data? This will force the extension to re-fetch data from APIs on the next enrichment.')) {
    return;
  }

  try {
    // Get all storage data
    const allData = await chrome.storage.local.get(null);

    // Find all cache keys (they start with 'enrichment_')
    const cacheKeys = Object.keys(allData).filter(key => key.startsWith('enrichment_'));

    if (cacheKeys.length === 0) {
      alert('No cache data found.');
      return;
    }

    // Remove all cache entries
    await chrome.storage.local.remove(cacheKeys);

    // Log the action
    await Logger.log('SYSTEM', `Cache cleared: ${cacheKeys.length} entries removed`, { keys: cacheKeys });

    alert(`Cache cleared successfully! Removed ${cacheKeys.length} cached entries.`);
    await loadLogs();
  } catch (error) {
    console.error('Clear cache failed:', error);
    alert('Failed to clear cache: ' + error.message);
  }
}

async function clearLogs() {
  if (!confirm('Are you sure you want to clear all logs? This cannot be undone.')) {
    return;
  }

  try {
    await Logger.clearLogs();
    await loadLogs();
  } catch (error) {
    console.error('Clear failed:', error);
    alert('Failed to clear logs: ' + error.message);
  }
}

// Utility functions
const formatTimestamp = (timestamp) => new Date(timestamp).toLocaleString('en-US', {
  month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
});

const escapeHtml = (text) => {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
};

const highlightText = (text, searchTerm) => {
  if (!searchTerm) return text;
  // SECURITY: Escape both the text and search term to prevent XSS
  const regex = new RegExp(`(${searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
  return text.replace(regex, (match) => `<span class="highlight">${escapeHtml(match)}</span>`);
};

const debounce = (func, wait) => {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};

const showError = (message) => {
  logsContainer.innerHTML = `<div class="empty-state"><p style="color: #ef4444;">❌ ${escapeHtml(message)}</p></div>`;
};

// Make toggleData available globally
window.toggleData = toggleData;
