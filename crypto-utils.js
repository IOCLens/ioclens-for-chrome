/**
 * Crypto Utilities for API Key Encryption
 * Provides secure encryption/decryption of sensitive data using Web Crypto API
 *
 * Security features:
 * - AES-GCM 256-bit encryption
 * - PBKDF2 key derivation with 100,000 iterations
 * - Random IV for each encryption
 * - Per-browser unique salt derived from installation
 */

const CryptoUtils = {
  // Encryption parameters
  PBKDF2_ITERATIONS: 100000,
  AES_KEY_LENGTH: 256,

  /**
   * Generate a master password from browser fingerprint
   * This provides basic encryption without requiring user password entry
   * NOTE: This is security by obscurity - protects against casual snooping
   * but not against determined attackers with access to the extension code
   *
   * @returns {Promise<string>} Master password
   */
  async getMasterPassword() {
    // Try to get or create a unique installation ID
    const result = await chrome.storage.local.get(['installationId']);

    if (result.installationId) {
      return result.installationId;
    }

    // Generate new installation ID (crypto-random)
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    const installationId = Array.from(randomBytes, byte =>
      byte.toString(16).padStart(2, '0')
    ).join('');

    await chrome.storage.local.set({ installationId });
    return installationId;
  },

  /**
   * Generate a unique salt for PBKDF2
   * Uses installation timestamp to ensure uniqueness per install
   *
   * @returns {Promise<Uint8Array>} Salt bytes
   */
  async getSalt() {
    const result = await chrome.storage.local.get(['installData']);
    const installDate = result.installData?.installDate || Date.now();

    // Combine fixed string with install date for deterministic salt
    const saltString = `threat-intel-extension-${installDate}`;
    return new TextEncoder().encode(saltString);
  },

  /**
   * Derive encryption key from master password using PBKDF2
   *
   * @param {string} masterPassword - Master password
   * @returns {Promise<CryptoKey>} AES-GCM encryption key
   */
  async deriveKey(masterPassword) {
    const encoder = new TextEncoder();
    const salt = await this.getSalt();

    // Import master password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(masterPassword),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    // Derive AES-GCM key using PBKDF2
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: this.PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: this.AES_KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );

    return key;
  },

  /**
   * Encrypt a string value using AES-GCM
   *
   * @param {string} plaintext - Value to encrypt
   * @returns {Promise<Object>} Encrypted data with IV
   */
  async encrypt(plaintext) {
    if (!plaintext || typeof plaintext !== 'string') {
      throw new Error('Invalid plaintext provided for encryption');
    }

    const encoder = new TextEncoder();
    const masterPassword = await this.getMasterPassword();
    const key = await this.deriveKey(masterPassword);

    // Generate random IV (96 bits for AES-GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(plaintext)
    );

    return {
      ciphertext: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv),
      version: 1 // For future migration support
    };
  },

  /**
   * Decrypt an encrypted value
   *
   * @param {Object} encryptedData - Object with ciphertext and IV
   * @returns {Promise<string>} Decrypted plaintext
   */
  async decrypt(encryptedData) {
    if (!encryptedData || !encryptedData.ciphertext || !encryptedData.iv) {
      throw new Error('Invalid encrypted data structure');
    }

    const masterPassword = await this.getMasterPassword();
    const key = await this.deriveKey(masterPassword);

    // Convert arrays back to Uint8Array
    const ciphertext = new Uint8Array(encryptedData.ciphertext);
    const iv = new Uint8Array(encryptedData.iv);

    try {
      // Decrypt
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      throw new Error('Decryption failed - data may be corrupted or tampered');
    }
  },

  /**
   * Check if a value is encrypted (has encryption metadata)
   *
   * @param {any} value - Value to check
   * @returns {boolean} True if value appears to be encrypted
   */
  isEncrypted(value) {
    return value &&
           typeof value === 'object' &&
           Array.isArray(value.ciphertext) &&
           Array.isArray(value.iv) &&
           value.version !== undefined;
  },

  /**
   * Migrate plaintext API keys to encrypted format
   * This is called automatically when loading config
   *
   * @param {Object} apiConfig - API configuration object
   * @returns {Promise<Object>} Migrated config with encrypted keys
   */
  async migrateToEncrypted(apiConfig) {
    if (!apiConfig || !apiConfig.modules) {
      return apiConfig;
    }

    let migrationNeeded = false;
    const migratedConfig = { ...apiConfig, modules: { ...apiConfig.modules } };

    for (const [apiName, config] of Object.entries(apiConfig.modules)) {
      if (config.key && typeof config.key === 'string' && config.key.length > 0) {
        // Plaintext key found - encrypt it
        console.log(`[CryptoUtils] Migrating ${apiName} API key to encrypted format`);
        migratedConfig.modules[apiName] = {
          ...config,
          key: await this.encrypt(config.key)
        };
        migrationNeeded = true;
      }
    }

    if (migrationNeeded) {
      console.log('[CryptoUtils] Migration complete - encrypted API keys saved');
      await chrome.storage.local.set({ apiConfig: migratedConfig });
    }

    return migratedConfig;
  },

  /**
   * Decrypt all API keys in configuration
   *
   * @param {Object} apiConfig - API configuration with encrypted keys
   * @returns {Promise<Object>} Config with decrypted keys
   */
  async decryptConfig(apiConfig) {
    if (!apiConfig || !apiConfig.modules) {
      return apiConfig;
    }

    const decryptedConfig = { ...apiConfig, modules: {} };

    for (const [apiName, config] of Object.entries(apiConfig.modules)) {
      if (this.isEncrypted(config.key)) {
        try {
          decryptedConfig.modules[apiName] = {
            ...config,
            key: await this.decrypt(config.key)
          };
        } catch (error) {
          console.error(`[CryptoUtils] Failed to decrypt ${apiName} key:`, error);
          // Keep original encrypted value on failure
          decryptedConfig.modules[apiName] = config;
        }
      } else {
        // Not encrypted or empty key
        decryptedConfig.modules[apiName] = config;
      }
    }

    return decryptedConfig;
  }
};

// Make available globally
if (typeof window !== 'undefined') {
  window.CryptoUtils = CryptoUtils;
}
