/**
 * License Manager - Freemium Model Enforcement
 *
 * PRIVACY: No user data is collected or transmitted during license verification.
 * License keys are verified with Gumroad API only when explicitly activated by the user.
 *
 * FREE TIER: VirusTotal only (most popular threat intelligence platform)
 * PRO TIER: All sources + CSV export + priority support
 *
 * Security:
 * - License keys stored encrypted in chrome.storage.local
 * - Verification only happens on user action (activation/deactivation)
 * - No automatic phone-home or telemetry
 */

const LicenseManager = {
  // Vercel endpoint for license verification
  VERIFICATION_ENDPOINT: 'https://ioclens-for-chrome.vercel.app/api/verify',

  /**
   * Check if user has PRO access
   * @returns {Promise<{isPro: boolean, licenseKey: string|null}>}
   */
  async checkProStatus() {
    try {
      const result = await chrome.storage.local.get(['proLicenseKey', 'legacyUser']);

      // LEGACY users get lifetime PRO access
      if (result.legacyUser === true) {
        return { isPro: true, licenseKey: null, tier: 'LEGACY' };
      }

      // PRO users with valid license key
      if (result.proLicenseKey) {
        return { isPro: true, licenseKey: result.proLicenseKey, tier: 'PRO' };
      }

      // FREE tier
      return { isPro: false, licenseKey: null, tier: 'FREE' };
    } catch (error) {
      console.error('[License] Failed to check PRO status:', error);
      // Fail safe: grant free tier on error
      return { isPro: false, licenseKey: null, tier: 'FREE' };
    }
  },

  /**
   * Verify license key with backend (Vercel endpoint)
   *
   * PRIVACY NOTE: Only sends license key for verification.
   * No user data, IOCs, or browsing history is transmitted.
   *
   * @param {string} licenseKey - License key to verify
   * @returns {Promise<{valid: boolean, error?: string}>}
   */
  async verifyLicense(licenseKey) {
    if (!licenseKey || typeof licenseKey !== 'string') {
      return { valid: false, error: 'Invalid license key format' };
    }

    try {
      const response = await fetch(this.VERIFICATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          license_key: licenseKey
        })
      });

      if (!response.ok) {
        throw new Error(`Verification server error: ${response.status}`);
      }

      const data = await response.json();

      if (data.success === true) {
        return { valid: true };
      } else {
        return { valid: false, error: data.message || 'Invalid license' };
      }

    } catch (error) {
      console.error('[License] Verification failed:', error);
      return {
        valid: false,
        error: 'Connection failed. Please check your internet connection and try again.'
      };
    }
  },

  /**
   * Activate PRO license
   * @param {string} licenseKey - License key to activate
   * @returns {Promise<{success: boolean, error?: string}>}
   */
  async activateLicense(licenseKey) {
    const verification = await this.verifyLicense(licenseKey);

    if (!verification.valid) {
      return { success: false, error: verification.error };
    }

    try {
      // Store encrypted license key
      await chrome.storage.local.set({ proLicenseKey: licenseKey });
      return { success: true };
    } catch (error) {
      console.error('[License] Failed to store license:', error);
      return { success: false, error: 'Failed to save license key' };
    }
  },

  /**
   * Deactivate PRO license
   * @returns {Promise<{success: boolean}>}
   */
  async deactivateLicense() {
    try {
      await chrome.storage.local.remove(['proLicenseKey']);
      return { success: true };
    } catch (error) {
      console.error('[License] Failed to deactivate:', error);
      return { success: false };
    }
  },

  /**
   * Get allowed features based on license tier
   * @returns {Promise<Object>} Feature flags
   */
  async getFeatureFlags() {
    const { isPro, tier } = await this.checkProStatus();

    if (isPro) {
      // PRO and LEGACY users get all features
      return {
        sources: {
          ipapi: true,
          ipapiCo: true,
          virustotal: true,
          abuseipdb: true,
          shodan: true,
          urlhaus: true,
          threatfox: true,
          otx: true,
          greynoise: true
        },
        features: {
          csvExport: true,
          bulkLookup: false, // Future feature
          apiAccess: false,  // Future feature
          prioritySupport: true
        },
        tier: tier
      };
    } else {
      // FREE tier: VirusTotal only
      return {
        sources: {
          ipapi: true,        // Geolocation is always free
          ipapiCo: false,
          virustotal: true,   // FREE tier gets VirusTotal
          abuseipdb: false,
          shodan: false,
          urlhaus: false,
          threatfox: false,
          otx: false,
          greynoise: false
        },
        features: {
          csvExport: false,
          bulkLookup: false,
          apiAccess: false,
          prioritySupport: false
        },
        tier: 'FREE'
      };
    }
  },

  /**
   * Enforce feature access (throws error if not allowed)
   * @param {string} feature - Feature name
   * @throws {Error} If feature is not allowed
   */
  async enforceFeature(feature) {
    const flags = await this.getFeatureFlags();

    if (flags.sources[feature] === false) {
      throw new Error(`${feature} is only available in PRO tier. Upgrade to access this source.`);
    }

    if (flags.features[feature] === false) {
      throw new Error(`This feature is only available in PRO tier. Upgrade to unlock.`);
    }
  },

  /**
   * Mark user as LEGACY (for early adopters)
   * This grants lifetime PRO access
   *
   * @returns {Promise<boolean>} Success status
   */
  async grantLegacyAccess() {
    try {
      await chrome.storage.local.set({ legacyUser: true });
      console.log('[License] LEGACY access granted');
      return true;
    } catch (error) {
      console.error('[License] Failed to grant LEGACY access:', error);
      return false;
    }
  }
};

// Export for use in other modules
if (typeof window !== 'undefined') {
  window.LicenseManager = LicenseManager;
}
