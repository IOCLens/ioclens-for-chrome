# Privacy Policy for IOCLens

**Last Updated:** 2025-01-21

## Introduction

IOCLens is a browser extension designed for security professionals to enrich Indicators of Compromise (IOCs) with threat intelligence data. We take your privacy seriously and are committed to transparency about data handling.

## Data Collection and Usage

### What We DO:

1. **Local Data Storage**
   - Store API keys **encrypted** in your browser's local storage (`chrome.storage.local`)
   - Store your license key (if PRO user) encrypted locally
   - Cache threat intelligence results locally for 5 minutes to improve performance
   - Store extension settings and preferences locally

2. **Direct API Requests**
   - When you analyze an IOC, your browser makes **direct requests** to threat intelligence providers (VirusTotal, Shodan, etc.)
   - These requests go from your browser → threat intel provider (NOT through our servers)
   - Each provider has their own privacy policy (links below)

### What We DON'T DO:

1. **We NEVER collect or store:**
   - Your browsing history
   - IOCs you analyze
   - API keys (we only store them encrypted locally)
   - User tracking data
   - Analytics or telemetry

2. **We NEVER transmit data to IOCLens servers:**
   - No IOCs are sent to our servers
   - No usage statistics are collected
   - No phone-home functionality

3. **We NEVER sync data to cloud:**
   - API keys are stored in `chrome.storage.local` (NOT `chrome.storage.sync`)
   - This means your API keys are never sent to Google's sync servers

## License Verification (PRO Users Only)

If you purchase a PRO license:

- License verification happens **only when you activate your license**
- Only your license key is transmitted to our verification endpoint (Vercel)
- No IOCs, browsing history, or API keys are transmitted during verification
- Verification is one-time (not continuous)

## Third-Party Services

When you analyze an IOC, your browser contacts these third-party services directly:

| Service | Privacy Policy |
|---------|---------------|
| VirusTotal | https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy |
| AbuseIPDB | https://www.abuseipdb.com/privacy |
| Shodan | https://account.shodan.io/privacy |
| ip-api.com | https://ip-api.com/docs/legal |
| URLhaus | https://abuse.ch/privacy/ |
| ThreatFox | https://abuse.ch/privacy/ |
| AlienVault OTX | https://cybersecurity.att.com/legal/privacy-policy |
| GreyNoise | https://www.greynoise.io/privacy |

**Note:** Each service has its own privacy policy and data retention practices. Please review them before using their APIs.

## Data Retention

- **Cache:** Threat intelligence results are cached locally for 5 minutes, then automatically deleted
- **API Keys:** Stored encrypted until you manually delete them in settings
- **License Key:** Stored encrypted until you deactivate your license

## Security Measures

1. **Encryption:** All API keys and license keys are encrypted using AES-GCM 256-bit encryption before storage
2. **Input Validation:** All IOC inputs are validated to prevent injection attacks
3. **Rate Limiting:** API requests are rate-limited to prevent abuse
4. **Origin Validation:** The extension only accepts commands from itself (not from external webpages)

## Permissions Explanation

IOCLens requests the following permissions:

| Permission | Why We Need It |
|------------|---------------|
| `contextMenus` | To add "Enrich IOC" to your right-click menu |
| `storage` | To store encrypted API keys and settings locally |
| `notifications` | To show error messages when IOC validation fails |
| `host_permissions` | To make API requests to threat intelligence providers |

**Note:** We do NOT request `activeTab`, `tabs`, or `webNavigation` permissions. This means we cannot see your browsing history or track your activity.

## Your Rights (GDPR Compliance)

As a user in the EU, you have the right to:

1. **Access:** View what data is stored (check `chrome.storage.local` in DevTools)
2. **Deletion:** Delete all extension data by:
   - Uninstalling the extension, OR
   - Clicking "Reset Settings" in Options page
3. **Portability:** Export your API configuration as JSON

## Changes to This Policy

We will notify users of any material changes to this privacy policy by:
- Updating the "Last Updated" date
- Posting a notice in the extension's options page

## Contact

For privacy questions or concerns, please contact:
- Email: privacy@your-domain.com
- Website: https://your-website.com/privacy

## Open Source

IOCLens is open source. You can review the code to verify our privacy claims:
- GitHub: https://github.com/your-username/ioclens

---

**Summary:** IOCLens does not collect, store, or transmit your data. All threat intelligence lookups happen directly between your browser and the threat intel providers. Your API keys are encrypted and stored locally.
