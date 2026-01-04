# 🛡️ IoCLens - SOC Threat Intel Enrichment


![Version](https://img.shields.io/badge/version-1.1.4-blue.svg)
![Chrome](https://img.shields.io/badge/platform-Chrome%20%7C%20Edge-success.svg)
![Manifest](https://img.shields.io/badge/manifest-v3-orange.svg)
![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)

[![Available in the Chrome Web Store](https://raw.githubusercontent.com/alrra/browser-logos/master/src/chrome/chrome_48x48.png) **Get it on Chrome Web Store**](https://chromewebstore.google.com/detail/ioclens-threat-intel-enri/ileoihlcgdihnnahkdnhebahmljkknnj)

Chrome Extension (Manifest V3) to instantly enrich Indicators of Compromise (IOCs) during SOC investigations. Save time by aggregating multiple threat intelligence sources in one click.

## Features
- **Auto-Detection**: Recognizes IPv4 addresses and domains in selected text.
- **Contextual Menu**: Right-click → "Enrich IOC" to launch analysis.
- **Multi-Source Aggregation**: Pulls data from VirusTotal, GreyNoise, and more.
- **Privacy-First**: Zero telemetry. Requests are sent directly from your browser to providers.
- **FREE Tier**: VirusTotal + GreyNoise (Community API) + InternetDB.
- **PRO Tier**: Advanced sources (AbuseIPDB, Shodan, URLhaus, ThreatFox, AlienVault OTX) + CSV export + Priority support.

## 🚀 Get the Best Experience

While the core logic is open-source for transparency, the **Official Chrome Store version** is the recommended way to use IOCLens.

| Feature | Chrome Web Store (Official) | Manual Clone (Dev Mode) |
| :--- | :---: | :---: |
| **Updates** | ⚡ **Automatic** | ❌ Manual (Must re-pull) |
| **Security** | ✅ **Verified by Google** | ⚠️ Self-audited |
| **FREE Sources** (VirusTotal, GreyNoise) | ✅ **Included** | ✅ **Included** |
| **PRO Sources** (AbuseIPDB, Shodan, URLhaus, ThreatFox, OTX) | ✅ **Included** | ❌ Not Available |
| **Priority Support** | ✅ **Yes** | ❌ Best effort |
| **Browser Compatibility** | Chrome, Brave, Edge, Opera | Experimental |

[<img src="https://developer.chrome.com/static/images/badges/en/promote_badge_large.png" alt="Available in the Chrome Web Store" width="200">](https://chromewebstore.google.com/detail/ioclens-threat-intel-enri/ileoihlcgdihnnahkdnhebahmljkknnj)

Buying a license is the best way to support the development of this tool and keep it privacy-first.

## Instructions

- **Get a free API key** on https://www.virustotal.com/
- **Set the key in settings**

## 📊 Service Tiers

### FREE Tier (No License Required)

- ✅ **VirusTotal** - Multi-engine malware scanning (requires free API key)
- ✅ **GreyNoise** - Internet noise intelligence (Community API, no key needed, 50 req/week)
- ✅ **InternetDB** - IP enrichment with ports, CVEs, and technologies (by Shodan, no key needed, unlimited)
- ✅ **IP-API** - IP geolocation data (always free)

### PRO Tier (License Required)

**Additional Threat Intelligence Sources:**
- 🔒 **AbuseIPDB** - IP abuse reputation database
- 🔒 **Shodan** - Internet-connected device search engine
- 🔒 **URLhaus** - Malware URL database (abuse.ch)
- 🔒 **ThreatFox** - IOC database (abuse.ch)
- 🔒 **AlienVault OTX** - Open threat intelligence platform

**Advanced Features:**
- 🔒 CSV export functionality
- 🔒 Priority email support
- 🔒 Early access to new features

[Get PRO License](https://chromewebstore.google.com/detail/ioclens-threat-intel-enri/ileoihlcgdihnnahkdnhebahmljkknnj)

## Screenshots

Pop-Up

![IOCLens Screenshot](./assets/popup1.png)
![IOCLens Screenshot](./assets/popup2.png)

Settings

![IOCLens Screenshot](./assets/settings1.png)
![IOCLens Screenshot](./assets/settings2.png)
