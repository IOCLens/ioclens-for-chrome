# Changelog

All notable changes to IOCLens will be documented in this file.

## [1.1.8] - 2026-02-03 (versionning problem with chrome store, so 1.1.6 -> 1.1.8)

### Added
- **"Give me Five" button**: New button in settings page to rate IOCLens on Chrome Web Store
- **Official Website button**: New button in settings page linking to https://ioclens.github.io/landing-page/

### Removed
- **PRO badge removed from popup footer**: Simplified footer display

## [1.1.5] - 2026-01-05

### Fixed
- **Critical config bug**: Settings showing APIs as "enabled" but not actually working
  - Fixed InternetDB and GreyNoise not appearing for users who upgraded from older versions
  - Old saved configs now automatically merge with new defaults when loading settings
  - Removed hardcoded `checked` attributes from HTML that were overriding actual config state
  - Config auto-upgrade happens seamlessly in both settings page and popup
  - **Impact**: Users with v1.1.2 or earlier configs now automatically get all new free APIs (InternetDB, GreyNoise)

### Changed
- Improved config loading logic in `options.js` and `popup.js`
  - Settings now merge saved config with defaults to ensure all modules exist
  - Prevents future issues when new APIs are added to the extension
  - Better handling of missing or incomplete config structures
- Settings UI now always reflects actual stored configuration state

### Technical
- Config merging uses JavaScript spread operators to combine `DEFAULT_CONFIG` with saved config
- Auto-saves upgraded config to storage on first load after update
- Future-proof: New free APIs will automatically activate for existing users

## [1.1.4] - 2026-01-04

### Added
- **Export JSON Button**: New button in popup to download enrichment data as JSON file
  - Located between "Copy JSON" and "Refresh" buttons
  - Downloads with descriptive filename: `ioclens_<IOC-value>_<date>.json`
  - Includes all enrichment data for offline analysis and reporting

- **Improved Scoring System v3.0**: New hierarchical decision-tree scoring algorithm
  - 13 priority-based rules for more accurate threat assessment
  - Better handling of conflicting evidence from multiple sources
  - Coverage-aware confidence adjustment (downgrades confidence when few sources respond)
  - Critical source detection (URLhaus/ThreatFox detections = instant HIGH confidence)
  - Clearer verdict messages explaining the reasoning
  - Added coverage metrics: shows "limited coverage: X/Y sources" when APIs fail

### Removed
- **Removed ipapi.co module**: Simplified geolocation to use only ip-api.com
  - ip-api.com provides all necessary geolocation data
  - Reduced complexity and maintenance burden
  - FREE tier geolocation still fully functional

### Changed
- **Manifest V3 Compliance**: Updated manifest.json for full Manifest V3 compliance
  - Changed `options_page` to `options_ui` (V3 standard)
  - Updated description to mention free sources (VirusTotal, GreyNoise, InternetDB)
  - Cleaned up formatting
- InternetDB now always shows in external links section, even when no data is found
- Confidence levels now reflect both verdict quality AND data completeness

## [1.1.3] - 2025-12-31

### Added
- **GreyNoise FREE tier**: GreyNoise Community API now available for all users without license
  - Detects malicious, suspicious, and benign internet scanners
  - No API key required (Community API)
  - Rate limited to 50 requests/week
  - Enabled by default for all users

- **InternetDB FREE tier**: Shodan InternetDB now available for all users without license
  - Free IP enrichment service by Shodan
  - Shows open ports, CVEs, technologies (CPEs), and tags
  - No API key required
  - Unlimited requests
  - Enabled by default for all users

### Fixed
- GreyNoise now properly handles "suspicious" classification (previously only handled malicious/benign/unknown)
- GreyNoise suspicious IPs now appear in "Threats Detected" section with appropriate severity
- Fixed GreyNoise verdict display when actor name is "unknown" (now shows descriptive message instead)

### Changed
- FREE tier now includes: VirusTotal + GreyNoise + InternetDB + IP-API geolocation
- PRO tier still includes: All FREE services + AbuseIPDB, Shodan, URLhaus, ThreatFox, AlienVault OTX + JSON export + Priority support


