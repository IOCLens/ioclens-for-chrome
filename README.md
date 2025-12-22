# SOC Threat Intel Enrichment Extension

Extension Chrome (Manifest V3) pour enrichir automatiquement les IOCs (Indicators of Compromise) pendant vos investigations SOC. Gagnez du temps en agrégeant plusieurs sources de threat intelligence en un seul clic.

## Fonctionnalités

- **Détection automatique** : Reconnaît les IPs v4 et domaines sélectionnés
- **Menu contextuel** : Clic droit → "Enrich IOC" pour lancer l'enrichissement
- **Enrichissement multi-sources** : Agrège les données de threat intelligence
- **Interface claire** : Affichage organisé des informations (réputation, géolocalisation, menaces)
- **Export JSON** : Copie rapide des données pour vos rapports
- **Cache intelligent** : Évite les requêtes redondantes (cache de 5 minutes)
- **Gestion d'erreurs** : Timeout et messages clairs en cas de problème

## Prérequis

- Chrome ou Edge (ou tout navigateur compatible Manifest V3)
- Connexion internet pour l'enrichissement (la détection IOC fonctionne offline)

## Installation en mode développeur

### 1. Télécharger le projet

```bash
git clone <url-du-repo>
cd threat-intel-extension
```

Ou téléchargez et décompressez le dossier `threat-intel-extension`.

### 2. Charger l'extension dans Chrome

1. Ouvrez Chrome et allez dans `chrome://extensions/`
2. Activez le **"Mode développeur"** (coin supérieur droit)
3. Cliquez sur **"Charger l'extension non empaquetée"**
4. Sélectionnez le dossier `threat-intel-extension`
5. L'extension apparaît dans votre liste avec l'icône 🔍

### 3. Ajouter les icônes (optionnel)

Par défaut, l'extension fonctionne sans icônes. Pour ajouter des icônes personnalisées :

1. Créez ou téléchargez des icônes PNG (16x16, 48x48, 128x128)
2. Placez-les dans le dossier `icons/` avec les noms :
   - `icon16.png`
   - `icon48.png`
   - `icon128.png`
3. Rechargez l'extension dans `chrome://extensions/`

**Note** : Vous pouvez utiliser un générateur d'icônes en ligne ou simplement utiliser un emoji converti en PNG.

## Utilisation

### Exemple 1 : Enrichir une IP

1. Naviguez vers une page contenant des logs ou des IOCs (par exemple, un dashboard SIEM)
2. Sélectionnez une IP v4 : `8.8.8.8`
3. **Clic droit** → **"Enrich IOC: 8.8.8.8"**
4. Une popup s'ouvre avec les informations enrichies :
   - Réputation (score visuel)
   - Géolocalisation (pays, ville, ISP, ASN)
   - Menaces détectées (proxy, VPN, Tor, etc.)
   - Détails techniques

### Exemple 2 : Enrichir un domaine

1. Sélectionnez un domaine : `malicious-domain.com`
2. **Clic droit** → **"Enrich IOC: malicious-domain.com"**
3. La popup affiche les données disponibles (enrichissement domaine limité dans ce POC)

### Exemple 3 : Export JSON

1. Après avoir enrichi un IOC, cliquez sur **"📋 Copy JSON"**
2. Les données complètes sont copiées dans votre presse-papier
3. Collez dans votre rapport, SIEM, ou outil de documentation

### IOCs de test

Voici quelques IOCs pour tester l'extension :

**IPs légitimes :**
- `8.8.8.8` (Google DNS)
- `1.1.1.1` (Cloudflare DNS)

**IPs suspectes (exemples) :**
- `185.220.101.50` (Tor exit node potentiel)
- Testez avec des IPs de votre propre veille

**Domaines :**
- `google.com` (légitime)
- `example.com` (test)

## Configuration des APIs

### APIs utilisées par défaut (sans clé)

Le POC utilise **ip-api.com** qui est gratuit sans clé API :
- **Limite** : 45 requêtes/minute
- **Données** : Géolocalisation, ISP, ASN, flags (proxy, hosting, mobile)

### Ajouter d'autres APIs (optionnel)

Pour étendre les fonctionnalités, vous pouvez ajouter ces APIs gratuites :

#### 1. VirusTotal (optionnel)

- **Inscription** : https://www.virustotal.com/gui/join-us
- **Clé gratuite** : 4 requêtes/minute
- **Configuration** : Ajoutez votre clé dans `popup/popup.js` ligne ~15

```javascript
const API_CONFIG = {
  ipApi: { /* ... */ },
  virusTotal: {
    apiKey: 'VOTRE_CLE_VIRUSTOTAL',
    url: 'https://www.virustotal.com/api/v3/ip_addresses/',
    timeout: 5000
  }
};
```

#### 2. AbuseIPDB (optionnel)

- **Inscription** : https://www.abuseipdb.com/register
- **Clé gratuite** : 1000 requêtes/jour
- **Configuration** : Similaire à VirusTotal

**Note** : Pour le POC, l'extension fonctionne parfaitement avec ip-api.com seul.

## Structure du projet

```
threat-intel-extension/
├── manifest.json           # Configuration Manifest V3
├── background.js           # Service worker (menu contextuel, validation IOC)
├── popup/
│   ├── popup.html         # Interface de la popup
│   ├── popup.js           # Logique d'enrichissement et affichage
│   ├── popup.css          # Design sobre et professionnel
├── icons/                 # Icônes de l'extension (optionnel)
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── README.md              # Ce fichier
```

## Fonctionnement technique

### 1. Détection IOC (background.js)

```javascript
// Regex de validation
const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
const domain = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i
```

### 2. Enrichissement (popup.js)

- **Requête HTTP** vers ip-api.com avec timeout de 5 secondes
- **Analyse heuristique** : Détection de proxy/VPN/Tor via mots-clés dans ASN/ISP
- **Score de réputation** : Calculé selon les flags (proxy: -15, hosting: -10, mobile: +10)

### 3. Cache (chrome.storage.local)

- **Durée** : 5 minutes par IOC
- **Format** : `cache_ipv4:8.8.8.8` → `{data: {...}, timestamp: 1234567890}`
- **Refresh** : Bouton "🔄 Refresh" force le bypass du cache

### 4. Sécurité

- **XSS Prevention** : Fonction `escapeHtml()` sur tous les inputs
- **Timeout** : 5 secondes max par requête API
- **CSP** : Pas d'eval(), pas d'inline scripts

## Limitations du POC

### Fonctionnalités limitées

1. **Enrichissement domaine** : Basique dans ce POC (pas d'APIs DNS/WHOIS intégrées)
2. **Hashes** : Non supportés dans cette version (MD5, SHA256, etc.)
3. **URLs** : Non supportées (uniquement IPs et domaines)
4. **Historique** : Pas de base de données locale des IOCs analysés

### Limitations APIs gratuites

- **ip-api.com** : 45 req/min (suffisant pour usage SOC normal)
- **Pas de VirusTotal** : Nécessite clé API (4 req/min tier gratuit)
- **Pas de threat feeds** : Pas d'intégration avec MISP, OpenCTI, etc.

### Améliorations futures possibles

- Ajouter support des hashes (MD5, SHA1, SHA256)
- Intégrer VirusTotal, AbuseIPDB avec clés API
- Historique local des IOCs enrichis
- Export CSV/JSON vers fichier
- Dark mode (actuellement un seul thème sombre)
- Support des URLs complètes

## Dépannage

### L'extension ne détecte pas mon IOC

- Vérifiez que le texte sélectionné est bien une **IP v4** valide (ex: `192.168.1.1`)
- Les domaines doivent avoir un TLD valide (ex: `.com`, `.org`)
- Pas d'espaces avant/après (l'extension trim automatiquement)

### "Erreur: Request timeout"

- Votre connexion internet est lente ou ip-api.com est inaccessible
- Augmentez le timeout dans `popup.js` ligne ~11 : `timeout: 10000` (10 secondes)

### La popup ne s'ouvre pas

- Vérifiez dans `chrome://extensions/` que l'extension est bien activée
- Rechargez l'extension (bouton circulaire ↻)
- Consultez les logs dans `chrome://extensions/` → "Détails" → "Vue d'arrière-plan"

### Cache trop agressif

- Utilisez le bouton **"🔄 Refresh"** pour forcer le bypass
- Modifiez la durée du cache dans `popup.js` ligne ~576 : `if (age < 5 * 60 * 1000)` → changez `5` (minutes)

## Développement et extension du code

### Ajouter une nouvelle API

1. Ouvrez `popup/popup.js`
2. Ajoutez la config dans `API_CONFIG` (ligne ~11)
3. Créez une fonction `async enrichXXX(ioc)` similaire à `enrichIP()`
4. Appelez cette fonction dans `enrichIOC()` (ligne ~57)

### Modifier le score de réputation

Éditez `determineIPReputation()` dans `popup.js` ligne ~203 :

```javascript
// Exemples d'ajustements
if (data.country === 'RU' || data.country === 'CN') {
  score -= 5;  // Ajuster selon votre politique
}
```

### Changer les seuils de réputation

Ligne ~230 dans `popup.js` :

```javascript
if (score >= 70) status = 'safe';       // Modifier 70
else if (score >= 40) status = 'suspicious';  // Modifier 40
else status = 'malicious';
```

## Sécurité et confidentialité

- **Données locales** : Tout le traitement est côté client (pas de backend externe)
- **Cache local** : Stocké dans `chrome.storage.local` (chiffré par le navigateur)
- **APIs tierces** : Les requêtes sont envoyées directement depuis votre navigateur vers les APIs publiques
- **Pas de télémétrie** : Aucune donnée n'est envoyée à un serveur tiers (sauf les APIs threat intel)

## Contribution

Ce POC est conçu pour être simple et extensible. N'hésitez pas à :

- Ajouter de nouvelles APIs threat intel
- Améliorer l'UI/UX
- Supporter d'autres types d'IOCs (hashes, URLs)
- Ajouter des exports (CSV, PDF, etc.)

## Licence

Code libre d'utilisation pour vos besoins SOC et d'investigation.

## Support

En cas de problème :

1. Vérifiez les logs dans la console (`chrome://extensions/` → Vue d'arrière-plan)
2. Testez avec une IP simple comme `8.8.8.8`
3. Vérifiez que ip-api.com est accessible depuis votre réseau

---

**Happy hunting! 🔍🛡️**
