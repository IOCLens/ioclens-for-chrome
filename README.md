# 🛡️ IoCLens - SOC Threat Intel Enrichment

![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)
![Chrome](https://img.shields.io/badge/platform-Chrome%20%7C%20Edge-success.svg)
![Manifest](https://img.shields.io/badge/manifest-v3-orange.svg)
![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)

> **L'outil indispensable pour les analystes SOC.** Enrichissez instantanément les indicateurs de compromission (IOCs) sans jamais quitter votre onglet.

---

## 📸 Aperçu

**IoCLens** est une extension Chrome (Manifest V3) conçue pour accélérer les investigations de cybersécurité. Elle agrège automatiquement les données de Threat Intelligence sur les IPs, hashs et domaines présents sur vos pages web, tout en respectant une politique stricte de confidentialité (zéro exfiltration de données).

## 📑 Table des Matières

- [Fonctionnalités Clés](#-fonctionnalités-clés)
- [Architecture & Confidentialité](#-architecture--confidentialité)
- [Installation](#-installation)
- [Configuration Avancée](#-configuration-avancée)
- [Stack Technique](#-stack-technique)
- [Contribution](#-contribution)
- [Support](#-support)

---

## ✨ Fonctionnalités Clés

| Fonctionnalité | Description |
| :--- | :--- |
| **🚀 Enrichissement Instantané** | Clic droit sur n'importe quel IOC (IP, Hash, URL) → "Enrich IOC". |
| **🧠 Multi-Sources** | Agrégation automatique via VirusTotal, Shodan, AbuseIPDB, etc. |
| **⚡ Cache Intelligent** | Système de cache local (TTL 5 min) pour économiser vos quotas API. |
| **📊 Visualisation Claire** | Score de réputation, géolocalisation et tags de menace en un coup d'œil. |
| **🔒 Privacy-First** | Aucune donnée de navigation n'est envoyée à nos serveurs. |
| **📂 Export Rapide** | Copiez les résultats en JSON/CSV pour vos rapports d'incident. |

---

## 🔒 Architecture & Confidentialité

La sécurité est au cœur de **IoCLens**. Contrairement à d'autres extensions, nous n'agissons pas comme un "homme du milieu".

* **Traitement Local :** Tout le code s'exécute dans votre navigateur.
* **Requêtes Directes :** Votre navigateur interroge directement les APIs tierces (ex: `browser` → `VirusTotal`).
* **Stockage Chiffré :** Les clés API et le cache sont stockés via `chrome.storage.local` (chiffré par l'OS).
* **Zéro Télémétrie :** Nous ne collectons ni votre historique, ni les IOCs que vous analysez.

---

## 📥 Installation

### Depuis les sources (Mode Développeur)

1.  **Cloner le dépôt :**
    ```bash
    git clone [https://github.com/votre-username/ioclens.git](https://github.com/votre-username/ioclens.git)
    cd ioclens
    ```
2.  **Charger dans Chrome :**
    * Ouvrez `chrome://extensions/` dans votre navigateur.
    * Activez le **Mode développeur** (switch en haut à droite).
    * Cliquez sur **Charger l'extension non empaquetée**.
    * Sélectionnez le dossier du projet.

### Prérequis
* Google Chrome, Microsoft Edge ou Brave.
* Connexion Internet active (pour interroger les APIs).

---

## ⚙️ Configuration Avancée

L'extension est conçue pour être modulaire. Vous pouvez ajuster la logique de réputation directement dans le code.

### Ajuster le Scoring (Fichier `popup.js`)

Pour modifier la sensibilité du score de réputation, éditez la fonction `determineIPReputation()` :

```javascript
// Exemple : Pénaliser certains pays
if (data.country === 'XX' || data.country === 'YY') {
  score -= 10; // Réduit le score de confiance
}
