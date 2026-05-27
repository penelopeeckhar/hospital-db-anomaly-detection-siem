# 🏥 hospital-db-anomaly-detection-siem

> Système SIEM léger de détection et journalisation des accès anormaux aux bases de données médicales — Stage d'initiation au CHU Hassan II de Fès

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey?logo=flask)
![MySQL](https://img.shields.io/badge/MySQL-8.0-orange?logo=mysql)
![SQLMap](https://img.shields.io/badge/SQLMap-1.9.x-red)
![License](https://img.shields.io/badge/Licence-Académique-green)

---

## 📋 Table des matières

- [Contexte](#-contexte)
- [Fonctionnalités](#-fonctionnalités)
- [Architecture du projet](#-architecture-du-projet)
- [Stack technique](#-stack-technique)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Utilisation](#-utilisation)
- [Structure des fichiers](#-structure-des-fichiers)
- [Détection des anomalies](#-détection-des-anomalies)
- [Interface web Flask](#-interface-web-flask)
- [Limitations et pistes d'amélioration](#-limitations-et-pistes-damélioration)
- [Auteur](#-auteur)

---

## 🏥 Contexte

Ce projet a été développé dans le cadre d'un **stage d'initiation d'un mois** (01/07/2025 – 01/08/2025) au sein du **Centre Hospitalier Universitaire Hassan II de Fès**, sous la supervision de **M. Soufiane ELAKRAA** (encadrant CHU) et **M. Imadeddine Mountasser** (encadrant pédagogique ENSA Fès).

**Problématique :** Comment identifier automatiquement des comportements anormaux dans l'accès aux données médicales, tout en garantissant traçabilité complète et réactivité face aux incidents ?

Le système répond aux enjeux de cybersécurité médicale en surveillant les accès à une base de données hospitalière MySQL, en détectant les comportements suspects, et en alertant automatiquement le Responsable du Système d'Information (RSI).

---

## ✅ Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| 🔍 **Détection d'anomalies** | Accès hors horaires (22h–6h), requêtes répétées, tentatives refusées multiples, requêtes échouées |
| 📋 **Journalisation** | Enregistrement automatique dans `anomalies_detectees` avec horodatage, utilisateur, gravité |
| 📧 **Alertes email automatiques** | Envoi de rapport CSV quotidien et alertes SQLi via SMTP/Gmail |
| 🌐 **Interface web Flask** | Dashboard, liste des anomalies, lancement d'analyse et scan SQLMap intégré |
| 🛡️ **Tests de vulnérabilité SQL** | Intégration SQLMap pour détecter les injections SQL (In-band, Blind, Out-of-band) |
| 📊 **Export CSV** | Génération de rapports horodatés dans le dossier `exports/` |
| ⚡ **Triggers MySQL** | Journalisation automatique au niveau base de données (INSERT, UPDATE, DELETE, SELECT) |

---

## 🏗️ Architecture du projet

```
┌─────────────────────────────────────────────────┐
│               Interface Web (Flask)              │
│  Dashboard │ Anomalies │ SQLMap Scan │ Analyse   │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│              Backend Python                      │
│   app.py (Flask routes)  │  analyse.py (SIEM)   │
│   - Détection anomalies  │  - Rapport CSV        │
│   - Alerte email         │  - Connexion MySQL    │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│              Base de données MySQL               │
│  Tables médicales  │  Tables de journalisation  │
│  patients, médecins│  access_logs, log_requetes  │
│  consultations...  │  anomalies_detectees        │
│                    │  Triggers, Vues, Index      │
└─────────────────────────────────────────────────┘
```

---

## 🛠️ Stack technique

- **Backend :** Python 3.10+, Flask 2.x
- **Base de données :** MySQL 8.0
- **Analyse & détection :** pandas, mysql-connector-python
- **Journalisation :** module `logging` (fichier `analyseur.log`)
- **Email :** `smtplib` + `email.mime` (SMTP Gmail, TLS)
- **Test de vulnérabilité :** SQLMap 1.9.x
- **Frontend :** HTML5, Bootstrap 5.3, Jinja2
- **Configuration :** `configparser` + fichier `.ini`

---

## ⚙️ Installation

### Prérequis

- Python 3.10+
- MySQL 8.0
- SQLMap (optionnel, pour le module scan)
- pip

### Étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/<votre-username>/hospital-db-anomaly-detection-siem.git
cd hospital-db-anomaly-detection-siem

# 2. Installer les dépendances Python
pip install -r requirements.txt

# 3. Créer la base de données
mysql -u root -p < hopital_db.sql

# 4. Configurer les credentials (voir section Configuration)
cp .env.example .env
# Remplir .env avec vos vraies valeurs

# 5. Lancer l'application Flask
python app.py
```

L'interface est accessible sur `http://127.0.0.1:5000`

---

## 🔧 Configuration

Copier `.env.example` en `.env` et remplir les valeurs :

```env
# Base de données MySQL
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=votre_mot_de_passe
MYSQL_DATABASE=hopital_db

# Email (App Password Gmail recommandé)
EMAIL_FROM=votre.email@gmail.com
EMAIL_TO=rsi@hopital.ma
EMAIL_SMTP=smtp.gmail.com
EMAIL_PORT=587
EMAIL_PASSWORD=votre_app_password_gmail
```

Pour générer un App Password Gmail : [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)

---

## 🚀 Utilisation

### Via l'interface web

| URL | Description |
|---|---|
| `http://127.0.0.1:5000/` | Dashboard — vue d'ensemble (nb patients, nb anomalies) |
| `http://127.0.0.1:5000/anomalies` | Liste des anomalies détectées |
| `http://127.0.0.1:5000/scan` | Lancer un scan SQLMap sur une URL |
| `http://127.0.0.1:5000/analyse` (POST) | Déclencher une nouvelle analyse de logs |

### Via la ligne de commande

```bash
# Lancer l'analyse et générer le rapport CSV + email
python analyse.py
```

Le rapport CSV est généré dans `exports/rapport_incidents_YYYYMMDD_HHMMSS.csv`

---

## 📁 Structure des fichiers

```
hospital-db-anomaly-detection-siem/
│
├── app.py                  # Application Flask (routes, dashboard, scan SQLMap)
├── analyse.py              # Moteur SIEM : détection, journalisation, email
│
├── templates/
│   ├── base.html           # Template de base (navbar Bootstrap)
│   ├── dashboard.html      # Vue d'ensemble
│   ├── anomalies.html      # Liste des anomalies
│   └── scan.html           # Interface SQLMap
│
├── rapport du projet du CHU HASSAN II FES 
├── analyseur.log           # Journal d'événements système (ignoré par git)
│
├── .env.example            # Modèle de configuration (à copier en .env)
├── .gitignore
├── requirements.txt
└── README.md
```

> Le fichier SQL de création de la base (`hopital_db.sql`) doit être fourni séparément ou généré depuis votre environnement local.

---

## 🔎 Détection des anomalies

Le moteur d'analyse (`analyse.py`) implémente 4 règles de détection :

### 1. Accès hors horaires (22h – 6h)
Toute requête ou accès enregistré entre 22h et 6h est classé comme anomalie de gravité **moyenne**. Couvre les tables `log_requetes` et `access_logs`.

### 2. Requêtes répétées sur consultations
Si un utilisateur effectue **≥ 10 requêtes** concernant des consultations en **≤ 10 minutes**, une anomalie de gravité **élevée** est générée. Signal d'extraction de masse ou de script automatisé.

### 3. Tentatives d'accès refusées multiples
**5 accès refusés** (`statut_acces = 'refuse'`) en **≤ 5 minutes** pour un même utilisateur → anomalie de gravité **élevée**. Indicateur d'attaque par force brute.

### 4. Requêtes échouées multiples
**5 requêtes échouées** (`succes = False`) en **≤ 5 minutes** → anomalie de gravité **moyenne**. Peut indiquer des tentatives d'injection SQL ou d'exploration illégitime.

### Niveaux de gravité

| Gravité | Couleur | Exemples |
|---|---|---|
| `faible` | 🟢 | Accès inhabituel isolé |
| `moyenne` | 🟡 | Accès hors horaires, requêtes échouées |
| `élevée` | 🔴 | Force brute, extraction de masse |
| `critique` | ⛔ | Suppression non autorisée, violation de rôle |

---

## 🌐 Interface web Flask

### Dashboard
Affiche en temps réel le nombre de patients et d'anomalies détectées. Donne accès aux boutons **Lancer une analyse** (appelle `analyse.py`) et **Scan SQLMap**.

### Page Anomalies
Tableau complet des anomalies enregistrées dans `anomalies_detectees`, triées par horodatage décroissant.

### Page Scan SQLMap
Permet de tester une URL pour des vulnérabilités SQL injection. Si une faille est détectée (In-band, Blind, Out-of-band), le système envoie automatiquement une **alerte email** au RSI avec le type de vulnérabilité, l'URL testée et des recommandations.

> ⚠️ Le scan SQLMap doit être utilisé **uniquement sur des environnements de test autorisés**. N'utilisez jamais cet outil sur des systèmes tiers sans permission explicite.

---

## ⚡ Triggers MySQL

Quatre triggers automatisent la journalisation au niveau base de données :

| Trigger | Moment | Action |
|---|---|---|
| `trg_log_insert_patients` | AFTER INSERT | Log ajout patient |
| `trg_log_update_patients` | AFTER UPDATE | Log modification patient |
| `trg_log_delete_patients` | AFTER DELETE | Log suppression patient |
| `trg_log_select_patients` | AFTER SELECT | Log lecture patient |

---

## 🚧 Limitations et pistes d'amélioration

- **Règles statiques** : le système repose sur des seuils fixes. Une approche Machine Learning permettrait une détection comportementale plus fine.
- **Scope limité aux logs DB** : les logs applicatifs et réseau ne sont pas encore intégrés.
- **Pas de gestion post-détection** : aucun workflow de traitement ou d'escalade des incidents n'est implémenté.
- **Interface basique** : l'ajout de graphiques, filtres et gestion des rôles utilisateurs enrichirait le tableau de bord.
- **Déploiement production** : Flask dev server utilisé ; un serveur WSGI (Gunicorn/uWSGI) est requis pour la production.

---

## 👩‍💻 Auteur

**Abir Majdi**  
Élève Ingénieure — Génie de Développement Numérique et Cybersécurité (GDNC)  
École Nationale des Sciences Appliquées de Fès (ENSA Fès)

Stage réalisé au **CHU Hassan II de Fès** — Service Informatique  
Période : 01/07/2025 – 01/08/2025  
Encadrant CHU : **M. Soufiane ELAKRAA**  
Encadrant pédagogique : **M. Imadeddine Mountasser**

---

> *Ce projet a été développé dans un cadre académique et de stage. Les données utilisées sont fictives. Le code est fourni à titre éducatif.*
