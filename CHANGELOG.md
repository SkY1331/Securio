# Changelog

## [2.1.0] - 2026-11-23

### Sécurité
- **Noms de fichiers piégés** : les caractères invisibles et d'inversion du sens de lecture
  (U+202E…) sont retirés des noms d'origine, avec un avertissement ; alerte quand le fichier
  déchiffré est un programme, un script ou un document à macros ; noms réservés de Windows
  (`CON`, `NUL`…) neutralisés
- **En-têtes hostiles** : bornes Argon2 resserrées (≤ 1 Gio, ≤ 10 passes) — un fichier forgé ne
  peut plus bloquer l'application
- **Argon2id à 256 Mio** par défaut (au lieu de 64 Mio) : une attaque par force brute coûte 4 fois
  plus cher ; les fichiers 2.0 restent lisibles (paramètres lus dans l'en-tête)
- **Robustesse de la clé** évaluée pendant la saisie (zxcvbn, dictionnaires français et anglais) ;
  les clés « très faibles » et « faibles » sont refusées au chiffrement
- **Secrets en mémoire** : mots de passe effacés côté Rust, clé retirée de l'interface après
  ouverture d'un fichier, session (contenu v1/v2 ou clé v3) effacée après 5 minutes d'inactivité
- **Fichiers temporaires** : journalisés et supprimés au démarrage suivant si l'application a été
  interrompue pendant un déchiffrement
- **CI** : permissions minimales par job (écriture réservée à la publication sur tag), actions
  épinglées par empreinte, `npm ci --ignore-scripts`, audit RustSec et npm, Dependabot, empreintes
  `SHA256SUMS.txt` et attestation de provenance des exécutables

## [2.0.0] - 2026-11-23

### Architecture
- Migration d'Electron vers **Tauri 2** : exécutable d'environ 10 Mo (au lieu de ~110 Mo),
  WebView2 du système, plus de Node.js ni de Chromium embarqués
- Toute la cryptographie passe en **Rust** (crate `securio-core`, bibliothèques RustCrypto) ;
  l'interface React ne manipule plus que des chemins de fichiers
- Installeurs NSIS et MSI avec association de l'extension `.encrypted`, exécutable portable ;
  compilation et tests automatiques sur GitHub Actions

### Nouveau format v3
- Dérivation de clé **Argon2id** (64 Mio, t = 3, p = 4), paramètres enregistrés dans le fichier
- **AES-256-GCM par segments de 1 Mio** (construction STREAM) : fichiers de toute taille traités
  en flux ; altération, troncature et réorganisation détectées
- Métadonnées chiffrées et complétées à 256 octets (la longueur du nom ne fuit plus)
- Paramètres d'en-tête bornés contre les fichiers forgés

### Rétro-compatibilité
- Lecture des formats v1 (≤ 1.2.1) et v2 (1.3) réimplémentée en Rust et vérifiée sur les mêmes
  fichiers témoins que la 1.3 (y compris les réparations d'images, de textes et de noms)
- Détection automatique de l'algorithme v1 trois fois plus rapide (une seule dérivation PBKDF2)
- Ajout de fichiers témoins v3

### Divers
- Écriture atomique : aucun fichier partiel en cas d'erreur (clé incorrecte, altération, disque plein)
- Clés et contenus déchiffrés effacés de la mémoire (`zeroize`)
- Barre de progression ; instance unique (un double-clic ouvre le fichier dans la fenêtre existante)

## [1.3.0] - 2026-11-23

### Sécurité
- Nouveau format de fichier **v2** : chiffrement authentifié AES-256-GCM (l'ancien AES-CBC ne
  détectait ni les altérations ni, de façon fiable, une mauvaise clé)
- Dérivation de clé PBKDF2-HMAC-SHA256 portée à 600 000 itérations (recommandation OWASP),
  paramètres enregistrés dans le fichier pour pouvoir évoluer
- Nom et type du fichier d'origine désormais chiffrés (ils étaient en clair dans l'en-tête)
- Mot de passe encodé en UTF-8 (NFC) : les caractères non latins ne sont plus tronqués
- Electron : `contextIsolation`, `sandbox`, `nodeIntegration` désactivé, preload minimal,
  CSP stricte, navigation et nouvelles fenêtres bloquées
- Electron 28 (plus maintenu) → 45 ; dépendances mises à jour (React 19, Vite 8)

### Rétro-compatibilité
- Les fichiers v1 (Securio 1.0 → 1.2.1) restent lisibles ; l'algorithme AES-128/192/256-CBC
  est détecté automatiquement
- Réparation des fichiers v1 abîmés par l'ancienne interface : images stockées en data-URL,
  textes stockés en Latin-1 tronqué, noms tronqués à 32 octets (le contenu brut reste disponible)
- Fichiers témoins générés avec le code d'origine + tests automatisés (`npm test`)

### Corrigé
- Les images et fichiers texte étaient altérés avant chiffrement (lecture en data-URL / texte) :
  tous les fichiers sont désormais lus en binaire
- L'ouverture d'un `.encrypted` par double-clic ne fonctionnait pas (IPC incohérent, script
  principal sans gestion des arguments) ; ajout de l'instance unique et de l'association de fichier
  (installeur NSIS)
- Le clic sur la zone de dépôt n'ouvrait pas le sélecteur de fichiers
- Numéro de version incohérent (package.json 1.1.0 / interface 1.2.1)
- Script de build dépendant de la commande Windows `copy` ; configuration ESLint manquante

### Modifié
- Mode chiffrer/déchiffrer choisi automatiquement selon le fichier
- Confirmation de la clé au chiffrement, bouton afficher/masquer, alerte clé courte
- Boîte « Enregistrer sous » native dans l'application
- Application empaquetée en archive asar, sans node_modules (React est inclus dans le bundle Vite)

## [1.2.1] - 2024-04-27

### Added
- Chargement automatique des fichiers .encrypted au démarrage de l'application
- Support du double-clic sur les fichiers .encrypted
- Intégration avec le système de fichiers pour l'ouverture directe des fichiers

## [1.2.0] - 2024-04-27

### Changed
- Simplification du format de fichier
- Suppression du support des types de fichiers spécifiques (images, documents, etc.)
- Tous les fichiers sont maintenant traités comme des fichiers binaires
- Interface utilisateur simplifiée

### Fixed
- Amélioration de la stabilité du traitement des fichiers
- Optimisation des performances

## [1.1.0] - 2024-04-19

### Added
- Support de multiples types de fichiers (PDF, JPG, PNG, Word, Excel, etc.)
- Nouveau format de fichier avec en-tête personnalisé
- Préservation des métadonnées des fichiers (type MIME, nom)
- Extension `.encrypted` pour les fichiers chiffrés
- Vérification de la version du format

### Changed
- Amélioration de la gestion des erreurs
- Messages d'erreur plus clairs et spécifiques
- Interface utilisateur adaptée aux différents types de fichiers

### Fixed
- Correction du déchiffrement des fichiers binaires
- Gestion correcte des ArrayBuffer
- Support des fichiers de grande taille

## [1.0.0] - 2024-04-19

### Added
- Chiffrement et déchiffrement de fichiers texte
- Support des algorithmes AES-128, AES-192, AES-256
- Interface utilisateur simple et intuitive
- Sauvegarde des fichiers chiffrés

### Sécurité
- Traitement local des données
- Pas de stockage des clés de chiffrement
- Algorithmes de chiffrement standards et sécurisés 