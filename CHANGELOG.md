# Changelog

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