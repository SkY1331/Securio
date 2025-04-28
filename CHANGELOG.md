# Changelog

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