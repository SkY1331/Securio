# Changelog

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